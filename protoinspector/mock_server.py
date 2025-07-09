# protoinspector/mock_server.py
import socket
import threading
import struct
import time
from enum import IntEnum
from bitstring import BitStream
import random

class UE4MessageType(IntEnum):
    Hello = 0
    Welcome = 1
    Challenge = 3
    Login = 6
    Join = 7
    
class MockUnrealServer:
    """Mock Unreal Engine 4/5 server that sends realistic packets"""
    
    def __init__(self, host="127.0.0.1", port=7777):
        self.host = host
        self.port = port
        self.running = False
        self.server_socket = None
        self.protocol_version = 11405  # UE 4.27 protocol version
        self.connections = {}
        self.demo_mode = True  # Enable demo mode for standalone testing
        
    def start(self):
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        print(f"[MockUnrealServer] Listening on {self.host}:{self.port} (UDP)")
        threading.Thread(target=self._receive_loop, daemon=True).start()
        
        # In demo mode, create a fake connection for testing
        if self.demo_mode:
            demo_addr = ('127.0.0.1', 7778)
            self.connections[demo_addr] = {
                'packet_id': 0,
                'actor_id': 1000,
                'state': 'connected'
            }
            print(f"[MockUnrealServer] Demo mode: Added mock connection for {demo_addr}")
        
    def _receive_loop(self):
        while self.running:
            try:
                data, addr = self.server_socket.recvfrom(4096)
                print(f"[MockUnrealServer] Received {len(data)} bytes from {addr}")
                self._handle_packet(data, addr)
            except Exception as e:
                if self.running:
                    print(f"[MockUnrealServer] Error: {e}")
    
    def _handle_packet(self, data: bytes, addr):
        """Handle incoming packet and respond appropriately"""
        # Import BitReader from protocol module to reuse parsing logic
        from .protocol import BitReader
        
        # Simple detection - in real implementation would parse properly
        if len(data) < 10:
            return
            
        # Check if it's a handshake packet
        reader = BitReader(data)
        is_handshake = reader.read_bit()
        
        if is_handshake:
            # Parse handshake type
            version = reader.read_bits(8)
            msg_type = reader.read_bits(8)
            
            if msg_type == UE4MessageType.Hello:
                print(f"[MockUnrealServer] Received Hello from {addr}")
                self._send_challenge(addr)
            elif msg_type == UE4MessageType.Login:
                print(f"[MockUnrealServer] Received Login from {addr}")
                self._send_welcome(addr)
                # Add to connections after welcome
                self.connections[addr] = {
                    'packet_id': 0,
                    'actor_id': 1000 + len(self.connections),
                    'state': 'connected'
                }
        else:
            # Regular packet - send game data
            packet_id = reader.read_bits(14)
            print(f"[MockUnrealServer] Received packet ID {packet_id} from {addr}")
            
            if addr not in self.connections:
                self.connections[addr] = {
                    'packet_id': 0,
                    'actor_id': 1000 + len(self.connections),
                    'state': 'connected'
                }
            
            # Send actor updates
            self._send_actor_update(addr)
    
    def _pad_to_byte(self, stream: BitStream):
        """Pad BitStream to byte boundary"""
        padding_needed = (8 - (stream.len % 8)) % 8
        if padding_needed > 0:
            stream.append('uint:%d=0' % padding_needed)
    
    def _get_packet_bytes(self, stream: BitStream) -> bytes:
        """Get bytes from BitStream, padding if necessary"""
        self._pad_to_byte(stream)
        return stream.bytes
    
    def _build_handshake_packet(self, msg_type: int, payload: BitStream) -> bytes:
        """Build a UE4 handshake packet"""
        packet = BitStream()
        
        # Handshake flag
        packet.append('bool=True')
        
        # Version
        packet.append('uint:8=%d' % 1)
        
        # Message type
        packet.append('uint:8=%d' % msg_type)
        
        # Append payload
        packet.append(payload)
        
        return self._get_packet_bytes(packet)
    
    def _send_challenge(self, addr):
        """Send Challenge packet"""
        payload = BitStream()
        
        # Timestamp (use current time in milliseconds)
        timestamp_ms = int(time.time() * 1000)
        payload.append('uint:64=%d' % timestamp_ms)
        
        # Cookie
        cookie = random.randint(0, 2**32-1)
        payload.append('uint:32=%d' % cookie)
        
        # Challenge data (256 bits / 32 bytes)
        for _ in range(8):
            payload.append('uint:32=%d' % random.randint(0, 2**32-1))
        
        packet = self._build_handshake_packet(UE4MessageType.Challenge, payload)
        self.server_socket.sendto(packet, addr)
        print(f"[MockUnrealServer] Sent Challenge to {addr} ({len(packet)} bytes)")
    
    def _send_welcome(self, addr):
        """Send Welcome packet"""
        payload = BitStream()
        
        # Cookie
        cookie = random.randint(0, 2**32-1)
        payload.append('uint:32=%d' % cookie)
        
        # Timestamp
        timestamp_ms = int(time.time() * 1000)
        payload.append('uint:64=%d' % timestamp_ms)
        
        # Session ID string
        session_id = "MockSession123"
        self._write_string(payload, session_id)
        
        packet = self._build_handshake_packet(UE4MessageType.Welcome, payload)
        self.server_socket.sendto(packet, addr)
        print(f"[MockUnrealServer] Sent Welcome to {addr} ({len(packet)} bytes)")
    
    def _send_actor_update(self, addr):
        """Send realistic actor replication data"""
        conn = self.connections[addr]
        conn['packet_id'] = (conn['packet_id'] + 1) % 16384  # 14-bit wrap
        
        packet = BitStream()
        
        # Not a handshake packet
        packet.append('bool=False')
        
        # Packet ID (14 bits)
        packet.append('uint:14=%d' % conn['packet_id'])
        
        # Has packet notify info
        packet.append('bool=True')
        
        # Acked packet (14 bits) - acknowledge previous packet
        if conn['packet_id'] > 0:
            packet.append('uint:14=%d' % (conn['packet_id'] - 1))
        else:
            packet.append('uint:14=0')
        
        # History word count
        self._write_packed_int(packet, 1)
        packet.append('uint:32=%d' % 0xFFFFFFFF)  # All packets received
        
        # Has more data
        packet.append('bool=True')
        
        # Build actor replication bunch
        self._build_actor_bunch(packet, conn)
        
        # No more bunches
        packet.append('bool=False')
        
        packet_bytes = self._get_packet_bytes(packet)
        self.server_socket.sendto(packet_bytes, addr)
        print(f"[MockUnrealServer] Sent Actor Update to {addr} (packet_id={conn['packet_id']}, {len(packet_bytes)} bytes)")
    
    def _build_actor_bunch(self, packet: BitStream, conn: dict):
        """Build an actor replication bunch"""
        # Bunch header flags
        packet.append('bool=False')  # Not control
        packet.append('bool=False')  # Not open
        packet.append('bool=False')  # Not close
        packet.append('bool=False')  # Not dormant
        packet.append('bool=False')  # Not repl pause
        packet.append('bool=True')   # Reliable
        
        # Extended reliable info
        packet.append('bool=False')  # No package exports
        packet.append('bool=False')  # No must be mapped
        packet.append('bool=False')  # Not partial
        
        # Channel index (actor channel)
        self._write_packed_int(packet, 2)  # Channel 2 for first actor
        
        # Build actor data
        actor_data = BitStream()
        
        # Not an RPC
        actor_data.append('bool=False')
        
        # Property replication header
        actor_data.append('bool=True')  # Has property
        
        # Property index (e.g., Location)
        self._write_packed_int(actor_data, 1)
        
        # Property data size in bits
        self._write_packed_int(actor_data, 96)  # 3 floats * 32 bits
        
        # Location data (X, Y, Z) - use struct.pack to get proper float bits
        x = 1000.0 + random.uniform(-10, 10)
        y = 2000.0 + random.uniform(-10, 10)
        z = 100.0 + random.uniform(-5, 5)
        
        # Convert floats to bits properly
        x_bits = struct.unpack('>I', struct.pack('>f', x))[0]
        y_bits = struct.unpack('>I', struct.pack('>f', y))[0]
        z_bits = struct.unpack('>I', struct.pack('>f', z))[0]
        
        actor_data.append('uint:32=%d' % x_bits)
        actor_data.append('uint:32=%d' % y_bits)
        actor_data.append('uint:32=%d' % z_bits)
        
        # No more properties
        actor_data.append('bool=False')
        
        # Write bunch data size (in bits)
        self._write_packed_int(packet, actor_data.len)
        
        # Reliable sequence
        packet.append('uint:14=%d' % conn['packet_id'])
        
        # Append actor data
        packet.append(actor_data)
    
    def _write_packed_int(self, stream: BitStream, value: int):
        """Write UE4 packed integer"""
        while value >= 0x80:
            stream.append('uint:8=%d' % ((value & 0x7F) | 0x80))
            value >>= 7
        stream.append('uint:8=%d' % value)
    
    def _write_string(self, stream: BitStream, s: str):
        """Write FString"""
        # Length including null terminator
        stream.append('int:32=%d' % (len(s) + 1))
        # String data - append as raw bytes
        string_bytes = s.encode('ascii') + b'\x00'
        # Append each byte
        for byte in string_bytes:
            stream.append('uint:8=%d' % byte)
    
    def send_simple_packet(self, addr):
        """Send a simple test packet"""
        packet = BitStream()
        
        # Handshake flag
        packet.append('bool=True')
        
        # Version
        packet.append('uint:8=1')
        
        # Message type (Hello)
        packet.append('uint:8=0')
        
        # Protocol version
        packet.append('uint:32=%d' % self.protocol_version)
        
        # Is little endian
        packet.append('bool=True')
        
        # Pad to byte boundary before sending
        packet_bytes = self._get_packet_bytes(packet)
        
        self.server_socket.sendto(packet_bytes, addr)
        print(f"[MockUnrealServer] Sent simple Hello packet to {addr} ({len(packet_bytes)} bytes)")
    
    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        print("[MockUnrealServer] Stopped.")

if __name__ == "__main__":
    server = MockUnrealServer()
    try:
        server.start()
        print("Mock Unreal Engine server running. Press Ctrl+C to stop.")
        
        # Send some test packets periodically
        import time
        counter = 0
        packet_types = ['hello', 'challenge', 'welcome', 'actor_update']
        
        while True:
            time.sleep(2)
            counter += 1
            
            # Demo address
            demo_addr = ('127.0.0.1', 7778)
            
            # Cycle through different packet types in demo mode
            if server.demo_mode:
                packet_type = packet_types[counter % len(packet_types)]
                
                try:
                    if packet_type == 'hello':
                        server.send_simple_packet(demo_addr)
                    elif packet_type == 'challenge':
                        server._send_challenge(demo_addr)
                    elif packet_type == 'welcome':
                        server._send_welcome(demo_addr)
                    elif packet_type == 'actor_update':
                        # Make sure connection exists for actor updates
                        if demo_addr in server.connections:
                            server._send_actor_update(demo_addr)
                        else:
                            server.send_simple_packet(demo_addr)
                except Exception as e:
                    print(f"[MockUnrealServer] Error sending {packet_type}: {e}")
            else:
                # Non-demo mode - only send to real connections
                if server.connections:
                    for addr in list(server.connections.keys()):
                        try:
                            server._send_actor_update(addr)
                        except Exception as e:
                            print(f"[MockUnrealServer] Error sending to {addr}: {e}")
                
    except KeyboardInterrupt:
        server.stop()