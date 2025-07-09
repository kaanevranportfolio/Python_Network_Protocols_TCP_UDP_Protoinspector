# protoinspector/injector.py
import socket
import struct
import time
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from enum import IntEnum
from bitstring import BitStream

class UE4MessageType(IntEnum):
    Hello = 0
    Welcome = 1
    Upgrade = 2
    Challenge = 3
    Cookie = 4
    Accepted = 5
    Login = 6
    Join = 7

@dataclass
class InjectionResult:
    success: bool
    bytes_sent: int
    response: Optional[bytes] = None
    error: Optional[str] = None

class UnrealPacketBuilder:
    """Builds Unreal Engine network packets"""
    
    def __init__(self):
        self.protocol_version = 11405  # UE 4.27
        
    def build_handshake_packet(self, msg_type: UE4MessageType, **kwargs) -> bytes:
        packet = BitStream()
        
        if msg_type == UE4MessageType.Hello:
            user_id = kwargs.get("user_id", "TestUser123")
            user_id_bytes = user_id.encode('ascii')

            # Magic number
            packet.append(b'\x80\x00\x00\x00')
            # Packet type (0 for Hello)
            packet.append('uint:8=0')
            # Channel sequence
            packet.append('uintle:32=1')
            # Ack sequence
            packet.append('uintle:32=0')
            # Has server time
            packet.append('bool=True')
            # Timestamp
            timestamp = kwargs.get("timestamp", int(time.time() * 1000) % 2**32)
            packet.append(f'uintle:32={timestamp}')
            # Protocol version
            version = kwargs.get("version", self.protocol_version)
            packet.append(f'uintle:32={version}')
            # GUID
            packet.append(b'\x12\x34\x56\x78\x9A\xBC\xDE\xF0\x12\x34\x56\x78\x9A\xBC\xDE\xF0')
            # Machine ID hash
            packet.append(b'\xDE\xAD\xBE\xEF')
            # User ID string
            packet.append(f'uintle:32={len(user_id_bytes)}')
            packet.append(user_id_bytes)
            # Session ID
            packet.append(b'\x12\x34\x56\x78')

        # You can add more message types here as needed
        
        self._pad_to_byte(packet)
        return packet.bytes



    def build_game_packet(self, packet_id: int, bunches: list) -> bytes:
        """Build a regular game packet"""
        packet = BitStream()
        
        # Not a handshake
        packet.append('bool=False')
        
        # Packet ID (14 bits)
        packet.append('uint:14=%d' % (packet_id % 16384))
        
        # Has packet notify
        packet.append('bool=True')
        
        # Acked packet
        if packet_id > 0:
            packet.append('uint:14=%d' % ((packet_id - 1) % 16384))
        else:
            packet.append('uint:14=0')
        
        # History word count
        self._write_packed_int(packet, 1)
        packet.append('uint:32=%d' % 0xFFFFFFFF)
        
        # Add bunches
        for i, bunch_data in enumerate(bunches):
            # Has more data
            packet.append('bool=True')
            
            # Build bunch
            self._build_bunch(packet, bunch_data)
        
        # No more data
        packet.append('bool=False')
        
        # Pad to byte boundary
        self._pad_to_byte(packet)
        return packet.bytes
    
    def _build_bunch(self, packet: BitStream, bunch_data: dict):
        """Build a bunch within a packet"""
        # Bunch flags
        flags = bunch_data.get('flags', {})
        packet.append('bool=%s' % flags.get('control', False))
        packet.append('bool=%s' % flags.get('open', False))
        packet.append('bool=%s' % flags.get('close', False))
        packet.append('bool=%s' % flags.get('dormant', False))
        packet.append('bool=%s' % flags.get('repl_pause', False))
        packet.append('bool=%s' % flags.get('reliable', True))
        
        # Extended reliable info
        if flags.get('reliable', True):
            packet.append('bool=False')  # No exports
            packet.append('bool=False')  # Not must be mapped
            packet.append('bool=False')  # Not partial
        
        # Channel index
        self._write_packed_int(packet, bunch_data.get('channel', 2))
        
        # Bunch data
        data = bunch_data.get('data', b'')
        self._write_packed_int(packet, len(data) * 8)  # Size in bits
        
        # Reliable sequence
        if flags.get('reliable', True):
            packet.append('uint:14=%d' % bunch_data.get('sequence', 0))
        
        # Append data
        if data:
            packet.append(data)
    
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
        # String data
        stream.append(s.encode('ascii') + b'\x00')
    
    def _pad_to_byte(self, stream: BitStream):
        """Pad BitStream to byte boundary"""
        padding_needed = (8 - (stream.len % 8)) % 8
        if padding_needed > 0:
            stream.append('uint:%d=0' % padding_needed)

class UnrealInjector:
    """Injects Unreal Engine packets into network"""
    
    def __init__(self):
        self.builder = UnrealPacketBuilder()
        self.socket = None
        self.packet_id = 0
        
    def _send_packet(self, target_ip: str, target_port: int, data: bytes) -> InjectionResult:
        """Send a packet to target"""
        try:
            if not self.socket:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.socket.settimeout(2.0)  # 2 second timeout for responses
            
            # Send packet
            self.socket.sendto(data, (target_ip, target_port))
            
            # Try to receive response
            try:
                response, addr = self.socket.recvfrom(4096)
                return InjectionResult(
                    success=True,
                    bytes_sent=len(data),
                    response=response
                )
            except socket.timeout:
                # No response is OK for UDP
                return InjectionResult(
                    success=True,
                    bytes_sent=len(data)
                )
                
        except Exception as e:
            return InjectionResult(
                success=False,
                bytes_sent=0,
                error=str(e)
            )
    
    def inject_hello(self, target_ip: str, target_port: int = 7777) -> InjectionResult:
        """Inject UE4 Hello packet to initiate connection"""
        packet_data = self.builder.build_handshake_packet(UE4MessageType.Hello)
        return self._send_packet(target_ip, target_port, packet_data)
    
    def inject_login(self, target_ip: str, target_port: int = 7777, 
                     player_name: str = "Injected", cookie: int = 0) -> InjectionResult:
        """Inject Login packet"""
        packet_data = self.builder.build_handshake_packet(
            UE4MessageType.Login,
            player_name=player_name,
            cookie=cookie
        )
        return self._send_packet(target_ip, target_port, packet_data)
    
    def inject_movement(self, target_ip: str, target_port: int = 7777,
                       x: float = 0.0, y: float = 0.0, z: float = 0.0) -> InjectionResult:
        """Inject a movement update packet"""
        # Build actor data with position update
        actor_data = BitStream()
        
        # Not an RPC
        actor_data.append('bool=False')
        
        # Has property
        actor_data.append('bool=True')
        
        # Property index 1 (Location)
        self.builder._write_packed_int(actor_data, 1)
        
        # Property size (96 bits for 3 floats)
        self.builder._write_packed_int(actor_data, 96)
        
        # Position data
        x_bits = struct.unpack('>I', struct.pack('>f', x))[0]
        y_bits = struct.unpack('>I', struct.pack('>f', y))[0]
        z_bits = struct.unpack('>I', struct.pack('>f', z))[0]
        
        actor_data.append('uint:32=%d' % x_bits)
        actor_data.append('uint:32=%d' % y_bits)
        actor_data.append('uint:32=%d' % z_bits)
        
        # No more properties
        actor_data.append('bool=False')
        
        # Pad actor data
        self.builder._pad_to_byte(actor_data)
        
        # Build bunch
        bunch = {
            'channel': 2,  # Actor channel
            'flags': {'reliable': True},
            'sequence': self.packet_id,
            'data': actor_data.bytes
        }
        
        # Build packet
        packet_data = self.builder.build_game_packet(self.packet_id, [bunch])
        self.packet_id += 1
        
        return self._send_packet(target_ip, target_port, packet_data)
    
    def inject_rpc(self, target_ip: str, target_port: int, channel: int, data: bytes) -> InjectionResult:
        """Inject an RPC call as a reliable bunch on the given channel with the provided data."""
        bunch = {
            'channel': channel,
            'flags': {'reliable': True},
            'sequence': self.packet_id,
            'data': data
        }
        packet_data = self.builder.build_game_packet(self.packet_id, [bunch])
        self.packet_id += 1
        return self._send_packet(target_ip, target_port, packet_data)
    
    def inject_custom(self, target_ip: str, target_port: int, data: bytes) -> InjectionResult:
        """Inject custom packet data"""
        return self._send_packet(target_ip, target_port, data)
    
    def close(self):
        """Close the injector socket"""
        if self.socket:
            self.socket.close()
            self.socket = None

# --- Functions for test_injector.py compatibility ---
from protoinspector.protocol import Packet
try:
    from scapy.all import IP, UDP, send
except ImportError:
    IP = UDP = send = None  # For test patching

def create_packet_from_payload(payload_hex, protocol_id=0x1234, sequence=0):
    """Create a Packet object from hex payload, protocol_id, and sequence."""
    payload = bytes.fromhex(payload_hex)
    return Packet(protocol_id=protocol_id, sequence=sequence, payload=payload)

def send_packet(target_ip, packet, target_port=9999):
    """Serialize the packet and send it using scapy's IP/UDP/send."""
    data = packet.serialize()
    ip_layer = IP(dst=target_ip)
    udp_layer = UDP(dport=target_port, sport=12345)
    send(ip_layer / udp_layer / data)

def inject_packet(target_ip, payload_hex, protocol_id, sequence, target_port):
    """Create a packet from payload and send it to the target."""
    pkt = create_packet_from_payload(payload_hex, protocol_id, sequence)
    send_packet(target_ip, pkt, target_port)