# protoinspector/protocol.py
import struct
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import IntEnum

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
class UnrealPacket:
    """Represents a parsed Unreal Engine packet"""
    is_handshake: bool
    packet_id: Optional[int]
    message_type: Optional[str]
    bunches: List[Dict]
    raw_data: bytes
    
    def __repr__(self):
        if self.is_handshake:
            return f"<UEPacket Handshake type={self.message_type}>"
        else:
            return f"<UEPacket ID={self.packet_id} bunches={len(self.bunches)}>"

class BitReader:
    """Bit-level reader for UE4 packets"""
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        
    def read_bit(self) -> bool:
        byte_pos = self.pos // 8
        bit_pos = self.pos % 8
        if byte_pos >= len(self.data):
            return False
        bit = (self.data[byte_pos] >> bit_pos) & 1
        self.pos += 1
        return bool(bit)
    
    def read_bits(self, num_bits: int) -> int:
        result = 0
        for i in range(num_bits):
            if self.read_bit():
                result |= (1 << i)
        return result
    
    def read_packed_int(self) -> int:
        """Read UE4 packed integer (variable length)"""
        value = 0
        for byte_index in range(5):  # Max 5 bytes
            byte = self.read_bits(8)
            value |= (byte & 0x7F) << (7 * byte_index)
            if (byte & 0x80) == 0:
                break
        return value
    
    def read_string(self) -> str:
        """Read FString"""
        length = struct.unpack('<i', self.read_bytes(4))[0]
        if length == 0:
            return ""
        elif length > 0:
            # ASCII string
            return self.read_bytes(length).decode('ascii', errors='ignore').rstrip('\x00')
        else:
            # Unicode string (negative length)
            length = -length
            return self.read_bytes(length * 2).decode('utf-16-le', errors='ignore').rstrip('\x00')
    
    def read_bytes(self, num_bytes: int) -> bytes:
        """Read raw bytes"""
        # Align to byte boundary
        if self.pos % 8 != 0:
            self.pos = ((self.pos + 7) // 8) * 8
        
        byte_pos = self.pos // 8
        result = self.data[byte_pos:byte_pos + num_bytes]
        self.pos += num_bytes * 8
        return result
    
    @property
    def bits_remaining(self) -> int:
        return len(self.data) * 8 - self.pos

def parse_unreal_packet(data: bytes) -> UnrealPacket:
    """Parse an Unreal Engine network packet"""
    reader = BitReader(data)
    
    # Check if handshake packet
    is_handshake = reader.read_bit()
    
    if is_handshake:
        # Parse handshake
        version = reader.read_bits(8)
        msg_type = reader.read_bits(8)
        
        message_type = UE4MessageType(msg_type).name if msg_type < len(UE4MessageType) else f"Unknown({msg_type})"
        
        handshake_data = {
            'version': version,
            'type': message_type,
            'type_id': msg_type
        }
        
        # Parse based on message type
        if msg_type == UE4MessageType.Hello:
            handshake_data['protocol_version'] = reader.read_bits(32)
            handshake_data['is_little_endian'] = reader.read_bit()
            
        elif msg_type == UE4MessageType.Challenge:
            handshake_data['timestamp'] = reader.read_bits(64)
            handshake_data['cookie'] = reader.read_bits(32)
            # Challenge is 256 bits (32 bytes)
            handshake_data['challenge'] = reader.read_bytes(32).hex()
            
        elif msg_type == UE4MessageType.Welcome:
            handshake_data['cookie'] = reader.read_bits(32)
            handshake_data['timestamp'] = reader.read_bits(64)
            if reader.bits_remaining >= 32:
                handshake_data['session_id'] = reader.read_string()
        
        return UnrealPacket(
            is_handshake=True,
            packet_id=None,
            message_type=message_type,
            bunches=[handshake_data],
            raw_data=data
        )
    
    else:
        # Regular packet
        packet_id = reader.read_bits(14)
        
        bunches = []
        
        # Check for packet notify
        has_packet_notify = reader.read_bit()
        if has_packet_notify:
            notify = {
                'type': 'PacketNotify',
                'acked_packet': reader.read_bits(14),
                'history_words': []
            }
            
            # Read history
            word_count = reader.read_packed_int()
            for _ in range(word_count):
                notify['history_words'].append(reader.read_bits(32))
            
            bunches.append(notify)
        
        # Read bunches
        while reader.bits_remaining > 8:
            has_more = reader.read_bit()
            if not has_more:
                break
            
            bunch = parse_bunch(reader)
            if bunch:
                bunches.append(bunch)
        
        return UnrealPacket(
            is_handshake=False,
            packet_id=packet_id,
            message_type=None,
            bunches=bunches,
            raw_data=data
        )

def parse_bunch(reader: BitReader) -> Optional[Dict]:
    """Parse a single bunch from the packet"""
    bunch = {'type': 'Bunch'}
    
    # Read bunch header
    control = reader.read_bit()
    open = reader.read_bit()
    close = reader.read_bit()
    dormant = reader.read_bit()
    is_repl_pause = reader.read_bit()
    reliable = reader.read_bit()
    
    bunch['flags'] = {
        'control': control,
        'open': open,
        'close': close,
        'dormant': dormant,
        'reliable': reliable
    }
    
    # Extended reliable info
    if reliable:
        has_exports = reader.read_bit()
        has_guids = reader.read_bit()
        partial = reader.read_bit()
        
        bunch['flags']['partial'] = partial
        
        if partial:
            bunch['flags']['partial_initial'] = reader.read_bit()
            bunch['flags']['partial_final'] = reader.read_bit()
    
    # Channel index
    channel = reader.read_packed_int()
    bunch['channel'] = channel
    
    # Bunch data size
    data_bits = reader.read_packed_int()
    bunch['data_bits'] = data_bits
    
    if reliable:
        bunch['chunk_id'] = reader.read_bits(14)
    
    # Parse bunch data based on channel type
    if control:
        bunch['channel_type'] = 'Control'
        # Control messages would be parsed here
    else:
        bunch['channel_type'] = 'Actor' if channel >= 1 else 'Unknown'
        
        if data_bits > 0 and reader.bits_remaining >= data_bits:
            # Check if RPC or property replication
            is_rpc = reader.read_bit()
            
            if is_rpc:
                bunch['data_type'] = 'RPC'
                bunch['function_index'] = reader.read_packed_int()
            else:
                bunch['data_type'] = 'PropertyReplication'
                properties = []
                
                while reader.bits_remaining > 8:
                    has_property = reader.read_bit()
                    if not has_property:
                        break
                    
                    prop = {
                        'index': reader.read_packed_int(),
                        'size_bits': reader.read_packed_int()
                    }
                    
                    # For demo, just show location property
                    if prop['index'] == 1 and prop['size_bits'] == 96:
                        # Read 3 floats for location
                        x_bits = reader.read_bits(32)
                        y_bits = reader.read_bits(32)
                        z_bits = reader.read_bits(32)
                        
                        # Convert to float (assuming big endian)
                        import struct
                        x = struct.unpack('>f', struct.pack('>I', x_bits))[0]
                        y = struct.unpack('>f', struct.pack('>I', y_bits))[0]
                        z = struct.unpack('>f', struct.pack('>I', z_bits))[0]
                        
                        prop['data'] = f"Location({x:.2f}, {y:.2f}, {z:.2f})"
                    
                    properties.append(prop)
                
                bunch['properties'] = properties
    
    return bunch

# Keep backward compatibility
class Packet:
    """Legacy packet format for backward compatibility"""
    HEADER_FORMAT = ">H I H"
    
    def __init__(self, protocol_id: int, sequence: int, payload: bytes):
        self.protocol_id = protocol_id
        self.sequence = sequence
        self.payload = payload
    
    def serialize(self) -> bytes:
        header = struct.pack(self.HEADER_FORMAT, self.protocol_id, self.sequence, len(self.payload))
        return header + self.payload
    
    @classmethod
    def deserialize(cls, data: bytes):
        header_size = struct.calcsize(cls.HEADER_FORMAT)
        if len(data) < header_size:
            raise ValueError("Packet too short")
        
        protocol_id, sequence, payload_len = struct.unpack(cls.HEADER_FORMAT, data[:header_size])
        payload = data[header_size:header_size + payload_len]
        
        return cls(protocol_id, sequence, payload)

# For backward compatibility
def parse_mock_unreal_packet(data: bytes):
    """Legacy function - now uses real UE parser"""
    try:
        packet = parse_unreal_packet(data)
        if packet.is_handshake:
            return {
                "sequence": 0,
                "length": len(data),
                "payload": f"Handshake: {packet.message_type}"
            }
        else:
            return {
                "sequence": packet.packet_id,
                "length": len(data),
                "payload": f"Bunches: {len(packet.bunches)}"
            }
    except:
        # Fallback to old format
        if len(data) < 8:
            raise ValueError("Packet too short")
        seq, length = struct.unpack("!II", data[:8])
        payload = data[8:8+length]
        return {"sequence": seq, "length": length, "payload": payload}