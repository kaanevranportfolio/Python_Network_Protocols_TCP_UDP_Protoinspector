# protoinspector/protocol.py

import struct
from bitstring import BitArray

class Packet:
    HEADER_FORMAT = ">H I H"  # Protocol ID (2 bytes), Sequence (4), Length (2) — Big endian

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

    def __repr__(self):
        return f"<Packet proto=0x{self.protocol_id:04x} seq={self.sequence} len={len(self.payload)}>"
