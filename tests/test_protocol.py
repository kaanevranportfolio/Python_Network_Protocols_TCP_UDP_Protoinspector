import pytest
from protoinspector.protocol import Packet

def test_packet_serialization_roundtrip():
    pkt = Packet(protocol_id=0x1234, sequence=7, payload=b"hello")
    data = pkt.serialize()
    parsed = Packet.deserialize(data)
    assert parsed.protocol_id == 0x1234
    assert parsed.sequence == 7
    assert parsed.payload == b"hello"

def test_invalid_data_too_short():
    with pytest.raises(ValueError):
        Packet.deserialize(b'\x00\x01')  # Too short

def test_payload_preserved():
    payload = b'\xde\xad\xbe\xef'
    pkt = Packet(0xAAAA, 99, payload)
    assert pkt.payload == payload
