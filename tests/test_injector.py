import pytest
from unittest.mock import patch, MagicMock
from protoinspector.injector import create_packet_from_payload, send_packet, inject_packet

def test_create_packet_from_payload_calls_packet_correctly():
    with patch("protoinspector.injector.Packet") as MockPacket:
        payload_hex = "deadbeef"
        protocol_id = 0x42
        sequence = 7
        result = create_packet_from_payload(payload_hex, protocol_id, sequence)
        MockPacket.assert_called_once_with(protocol_id=protocol_id, sequence=sequence, payload=bytes.fromhex(payload_hex))
        assert result == MockPacket.return_value

@patch("protoinspector.injector.send")
@patch("protoinspector.injector.UDP")
@patch("protoinspector.injector.IP")
def test_send_packet_calls_scapy_and_serializes_packet(MockIP, MockUDP, MockSend):
    mock_packet = MagicMock()
    mock_packet.serialize.return_value = b"abc"
    # Simulate scapy's / operator chaining
    class Dummy:
        def __truediv__(self, other): return self
    MockIP.return_value = Dummy()
    MockUDP.return_value = Dummy()
    target_ip = "1.2.3.4"
    target_port = 5555
    send_packet(target_ip, mock_packet, target_port)
    mock_packet.serialize.assert_called_once()
    MockIP.assert_called_once_with(dst=target_ip)
    MockUDP.assert_called_once_with(dport=target_port, sport=12345)
    MockSend.assert_called_once()

@patch("protoinspector.injector.send_packet", autospec=True)
@patch("protoinspector.injector.create_packet_from_payload", autospec=True)
def test_inject_packet_calls_create_and_send(mock_create, mock_send):
    target_ip = "8.8.8.8"
    hex_payload = "cafebabe"
    protocol_id = 0x99
    sequence = 123
    target_port = 8888
    mock_packet = MagicMock()
    mock_create.return_value = mock_packet
    inject_packet(target_ip, hex_payload, protocol_id, sequence, target_port)
    mock_create.assert_called_once_with(hex_payload, protocol_id, sequence)
    mock_send.assert_called_once_with(target_ip, mock_packet, target_port)