# protoinspector/injector.py

from scapy.all import IP, UDP, send
from protoinspector.protocol import Packet

def create_packet_from_payload(payload_hex: str, protocol_id: int = 0x1234, sequence: int = 0):
    """
    Create a Packet object from a hex string payload.
    """
    payload = bytes.fromhex(payload_hex)
    return Packet(protocol_id=protocol_id, sequence=sequence, payload=payload)

def send_packet(target_ip: str, packet: Packet, target_port: int = 9999):
    """
    Send the serialized packet as a UDP datagram to the target IP and port.
    """
    raw_data = packet.serialize()
    ip_packet = IP(dst=target_ip) / UDP(dport=target_port, sport=12345) / raw_data
    send(ip_packet)
    print(f"[*] Packet sent to {target_ip}:{target_port}")


def inject_packet(target_ip: str, hex_payload: str, protocol_id: int, sequence: int, target_port: int = 9999):
    """
    Combines packet creation and sending in one step.
    """
    packet = create_packet_from_payload(hex_payload, protocol_id, sequence)
    send_packet(target_ip, packet, target_port)


