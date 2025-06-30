# protoinspector/sniffer.py

from scapy.all import sniff, Raw, TCP, UDP, IP
from protoinspector.protocol import Packet
from protoinspector.analyzer import (
    display_packet,
    get_ip_header_table,
    get_transport_header_table,
    console
)
from rich.columns import Columns  # <-- Add this line
import struct

def _packet_callback_factory(output_file=None):
    def _packet_callback(pkt):
        print(pkt.summary())
        ip_table = None
        transport_table = None
        if IP in pkt:
            ip_table = get_ip_header_table(pkt[IP])
        if TCP in pkt:
            transport_table = get_transport_header_table("TCP", pkt[TCP])
        elif UDP in pkt:
            transport_table = get_transport_header_table("UDP", pkt[UDP])
        if ip_table and transport_table:
            console.print(Columns([ip_table, transport_table]))
        elif ip_table:
            console.print(ip_table)
        elif transport_table:
            console.print(transport_table)
        if Raw in pkt:
            raw_data = bytes(pkt[Raw])
            try:
                packet = Packet.deserialize(raw_data)
                display_packet(packet)
                if output_file:
                    with open(output_file, "ab") as f:
                        # Write length-prefixed raw data
                        f.write(struct.pack("!I", len(raw_data)))
                        f.write(raw_data)
            except Exception as e:
                print(f"[!] Failed to parse packet: {e}")
    return _packet_callback

def start_sniffing(interface: str, count: int = 0, output_file=None):
    """
    Start sniffing on the given network interface.
    :param interface: Name of the network interface (e.g. eth0)
    :param count: Number of packets to capture (0 for infinite)
    :param output_file: Optional file to save captured packets
    """
    print(f"[*] Starting packet capture on {interface}...")
    sniff(
        iface=interface,
        prn=_packet_callback_factory(output_file),
        store=False,
        count=count
    )
