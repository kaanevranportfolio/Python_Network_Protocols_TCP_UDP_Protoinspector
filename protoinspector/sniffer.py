# protoinspector/sniffer.py

from scapy.all import sniff, Raw
from protoinspector.protocol import Packet
from protoinspector.analyzer import display_packet
import struct

def _packet_callback_factory(output_file=None):
    def _packet_callback(pkt):
        print(pkt.summary())
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
