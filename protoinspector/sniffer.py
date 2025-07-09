# protoinspector/sniffer.py
from scapy.all import sniff, Raw, TCP, UDP, IP
from protoinspector.protocol import parse_unreal_packet, UnrealPacket
from protoinspector.analyzer import (
    display_packet,
    get_ip_header_table,
    get_transport_header_table,
    console
)
from rich.columns import Columns
import struct

def _packet_callback_factory(output_file=None, detect_unreal=True):
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
            
            # Try to detect and parse Unreal Engine packets
            if detect_unreal and UDP in pkt:
                # Common UE4 ports: 7777, 7778, 7779
                if pkt[UDP].dport in [7777, 7778, 7779] or pkt[UDP].sport in [7777, 7778, 7779]:
                    try:
                        ue_packet = parse_unreal_packet(raw_data)
                        console.print("\n[bold green]Detected Unreal Engine Packet![/bold green]")
                        display_packet(ue_packet)
                        
                        if output_file:
                            with open(output_file, "ab") as f:
                                f.write(struct.pack("!I", len(raw_data)))
                                f.write(raw_data)
                        return
                    except Exception as e:
                        # Not a UE packet, continue with normal processing
                        pass
            
            # Fallback to generic display
            console.print(f"\n[yellow]Raw Data ({len(raw_data)} bytes):[/yellow]")
            console.print(f"[dim]{raw_data[:64].hex()}{'...' if len(raw_data) > 64 else ''}[/dim]")
            
            if output_file:
                with open(output_file, "ab") as f:
                    f.write(struct.pack("!I", len(raw_data)))
                    f.write(raw_data)
                    
    return _packet_callback

def start_sniffing(interface, count, output_file, port=None):
    """
    Start sniffing on the given network interface.
    :param interface: Name of the network interface (e.g. eth0)
    :param count: Number of packets to capture (0 for infinite)
    :param output_file: Optional file to save captured packets
    :param port: Optional port to filter packets on
    """
    print(f"[*] Starting packet capture on {interface}...")
    
    # Build filter
    filters = []
    if port is not None:
        filters.append(f"port {port}")
    
    # Add UDP filter for game traffic
    filters.append("udp")
    
    filter_str = " or ".join(filters) if filters else None
    
    if filter_str:
        print(f"[*] Filter: {filter_str}")
    
    sniff(
        iface=interface,
        filter=filter_str,
        prn=_packet_callback_factory(output_file),
        store=False,
        count=count
    )