# protoinspector/analyzer.py

from protoinspector.protocol import Packet
from rich.console import Console
from rich.table import Table
from scapy.layers.inet import IP

console = Console()

def parse_packet(data: bytes) -> Packet:
    """
    Deserialize raw bytes into a Packet object.
    """
    return Packet.deserialize(data)

def display_packet(packet: Packet):
    """
    Print a human-readable summary of a Packet object.
    """
    table = Table(title="Analyzed Packet")

    table.add_column("Field", style="bold cyan")
    table.add_column("Value", style="bold white")

    table.add_row("Protocol ID", f"0x{packet.protocol_id:04X}")
    table.add_row("Sequence", str(packet.sequence))
    table.add_row("Payload (hex)", packet.payload.hex())
    table.add_row("Payload (ascii)", safe_ascii(packet.payload))

    console.print(table)

def safe_ascii(data: bytes) -> str:
    """
    Convert binary data to ASCII, replacing non-printables with dots.
    """
    return ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)

import struct

def analyze_packet_file(file_path: str):
    """
    Read packets from a binary file, parse, and display them.
    """
    with open(file_path, "rb") as f:
        index = 0
        while True:
            size_bytes = f.read(4)
            if not size_bytes:
                break
            packet_size = struct.unpack("!I", size_bytes)[0]
            packet_data = f.read(packet_size)

            try:
                packet = parse_packet(packet_data)
                console.rule(f"Packet #{index}")
                display_packet(packet)
                index += 1
            except Exception as e:
                console.print(f"[bold red]Error parsing packet #{index}: {e}[/bold red]")
                break

from rich.columns import Columns

def get_ip_header_table(header):
    table = Table(title="IP Header")
    table.add_column("Field", style="bold green")
    table.add_column("Value", style="bold white")
    table.add_row("Source IP", str(header.src))
    table.add_row("Destination IP", str(header.dst))
    table.add_row("Version", str(header.version))
    table.add_row("Header Length", str(header.ihl))
    table.add_row("TTL", str(header.ttl))
    table.add_row("Protocol", str(header.proto))
    table.add_row("Total Length", str(header.len))
    table.add_row("ID", str(header.id))
    table.add_row("Flags", str(header.flags))
    table.add_row("Fragment Offset", str(header.frag))
    table.add_row("Checksum", str(header.chksum))
    return table

def display_ip_header(header):
    """
    Display IP header fields in a rich table.
    """
    table = get_ip_header_table(header)
    console.print(table)

def get_transport_header_table(proto: str, header):
    table = Table(title=f"{proto} Header")
    table.add_column("Field", style="bold magenta")
    table.add_column("Value", style="bold white")
    if proto == "TCP":
        table.add_row("Source Port", str(header.sport))
        table.add_row("Destination Port", str(header.dport))
        table.add_row("Sequence Number", str(header.seq))
        table.add_row("Acknowledgment", str(header.ack))
        table.add_row("Flags", str(header.flags))
        table.add_row("Window", str(header.window))
    elif proto == "UDP":
        table.add_row("Source Port", str(header.sport))
        table.add_row("Destination Port", str(header.dport))
        table.add_row("Length", str(header.len))
        table.add_row("Checksum", str(header.chksum))
    return table

def display_transport_header(proto: str, header):
    """
    Display TCP or UDP header fields in a rich table.
    """
    table = get_transport_header_table(proto, header)
    console.print(table)
