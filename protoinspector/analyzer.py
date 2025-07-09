# protoinspector/analyzer.py
from protoinspector.protocol import Packet, UnrealPacket, parse_unreal_packet
from rich.console import Console
from rich.table import Table
from rich.tree import Tree
from scapy.layers.inet import IP
import struct
from typing import Dict, List, Any

console = Console()

def parse_packet(data: bytes) -> UnrealPacket:
    """Parse raw bytes as Unreal Engine packet"""
    return parse_unreal_packet(data)

def display_packet(packet):
    """Display parsed packet with proper formatting"""
    if isinstance(packet, UnrealPacket):
        display_unreal_packet(packet)
    else:
        # Legacy display
        display_legacy_packet(packet)

def display_unreal_packet(packet: UnrealPacket):
    """Display Unreal Engine packet in rich format"""
    if packet.is_handshake:
        table = Table(title=f"[bold cyan]Unreal Engine Handshake - {packet.message_type}[/bold cyan]")
        table.add_column("Field", style="bold green")
        table.add_column("Value", style="bold white")
        
        if packet.bunches:
            handshake = packet.bunches[0]
            for key, value in handshake.items():
                if key != 'type':
                    table.add_row(key.replace('_', ' ').title(), str(value))
    else:
        table = Table(title=f"[bold cyan]Unreal Engine Packet ID: {packet.packet_id}[/bold cyan]")
        table.add_column("Bunch #", style="bold yellow")
        table.add_column("Channel", style="bold green") 
        table.add_column("Type", style="bold magenta")
        table.add_column("Details", style="bold white")
        
        for i, bunch in enumerate(packet.bunches):
            if bunch.get('type') == 'PacketNotify':
                table.add_row(
                    str(i),
                    "Notify",
                    "Ack",
                    f"Acked: {bunch['acked_packet']}"
                )
            else:
                flags = bunch.get('flags', {})
                flag_str = ' '.join([k for k, v in flags.items() if v])
                
                details = f"Flags: {flag_str}"
                if bunch.get('data_type') == 'PropertyReplication':
                    props = bunch.get('properties', [])
                    if props:
                        details += f"\nProperties: {len(props)}"
                        for prop in props:
                            if 'data' in prop:
                                details += f"\n  {prop['data']}"
                
                table.add_row(
                    str(i),
                    str(bunch.get('channel', 'N/A')),
                    bunch.get('channel_type', 'Unknown'),
                    details
                )
    
    console.print(table)
    
    # Show raw hex for debugging
    console.print(f"\n[dim]Raw packet size: {len(packet.raw_data)} bytes[/dim]")
    console.print(f"[dim]Hex: {packet.raw_data[:32].hex()}{'...' if len(packet.raw_data) > 32 else ''}[/dim]")

def display_legacy_packet(packet: Packet):
    """Display legacy packet format"""
    table = Table(title="Analyzed Packet")
    table.add_column("Field", style="bold cyan")
    table.add_column("Value", style="bold white")
    
    table.add_row("Protocol ID", f"0x{packet.protocol_id:04X}")
    table.add_row("Sequence", str(packet.sequence))
    table.add_row("Payload (hex)", packet.payload.hex())
    table.add_row("Payload (ascii)", safe_ascii(packet.payload))
    
    console.print(table)

def safe_ascii(data: bytes) -> str:
    """Convert binary data to ASCII, replacing non-printables with dots."""
    return ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)

def analyze_packet_file(file_path: str):
    """Read packets from a binary file, parse, and display them."""
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
                # Show hex dump for debugging
                console.print(f"[dim]Raw data: {packet_data[:64].hex()}{'...' if len(packet_data) > 64 else ''}[/dim]")
                break

def analyze_session(packets: List[UnrealPacket]) -> Dict[str, Any]:
    """Analyze a session of Unreal Engine packets"""
    analysis = {
        'total_packets': len(packets),
        'handshake_packets': 0,
        'data_packets': 0,
        'unique_channels': set(),
        'packet_loss': [],
        'sequence_gaps': [],
        'actor_updates': 0,
        'rpc_calls': 0
    }
    
    last_packet_id = -1
    
    for packet in packets:
        if packet.is_handshake:
            analysis['handshake_packets'] += 1
        else:
            analysis['data_packets'] += 1
            
            # Check for sequence gaps
            if last_packet_id >= 0 and packet.packet_id != (last_packet_id + 1) % 16384:
                gap = {
                    'from': last_packet_id,
                    'to': packet.packet_id,
                    'missing': []
                }
                
                # Calculate missing packets
                current = (last_packet_id + 1) % 16384
                while current != packet.packet_id:
                    gap['missing'].append(current)
                    current = (current + 1) % 16384
                
                analysis['sequence_gaps'].append(gap)
            
            last_packet_id = packet.packet_id
            
            # Analyze bunches
            for bunch in packet.bunches:
                if bunch.get('type') != 'PacketNotify':
                    channel = bunch.get('channel', -1)
                    if channel >= 0:
                        analysis['unique_channels'].add(channel)
                    
                    if bunch.get('data_type') == 'PropertyReplication':
                        analysis['actor_updates'] += 1
                    elif bunch.get('data_type') == 'RPC':
                        analysis['rpc_calls'] += 1
    
    return analysis

def display_session_analysis(analysis: Dict[str, Any]):
    """Display session analysis results"""
    console.print("\n[bold cyan]Session Analysis[/bold cyan]")
    
    # Summary table
    summary = Table(title="Summary")
    summary.add_column("Metric", style="cyan")
    summary.add_column("Value", style="green")
    
    summary.add_row("Total Packets", str(analysis['total_packets']))
    summary.add_row("Handshake Packets", str(analysis['handshake_packets']))
    summary.add_row("Data Packets", str(analysis['data_packets']))
    summary.add_row("Unique Channels", str(len(analysis['unique_channels'])))
    summary.add_row("Actor Updates", str(analysis['actor_updates']))
    summary.add_row("RPC Calls", str(analysis['rpc_calls']))
    
    console.print(summary)
    
    # Sequence analysis
    if analysis['sequence_gaps']:
        gaps_table = Table(title="[red]Sequence Gaps Detected[/red]")
        gaps_table.add_column("From", style="yellow")
        gaps_table.add_column("To", style="yellow")
        gaps_table.add_column("Missing Count", style="red")
        
        for gap in analysis['sequence_gaps']:
            gaps_table.add_row(
                str(gap['from']),
                str(gap['to']),
                str(len(gap['missing']))
            )
        
        console.print("\n")
        console.print(gaps_table)

# Keep existing functions for backward compatibility
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
    """Display IP header fields in a rich table."""
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
    """Display TCP or UDP header fields in a rich table."""
    table = get_transport_header_table(proto, header)
    console.print(table)