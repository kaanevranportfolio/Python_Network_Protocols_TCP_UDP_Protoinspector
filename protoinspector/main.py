# main.py

import typer
from protoinspector import sniffer, analyzer, injector
from rich.console import Console

console = Console()

app = typer.Typer(help="ProtoInspector - Network Protocol Analysis Tool")

@app.command()
def sniff(
    interface: str = typer.Option(..., "--interface", "-i", help="Network interface to capture packets on"),
    count: int = typer.Option(0, "--count", "-c", help="Number of packets to capture, 0 for unlimited"),
    output_file: str = typer.Option(None, "--output-file", "-o", help="File to save captured packets"),
    port: int = typer.Option(None, "--port", "-p", help="Port to filter packets on (leave empty for all ports)"),
):
    """
    Capture and analyze packets live from a network interface.
    """
    sniffer.start_sniffing(interface, count, output_file, port)

@app.command()
def analyze(file: str = typer.Option(..., help="File path to raw packet data")):
    """
    Analyze a raw packet file and display its contents.
    """
    try:
        with open(file, "rb") as f:
            data = f.read()
        packet = analyzer.parse_packet(data)
        analyzer.display_packet(packet)
    except Exception as e:
        typer.echo(f"[!] Failed to analyze file: {e}")

@app.command()
def inject(target_ip: str = typer.Option(..., help="Target IP address"),
           payload: str = typer.Option(..., help="Payload as a hex string"),
           protocol_id: int = typer.Option(0x1234, help="Protocol ID"),
           sequence: int = typer.Option(0, help="Sequence number"),
           target_port: int = typer.Option(9999, help="Target UDP port")):
    """
    Craft and send a custom packet to the target IP and port.
    """
    try:
        packet = injector.create_packet_from_payload(payload, protocol_id, sequence)
        injector.send_packet(target_ip, packet, target_port)
    except Exception as e:
        typer.echo(f"[!] Failed to send packet: {e}")

@app.command()
def inject_ue(
    target_ip: str = typer.Option("127.0.0.1", "--target", "-t", help="Target IP address"),
    port: int = typer.Option(7777, "--port", "-p", help="Target port"),
    packet_type: str = typer.Option(..., "--type", help="Packet type: hello, login, movement, rpc"),
    params: str = typer.Option("", "--params", help="Parameters for the packet type")
):
    """Inject Unreal Engine packets"""
    from protoinspector.injector import UnrealInjector
    
    injector = UnrealInjector()
    
    if packet_type == "hello":
        result = injector.inject_hello(target_ip, port)
    elif packet_type == "login":
        username = params or "Player1"
        result = injector.inject_login(target_ip, port, username)
    elif packet_type == "movement":
        coords = params.split(",") if params else ["0", "0", "0"]
        x, y, z = float(coords[0]), float(coords[1]), float(coords[2])
        result = injector.inject_movement(target_ip, port, x, y, z)
    elif packet_type == "rpc":
        func_index = int(params) if params else 0x100
        result = injector.inject_rpc(target_ip, port, func_index)
    else:
        console.print(f"[red]Unknown packet type: {packet_type}[/red]")
        return
    
    if result.success:
        console.print(f"[green]✓ Packet sent successfully![/green]")
        console.print(f"  Sequence: {result.sequence}")
        console.print(f"  Size: {result.size} bytes")
    else:
        console.print(f"[red]✗ Failed: {result.error}[/red]")

# Add to main.py


if __name__ == "__main__":
    app()
