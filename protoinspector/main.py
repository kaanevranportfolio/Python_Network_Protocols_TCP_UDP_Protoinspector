# main.py

import typer
from protoinspector import sniffer, analyzer, injector

app = typer.Typer(help="ProtoInspector - Network Protocol Analysis Tool")

@app.command()
def sniff(
    interface: str = typer.Option(..., help="Network interface to capture packets on"),
    count: int = typer.Option(0, help="Number of packets to capture, 0 for unlimited"),
    output_file: str = typer.Option(None, help="File to save captured packets"),
):
    """
    Capture and analyze packets live from a network interface.
    """
    sniffer.start_sniffing(interface, count, output_file)

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

if __name__ == "__main__":
    app()
