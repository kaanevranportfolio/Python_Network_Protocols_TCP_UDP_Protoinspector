import struct
from protoinspector.analyzer import analyze_packet_file
from protoinspector.protocol import Packet

def test_analyzer_reads_file(capsys):
    pkt1 = Packet(0x1234, 1, b'foo').serialize()
    pkt2 = Packet(0x1234, 2, b'bar').serialize()
    with open("test_packets.bin", "wb") as f:
        for pkt in [pkt1, pkt2]:
            f.write(struct.pack("!I", len(pkt)))
            f.write(pkt)

    analyze_packet_file("test_packets.bin")
    out = capsys.readouterr().out

    # Check that the hex output contains the ASCII payloads in hex form
    assert "666f6f" in out  # hex for 'foo'
    assert "626172" in out  # hex for 'bar'

    import os
    os.remove("test_packets.bin")
