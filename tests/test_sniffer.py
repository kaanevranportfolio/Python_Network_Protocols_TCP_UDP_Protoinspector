import os
import struct
import tempfile
from protoinspector.protocol import Packet
from protoinspector.sniffer import start_sniffing

def test_sniffer_saves_packets(monkeypatch):
    fake_payloads = [b"one", b"two", b"three"]

    def mock_sniff(iface, prn, count, **kwargs):
        for i, p in enumerate(fake_payloads):
            class FakePkt:
                def __bytes__(self):
                    # Provide required arguments for Packet
                    return Packet(protocol_id=1, sequence=i, payload=p).serialize()
                def summary(self): return f"FakePkt({p!r})"
                def __contains__(self, item):
                    from scapy.all import Raw
                    return item is Raw
                def __getitem__(self, item):
                    from scapy.all import Raw
                    if item is Raw:
                        return self
                    raise KeyError(item)
            prn(FakePkt())

    monkeypatch.setattr("protoinspector.sniffer.sniff", mock_sniff)

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmpfile:
        output_path = tmpfile.name

    try:
        start_sniffing("fake0", len(fake_payloads), output_file=output_path)
        assert os.path.exists(output_path)

        with open(output_path, "rb") as f:
            for expected in fake_payloads:
                size_bytes = f.read(4)
                assert len(size_bytes) == 4, "Not enough bytes for size header"
                size = struct.unpack("!I", size_bytes)[0]
                raw = f.read(size)
                pkt = Packet.deserialize(raw)
                assert pkt.payload == expected
    finally:
        os.remove(output_path)