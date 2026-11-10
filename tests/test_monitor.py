import time

from nta import parser, samplegen
from nta.monitor import Monitor


def _wait(condition, timeout=60.0):
    deadline = time.monotonic() + timeout
    while not condition() and time.monotonic() < deadline:
        time.sleep(0.1)


def test_replay_delivers_every_packet(tmp_path):
    path = samplegen.generate(tmp_path / "normal.pcap", "normal")
    mon = Monitor()
    mon.start_replay(path, speed=1000)
    _wait(lambda: not mon.running)
    assert not mon.running and mon.error is None
    assert len(mon.snapshot()) == len(parser.load_pcap(path))


def test_stop_ends_replay_early(tmp_path):
    path = samplegen.generate(tmp_path / "normal.pcap", "normal")
    mon = Monitor()
    mon.start_replay(path, speed=1)  # would take about a minute
    _wait(lambda: len(mon) > 0, timeout=10)
    mon.stop()
    assert not mon.running
    assert 0 < len(mon) < len(parser.load_pcap(path))
    assert mon.pcap_bytes()[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4")
