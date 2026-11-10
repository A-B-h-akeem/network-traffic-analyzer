"""End-to-end checks: generated captures -> parser -> detectors.

Run with:  python -m pytest
"""

from pathlib import Path

import pytest

from nta import analysis, detectors, parser, samplegen


@pytest.fixture(scope="session")
def frames(tmp_path_factory) -> dict:
    out = tmp_path_factory.mktemp("pcaps")
    return {s: parser.load_pcap(samplegen.generate(Path(out) / f"{s}.pcap", s))
            for s in samplegen.SCENARIOS}


def kinds(df, th=None) -> set[str]:
    return {a.kind for a in detectors.run_all(df, th)}


def test_normal_traffic_raises_no_alerts(frames):
    assert kinds(frames["normal"]) == set()


def test_demo_detects_every_injected_event(frames):
    assert kinds(frames["demo"]) >= {
        "Port scan", "SYN flood", "ICMP flood", "ARP spoofing",
        "Link saturation", "Dominant talker", "High retransmission rate",
    }


def test_alert_details_point_at_the_right_hosts(frames):
    alerts = {a.kind: a for a in detectors.run_all(frames["demo"])}
    assert alerts["Port scan"].source == "192.168.1.66"
    assert "22, 80, 443" in alerts["Port scan"].detail
    assert alerts["SYN flood"].target == "192.168.1.20:80"
    assert alerts["ICMP flood"].source == "192.168.1.77"
    assert alerts["ARP spoofing"].target == "192.168.1.1"
    assert alerts["Link saturation"].target == "192.168.1.12"


def test_advanced_detects_brute_force_and_dns_tunnel_only(frames):
    alerts = {a.kind: a for a in detectors.run_all(frames["advanced"])}
    assert set(alerts) == {"Brute-force login", "DNS tunnelling"}
    assert alerts["Brute-force login"].source == "203.0.113.50"
    assert alerts["Brute-force login"].target == "192.168.1.20:22"
    assert alerts["DNS tunnelling"].source == "192.168.1.77"
    assert alerts["DNS tunnelling"].target == "tunnel.example"


def test_demo_attacks_do_not_trigger_the_new_rules(frames):
    # The port scan touches port 22 once and the SYN flood uses one SYN per
    # source, so neither may be mistaken for password guessing.
    assert not {"Brute-force login", "DNS tunnelling"} & kinds(frames["demo"])


def test_raising_link_capacity_clears_saturation(frames):
    th = detectors.Thresholds(link_capacity_mbps=100)
    assert "Link saturation" not in kinds(frames["demo"], th)


def test_summary_and_throughput_are_consistent(frames):
    df = frames["demo"]
    s = analysis.summarize(df)
    tp = analysis.throughput(df)
    assert s.packets == len(df) == tp["packets"].sum()
    assert s.bytes == tp["bytes"].sum()
    assert s.peak_mbps == pytest.approx(tp["mbps"].max())
