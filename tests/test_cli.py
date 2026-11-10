import json

import cli
from nta import samplegen


def test_analyze_writes_json_report(tmp_path, capsys):
    pcap = samplegen.generate(tmp_path / "advanced.pcap", "advanced")
    out = tmp_path / "report.json"
    assert cli.main(["analyze", str(pcap), "--json", str(out)]) == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["summary"]["packets"] > 0
    assert report["thresholds"]["link_capacity_mbps"] == 10.0
    assert {a["kind"] for a in report["alerts"]} == {"Brute-force login", "DNS tunnelling"}
    assert "Alerts (2)" in capsys.readouterr().out
