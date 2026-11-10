"""Command-line interface for the network traffic analyzer.

Examples:
    python cli.py generate                      # write the sample captures to samples/
    python cli.py analyze samples/demo.pcap     # print statistics and alerts
    python cli.py analyze my.pcap --json report.json   # also save summary + alerts as JSON
    python cli.py interfaces                    # list capture interfaces
    python cli.py capture -d 30 -o mine.pcap    # capture 30 s live, then analyze it
    python cli.py monitor                       # watch live traffic, print alerts as they appear
    python cli.py monitor --replay samples/demo.pcap --speed 5
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
import time
from pathlib import Path

import pandas as pd
from scapy.utils import wrpcap

from nta import analysis, capture, detectors, parser, samplegen
from nta.monitor import Monitor


def _mb(n: float) -> str:
    return f"{n / 1e6:.2f} MB"


def print_report(df: pd.DataFrame, th: detectors.Thresholds) -> None:
    if df.empty:
        print("\nNo packets captured.")
        return
    s = analysis.summarize(df)
    print("\n=== Summary ===")
    print(f"Packets: {s.packets:,}   Data: {_mb(s.bytes)}   Duration: {s.duration_s:.1f}s   "
          f"Hosts: {s.hosts:,}")
    print(f"Throughput: avg {s.avg_mbps:.2f} Mbit/s, peak {s.peak_mbps:.2f} Mbit/s "
          f"(link capacity {th.link_capacity_mbps:g} Mbit/s)")

    print("\n=== Protocols ===")
    proto = analysis.breakdown(df, "proto")
    proto["bytes"] = proto["bytes"].map(_mb)
    proto["share"] = proto["share"].map("{:.1%}".format)
    print(proto.to_string(index=False))

    print("\n=== Top talkers (by bytes sent) ===")
    talkers = analysis.top_talkers(df, n=5)
    for col in ("bytes_sent", "bytes_received"):
        talkers[col] = talkers[col].map(_mb)
    talkers["share_sent"] = talkers["share_sent"].map("{:.1%}".format)
    print(talkers.to_string(index=False))

    alerts = detectors.run_all(df, th)
    print(f"\n=== Alerts ({len(alerts)}) ===")
    if not alerts:
        print("No bottlenecks or attacks detected.")
    for a in alerts:
        print(f"[{a.severity:<6}] {a.category} / {a.kind}  "
              f"t={a.first_seen:.1f}-{a.last_seen:.1f}s")
        print(f"          {a.source} -> {a.target}")
        print(f"          {a.detail}")


def write_json(path: str, df: pd.DataFrame, th: detectors.Thresholds) -> None:
    """Machine-readable results, e.g. for a SIEM or a script that acts on alerts."""
    report = {
        "summary": dataclasses.asdict(analysis.summarize(df)),
        "thresholds": dataclasses.asdict(th),
        "alerts": [dataclasses.asdict(a) for a in detectors.run_all(df, th)],
    }
    Path(path).write_text(json.dumps(report, indent=2, default=float), encoding="utf-8")
    print(f"\nSaved summary and {len(report['alerts'])} alert(s) to {path}")


def run_monitor(mon: Monitor, th: detectors.Thresholds, interval: float,
                duration: float) -> pd.DataFrame:
    """Re-analyze every `interval` seconds and print each alert once, when it
    first appears. Stops when the feed ends, after `duration` s, or on Ctrl+C."""
    seen: set[tuple] = set()
    began = time.monotonic()
    try:
        while True:
            time.sleep(interval)
            elapsed = time.monotonic() - began
            df = mon.snapshot()
            if not df.empty:
                tp = analysis.throughput(df)
                rate = tp["mbps"].iloc[-2] if len(tp) > 1 else tp["mbps"].iloc[-1]
                alerts = detectors.run_all(df, th)
                print(f"[{elapsed:6.1f}s] {len(df):>8,} packets  "
                      f"{rate:6.2f} Mbit/s  {len(alerts)} alert(s)")
                for a in alerts:
                    # Source/target lists grow as traffic arrives ("+N more"),
                    # so identify an alert by its first host and start time.
                    key = (a.kind, a.source.split(",")[0], round(a.first_seen))
                    if key not in seen:
                        seen.add(key)
                        print(f"   NEW [{a.severity}] {a.kind}: {a.source} -> {a.target}")
                        print(f"       {a.detail}")
            if not mon.running or (duration and elapsed >= duration):
                break
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        mon.stop()
    if mon.error:
        print(f"Monitor error: {mon.error}", file=sys.stderr)
    return mon.snapshot()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    gen = sub.add_parser("generate", help="create sample pcap files")
    gen.add_argument("--out-dir", default="samples")

    an = sub.add_parser("analyze", help="analyze a .pcap/.pcapng file")
    an.add_argument("pcap")
    an.add_argument("--capacity", type=float, default=10.0,
                    help="link capacity in Mbit/s (default 10)")
    an.add_argument("--max-packets", type=int, default=None)
    an.add_argument("--json", metavar="PATH", help="also save summary and alerts as JSON")

    sub.add_parser("interfaces", help="list interfaces available for capture")

    cap = sub.add_parser("capture", help="capture live traffic, save and analyze it")
    cap.add_argument("-i", "--iface", default=None, help="interface (default: system default)")
    cap.add_argument("-d", "--duration", type=float, default=30)
    cap.add_argument("-f", "--filter", default=None, help='BPF filter, e.g. "tcp port 443"')
    cap.add_argument("-o", "--output", default="capture.pcap")
    cap.add_argument("--capacity", type=float, default=10.0)

    mon = sub.add_parser("monitor", help="monitor continuously, printing alerts as they appear")
    mon.add_argument("--replay", metavar="PCAP", help="replay a capture file instead of "
                     "live traffic (no capture rights needed)")
    mon.add_argument("--speed", type=float, default=1.0, help="replay speed multiplier")
    mon.add_argument("-i", "--iface", default=None)
    mon.add_argument("-f", "--filter", default=None, help="BPF filter (live only)")
    mon.add_argument("--interval", type=float, default=2.0, help="seconds between updates")
    mon.add_argument("-d", "--duration", type=float, default=0,
                     help="stop after this many seconds (default: until Ctrl+C)")
    mon.add_argument("-o", "--output", default=None, help="save the packets to this pcap")
    mon.add_argument("--capacity", type=float, default=10.0)

    args = ap.parse_args(argv)

    if args.cmd == "generate":
        for scenario in samplegen.SCENARIOS:
            path = samplegen.generate(Path(args.out_dir) / f"{scenario}.pcap", scenario)
            print(f"Wrote {path}")
        return 0

    if args.cmd == "analyze":
        df = parser.load_pcap(args.pcap, args.max_packets)
        th = detectors.Thresholds(link_capacity_mbps=args.capacity)
        print_report(df, th)
        if args.json:
            write_json(args.json, df, th)
        return 0

    ok, message = capture.capture_status()
    if args.cmd == "interfaces":
        print(message)
        for iface in capture.list_interfaces():
            print(f"  {iface.name:<45} {iface.ip:<16} {iface.description}")
        return 0

    if args.cmd == "capture":
        if not ok:
            print(f"Cannot capture: {message}", file=sys.stderr)
            return 1
        print(f"Capturing for {args.duration:g}s on {args.iface or capture.default_interface()}...")
        packets = capture.capture(args.iface, args.duration, args.filter)
        wrpcap(args.output, packets)
        print(f"Saved {len(packets):,} packets to {args.output}")
        print_report(parser.packets_to_frame(packets),
                     detectors.Thresholds(link_capacity_mbps=args.capacity))
        return 0

    if args.cmd == "monitor":
        monitor = Monitor()
        if args.replay:
            print(f"Loading {args.replay}...")
            monitor.start_replay(args.replay, args.speed, frame=parser.load_pcap(args.replay))
        elif not ok:
            print(f"Cannot capture: {message}\nTip: try --replay samples/demo.pcap",
                  file=sys.stderr)
            return 1
        else:
            monitor.start_live(args.iface, args.filter)
        th = detectors.Thresholds(link_capacity_mbps=args.capacity)
        print(f"{monitor.description}. Press Ctrl+C to stop.")
        df = run_monitor(monitor, th, args.interval, args.duration)
        if args.output:
            Path(args.output).write_bytes(monitor.pcap_bytes())
            print(f"Saved {len(monitor):,} packets to {args.output}")
        print_report(df, th)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
