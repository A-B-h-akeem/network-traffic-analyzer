"""Evaluate the detectors against the events injected into the sample captures.

Run:  python evaluate.py

The sample generator records when each injected event starts and ends, which
gives exact ground truth. Three views are reported:

1. Event level: was each injected event reported, and were there alerts with
   no event behind them (false alarms)?
2. Per-second classification: every second of every capture is labelled, for
   each event type, "attack" or "normal", both from the ground truth and from
   the alerts. This gives accuracy, precision, recall and F1.
3. Detection delay: the capture is analysed as it grows, in steps of
   `--step` seconds, to find how soon after its start each event is reported.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from nta import detectors, parser, samplegen

SAMPLES = Path(__file__).parent / "samples"

# Alert kinds with a precise time window, judged second by second.
TIMED_KINDS = ["Port scan", "SYN flood", "ICMP flood", "ARP spoofing",
               "Brute-force login", "DNS tunnelling", "Link saturation"]
# Side effects of a congested link: correct only if congestion was injected.
CONGESTION_EFFECTS = {"Dominant talker", "High retransmission rate", "Lossy TCP flow"}


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def add(self, truth: bool, predicted: bool) -> None:
        if truth and predicted:
            self.tp += 1
        elif predicted:
            self.fp += 1
        elif truth:
            self.fn += 1
        else:
            self.tn += 1

    def metrics(self) -> dict[str, float]:
        total = self.tp + self.fp + self.fn + self.tn
        precision = self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0
        recall = self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        return {"accuracy": (self.tp + self.tn) / total if total else 1.0,
                "precision": precision, "recall": recall, "f1": f1}


def overlaps(a0: float, a1: float, b0: float, b1: float) -> bool:
    return a0 <= b1 and b0 <= a1


def load(scenario: str) -> pd.DataFrame:
    path = SAMPLES / f"{scenario}.pcap"
    if not path.exists():
        samplegen.generate(path, scenario)
    return parser.load_pcap(path)


def first_detection(df: pd.DataFrame, ev: samplegen.Event, origin: float,
                    th: detectors.Thresholds, step: float) -> float | None:
    """Capture time (s) at which `ev` is first reported, analysing the capture
    as it would look `step`, 2*`step`, ... seconds after `ev` starts."""
    t = ev.start - origin
    end = df["t"].max()
    while t <= end + step:
        t += step
        seen = df[df["t"] <= t]
        for a in detectors.run_all(seen, th):
            if a.kind == ev.kind and overlaps(a.first_seen + origin,
                                              a.last_seen + origin, ev.start, ev.end):
                return t
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--step", type=float, default=0.25,
                    help="resolution of the detection-delay search, in seconds")
    args = ap.parse_args()
    th = detectors.Thresholds()

    overall = Counts()
    per_kind = {k: Counts() for k in TIMED_KINDS}
    events_found = events_total = false_alarms = 0
    delays = []

    for scenario in samplegen.SCENARIOS:
        df = load(scenario)
        truth = samplegen.ground_truth(scenario)
        origin = float(df["time"].min())
        alerts = detectors.run_all(df, th)
        print(f"\n=== {scenario}.pcap: {len(df):,} packets, {len(truth)} injected "
              f"event(s), {len(alerts)} alert(s) ===")

        for ev in truth:
            hit = any(a.kind == ev.kind and overlaps(a.first_seen + origin,
                      a.last_seen + origin, ev.start, ev.end) for a in alerts)
            events_total += 1
            events_found += hit
            when = first_detection(df, ev, origin, th, args.step) if hit else None
            delay = when - (ev.start - origin) if when is not None else None
            if delay is not None:
                delays.append((ev.kind, delay))
            print(f"  {'FOUND ' if hit else 'MISSED'} {ev.kind:<18} "
                  f"{ev.start - origin:5.1f}-{ev.end - origin:5.1f} s"
                  + (f"   detected after {delay:.2f} s of attack traffic" if delay is not None else ""))

        congested = any(ev.kind == "Link saturation" for ev in truth)
        for a in alerts:
            explained = (congested if a.kind in CONGESTION_EFFECTS else
                         any(ev.kind == a.kind and overlaps(a.first_seen + origin,
                             a.last_seen + origin, ev.start, ev.end) for ev in truth))
            if not explained:
                false_alarms += 1
                print(f"  FALSE ALARM {a.kind}: {a.source} -> {a.target}")

        # Per-second labels for each kind with a precise time window.
        for second in range(int(df["t"].max()) + 1):
            s0, s1 = origin + second, origin + second + 1
            for kind in TIMED_KINDS:
                truth_on = any(ev.kind == kind and overlaps(ev.start, ev.end, s0, s1)
                               for ev in truth)
                pred_on = any(a.kind == kind and overlaps(a.first_seen + origin,
                              a.last_seen + origin, s0, s1) for a in alerts)
                per_kind[kind].add(truth_on, pred_on)
                overall.add(truth_on, pred_on)

    print("\n=== Event level ===")
    print(f"Injected events detected: {events_found} of {events_total}")
    print(f"False alarms:             {false_alarms}")

    print("\n=== Per-second classification (all three captures) ===")
    print(f"{'Event type':<18} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>5}  "
          f"{'Accuracy':>8} {'Precision':>9} {'Recall':>7} {'F1':>6}")
    for kind, c in [*per_kind.items(), ("All types", overall)]:
        m = c.metrics()
        print(f"{kind:<18} {c.tp:>4} {c.fp:>4} {c.fn:>4} {c.tn:>5}  "
              f"{m['accuracy']:>8.3f} {m['precision']:>9.3f} {m['recall']:>7.3f} {m['f1']:>6.3f}")

    print(f"\n=== Detection delay (analysis every {args.step:g} s of capture) ===")
    for kind, delay in delays:
        print(f"{kind:<18} {delay:5.2f} s")
    if delays:
        values = [d for _, d in delays]
        print(f"{'Mean':<18} {sum(values) / len(values):5.2f} s   (max {max(values):.2f} s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
