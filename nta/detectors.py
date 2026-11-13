"""Rule-based detection of network bottlenecks and common attacks.

Each detector looks at the packet table and returns zero or more `Alert`s.
The thresholds are deliberately simple and adjustable, so results are easy to
explain: "host X sent SYNs to 500 different ports of host Y within 3 seconds".
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

import pandas as pd

from nta import analysis

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}

# Services where repeated connections from one host usually mean password guessing.
LOGIN_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 110: "POP3", 143: "IMAP",
               3306: "MySQL", 3389: "RDP", 5900: "VNC"}


@dataclass(frozen=True)
class Thresholds:
    # Bottlenecks
    link_capacity_mbps: float = 10.0   # capacity of the monitored link
    utilization_pct: float = 80.0      # a second above this % counts as saturated
    top_talker_share_pct: float = 50.0 # one host sending more than this % of bytes
    top_talker_min_mb: float = 1.0     # ...once at least this much was captured
    retransmission_pct: float = 3.0    # TCP segments resent, overall or per flow
    min_flow_segments: int = 100       # segments needed before a rate is judged
    # Attacks
    scan_distinct_ports: int = 20      # SYNs to this many ports of one host
    syn_flood_rate: int = 100          # SYNs per second to one host:port
    icmp_flood_rate: int = 50          # echo requests per second to one host
    brute_force_attempts: int = 20     # connections from one source to one login service
    dns_tunnel_names: int = 30         # unique names under one domain from one host
    dns_tunnel_length: int = 40        # ...with at least this average name length


@dataclass
class Alert:
    category: str      # "Attack" or "Bottleneck"
    kind: str
    severity: str      # "High", "Medium" or "Low"
    source: str
    target: str
    first_seen: float  # seconds since capture start
    last_seen: float
    detail: str


def _syn_only(df: pd.DataFrame) -> pd.DataFrame:
    return df[(df["proto"] == "TCP") & (df["tcp_flags"] == "S")]


def _peak_rate(times: pd.Series) -> int:
    return int((times // 1).value_counts().max()) if len(times) else 0


def _hosts(values: pd.Series, limit: int = 3) -> str:
    uniq = list(dict.fromkeys(values.dropna()))
    text = ", ".join(map(str, uniq[:limit]))
    return text + (f" (+{len(uniq) - limit} more)" if len(uniq) > limit else "")


# --- Attacks -----------------------------------------------------------------

def detect_port_scans(df: pd.DataFrame, th: Thresholds) -> list[Alert]:
    """One source probing many different ports on the same target."""
    syn = _syn_only(df)
    # Count ports for every pair in one vectorized pass; a SYN flood with
    # thousands of spoofed sources would make a per-pair Python loop slow.
    ports_per_pair = syn.groupby(["src", "dst"])["dport"].nunique()
    suspects = ports_per_pair[ports_per_pair >= th.scan_distinct_ports]
    alerts = []
    for (src, dst), ports in suspects.items():
        g = syn[(syn["src"] == src) & (syn["dst"] == dst)]
        # Ports that answered SYN-ACK are open; the scanner learned about them.
        replies = df[(df["src"] == dst) & (df["dst"] == src)
                     & (df["tcp_flags"] == "SA")]
        open_ports = sorted(set(replies["sport"].dropna().astype(int))
                            & set(g["dport"].dropna().astype(int)))
        span = g["t"].max() - g["t"].min()
        open_text = ", ".join(map(str, open_ports[:10])) or "none"
        alerts.append(Alert(
            "Attack", "Port scan", "High", src, dst, g["t"].min(), g["t"].max(),
            f"SYN probes to {ports} distinct ports in {span:.1f}s. "
            f"Open ports revealed: {open_text}.",
        ))
    return alerts


def detect_syn_floods(df: pd.DataFrame, th: Thresholds) -> list[Alert]:
    """A burst of connection requests that are never completed."""
    syn = _syn_only(df)
    per_target_second = syn.groupby(["dst", "dport", syn["t"] // 1]).size()
    hot = per_target_second[per_target_second >= th.syn_flood_rate]
    alerts = []
    for dst, dport in hot.index.droplevel(2).unique():
        g = syn[(syn["dst"] == dst) & (syn["dport"] == dport)]
        per_second = (g["t"] // 1).value_counts()
        flood_seconds = per_second[per_second >= th.syn_flood_rate].index
        if flood_seconds.empty:
            continue
        # Keep only the burst, so ordinary connections to the same port
        # before or after it don't stretch the alert.
        g = g[(g["t"] // 1).isin(flood_seconds)]
        peak = int(per_second.max())
        answered = df[(df["src"] == dst) & (df["sport"] == dport)
                      & (df["tcp_flags"] == "SA")
                      & df["t"].between(g["t"].min(), g["t"].max() + 1)]
        sources = g["src"].nunique()
        spoof_hint = " Many distinct sources suggests spoofed IPs." if sources > 50 else ""
        alerts.append(Alert(
            "Attack", "SYN flood", "High", _hosts(g["src"]), f"{dst}:{dport}",
            g["t"].min(), g["t"].max(),
            f"{len(g):,} SYNs from {sources:,} sources, peak {peak:,}/s; only "
            f"{len(answered) / len(g):.0%} answered with SYN-ACK.{spoof_hint}",
        ))
    return alerts


def detect_icmp_floods(df: pd.DataFrame, th: Thresholds) -> list[Alert]:
    """Ping flood: many ICMP echo requests per second to one host."""
    echo = df[(df["proto"] == "ICMP") & (df["icmp_type"] == 8)]
    alerts = []
    for dst, g in echo.groupby("dst"):
        peak = _peak_rate(g["t"])
        if peak < th.icmp_flood_rate:
            continue
        alerts.append(Alert(
            "Attack", "ICMP flood", "Medium", _hosts(g["src"]), dst,
            g["t"].min(), g["t"].max(),
            f"{len(g):,} echo requests ({g['length'].sum() / 1e6:.2f} MB), "
            f"peak {peak:,}/s.",
        ))
    return alerts


def detect_arp_spoofing(df: pd.DataFrame, th: Thresholds) -> list[Alert]:
    """The same IP announced by more than one MAC address in ARP replies.

    This is how man-in-the-middle attacks redirect a LAN's traffic: the
    attacker keeps telling victims "the gateway's IP is at my MAC".
    """
    replies = df[(df["proto"] == "ARP") & (df["arp_op"] == 2)]
    alerts = []
    for ip, g in replies.groupby("src"):
        counts = g["arp_hwsrc"].value_counts()
        if len(counts) < 2:
            continue
        macs = ", ".join(f"{mac} ({n} replies)" for mac, n in counts.items())
        # The conflict starts when the second MAC first claims the IP; replies
        # before that came from a single owner and were legitimate.
        conflict_start = g.groupby("arp_hwsrc")["t"].min().sort_values().iloc[1]
        alerts.append(Alert(
            "Attack", "ARP spoofing", "High", _hosts(g["arp_hwsrc"]), ip,
            float(conflict_start), g["t"].max(),
            f"{ip} claimed by {len(counts)} MAC addresses: {macs}. "
            f"Traffic for {ip} may be intercepted.",
        ))
    return alerts


def detect_brute_force(df: pd.DataFrame, th: Thresholds) -> list[Alert]:
    """Many connections from one source to one login service (password guessing).

    A person logs in once and keeps the session open; a guessing tool opens a
    new connection for every few passwords it tries.
    """
    syn = _syn_only(df)
    syn = syn[syn["dport"].isin(list(LOGIN_PORTS))]
    attempts = syn.groupby(["src", "dst", "dport"]).size()
    alerts = []
    for (src, dst, dport), n in attempts[attempts >= th.brute_force_attempts].items():
        g = syn[(syn["src"] == src) & (syn["dst"] == dst) & (syn["dport"] == dport)]
        span = max(g["t"].max() - g["t"].min(), 1.0)
        alerts.append(Alert(
            "Attack", "Brute-force login", "High", src, f"{dst}:{dport}",
            g["t"].min(), g["t"].max(),
            f"{n:,} {LOGIN_PORTS[int(dport)]} connection attempts in {span:.0f}s "
            f"({n / span * 60:.0f} per minute), typical of password guessing.",
        ))
    return alerts


def _base_domain(name: str) -> str:
    # The last two labels ("a.b.tunnel.example" -> "tunnel.example"). Simple on
    # purpose: suffixes like co.uk are grouped one level too high, which only
    # makes the rule stricter.
    return ".".join(name.split(".")[-2:])


def detect_dns_tunnelling(df: pd.DataFrame, th: Thresholds) -> list[Alert]:
    """Data hidden in DNS queries: a stream of long, never-repeated names under
    one domain. Normal lookups reuse a few short names that are then cached."""
    queries = df.dropna(subset=["dns_query"])
    if queries.empty:
        return []
    queries = queries.assign(domain=queries["dns_query"].map(_base_domain))
    unique_names = queries.groupby(["src", "domain"])["dns_query"].nunique()
    alerts = []
    for (src, domain), _ in unique_names[unique_names >= th.dns_tunnel_names].items():
        g = queries[(queries["src"] == src) & (queries["domain"] == domain)]
        names = g["dns_query"].drop_duplicates()
        avg_len = names.str.len().mean()
        if avg_len < th.dns_tunnel_length:
            continue
        # Everything left of the domain is the payload the client smuggled out.
        payload = (names.str.len() - len(domain) - 1).clip(lower=0).sum()
        alerts.append(Alert(
            "Attack", "DNS tunnelling", "High", src, domain,
            g["t"].min(), g["t"].max(),
            f"{len(names):,} unique names under {domain}, average {avg_len:.0f} "
            f"characters (about {payload / 1000:.1f} KB of encoded data), typical "
            "of data exfiltration or a covert channel over DNS.",
        ))
    return alerts


# --- Bottlenecks -------------------------------------------------------------

def detect_link_saturation(df: pd.DataFrame, th: Thresholds) -> list[Alert]:
    """Periods where throughput approaches the link's capacity."""
    tp = analysis.throughput(df)
    limit = th.link_capacity_mbps * th.utilization_pct / 100
    busy = tp[tp["mbps"] >= limit]
    if busy.empty:
        return []
    # Merge consecutive busy seconds into one episode.
    episode = (busy["second"].diff() != 1).cumsum()
    alerts = []
    for _, ep in busy.groupby(episode):
        start, end = ep["second"].min(), ep["second"].max() + 1
        window = df[(df["t"] >= start) & (df["t"] < end)]
        top = window.groupby(["src", "dst"])["length"].sum().sort_values()
        (t_src, t_dst), t_bytes = top.index[-1], top.iloc[-1]
        share = t_bytes / window["length"].sum()
        peak = ep["mbps"].max()
        alerts.append(Alert(
            "Bottleneck", "Link saturation",
            "High" if peak >= th.link_capacity_mbps else "Medium",
            t_src, t_dst, float(start), float(end),
            f"{len(ep)}s above {th.utilization_pct:.0f}% of the "
            f"{th.link_capacity_mbps:g} Mbit/s link (peak {peak:.1f} Mbit/s). "
            f"{t_src} → {t_dst} caused {share:.0%} of it.",
        ))
    return alerts


def detect_top_talker(df: pd.DataFrame, th: Thresholds) -> list[Alert]:
    # Shares are meaningless on a tiny sample (e.g. the first seconds of a
    # live capture), so wait until enough traffic has been seen.
    if df["length"].sum() < th.top_talker_min_mb * 1e6:
        return []
    talkers = analysis.top_talkers(df, n=1)
    if talkers.empty or talkers["share_sent"].iloc[0] * 100 < th.top_talker_share_pct:
        return []
    host, share = talkers["host"].iloc[0], talkers["share_sent"].iloc[0]
    sent = df[df["src"] == host]
    peers = sent.groupby("dst")["length"].sum().sort_values(ascending=False)
    return [Alert(
        "Bottleneck", "Dominant talker", "Medium", host, _hosts(pd.Series(peers.index)),
        sent["t"].min(), sent["t"].max(),
        f"{host} sent {share:.0%} of all bytes "
        f"({talkers['bytes_sent'].iloc[0] / 1e6:.1f} MB); it may starve other hosts.",
    )]


def detect_retransmissions(df: pd.DataFrame, th: Thresholds) -> list[Alert]:
    flows = analysis.retransmissions(df)
    if flows.empty:
        return []
    alerts = []
    total, resent = flows["segments"].sum(), flows["retransmitted"].sum()
    if total >= th.min_flow_segments and resent / total * 100 >= th.retransmission_pct:
        alerts.append(Alert(
            "Bottleneck", "High retransmission rate", "Medium", "All TCP flows", "—",
            float(df["t"].min()), float(df["t"].max()),
            f"{resent:,} of {total:,} TCP data segments ({resent / total:.1%}) were "
            "resent, a sign of packet loss or congestion.",
        ))
    bad = flows[(flows["segments"] >= th.min_flow_segments)
                & (flows["rate"] * 100 >= th.retransmission_pct)]
    for row in bad.itertuples():
        f = df[(df["src"] == row.src) & (df["dst"] == row.dst)
               & (df["sport"] == row.sport) & (df["dport"] == row.dport)]
        alerts.append(Alert(
            "Bottleneck", "Lossy TCP flow", "Low",
            f"{row.src}:{row.sport}", f"{row.dst}:{row.dport}",
            f["t"].min(), f["t"].max(),
            f"{row.retransmitted:,} of {row.segments:,} segments "
            f"({row.rate:.1%}) retransmitted.",
        ))
    return alerts


DETECTORS = [
    detect_port_scans, detect_syn_floods, detect_icmp_floods, detect_arp_spoofing,
    detect_brute_force, detect_dns_tunnelling, detect_link_saturation, detect_top_talker, detect_retransmissions,
]


def run_all(df: pd.DataFrame, th: Thresholds | None = None) -> list[Alert]:
    th = th or Thresholds()
    if df.empty:
        return []
    alerts = [a for detector in DETECTORS for a in detector(df, th)]
    return sorted(alerts, key=lambda a: (SEVERITY_ORDER[a.severity], a.first_seen))


def alerts_frame(alerts: list[Alert]) -> pd.DataFrame:
    columns = list(Alert.__dataclass_fields__)
    return pd.DataFrame([asdict(a) for a in alerts], columns=columns)
