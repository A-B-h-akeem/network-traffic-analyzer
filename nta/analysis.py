"""Traffic statistics computed from the packet table built by `nta.parser`."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd


@dataclass(frozen=True)
class Summary:
    packets: int
    bytes: int
    duration_s: float
    avg_mbps: float
    peak_mbps: float
    hosts: int


def to_mbps(n_bytes: float, seconds: float) -> float:
    return n_bytes * 8 / 1e6 / seconds if seconds > 0 else 0.0


def throughput(df: pd.DataFrame, bin_s: float = 1.0) -> pd.DataFrame:
    """Packets, bytes and Mbit/s per time bin, with empty bins filled in."""
    if df.empty:
        return pd.DataFrame(columns=["second", "packets", "bytes", "mbps"])
    bins = (df["t"] // bin_s).astype(int)
    out = df.groupby(bins).agg(packets=("length", "size"), bytes=("length", "sum"))
    out = out.reindex(range(bins.max() + 1), fill_value=0)
    out.index = out.index * bin_s
    out.index.name = "second"
    out["mbps"] = out["bytes"] * 8 / 1e6 / bin_s
    return out.reset_index()


def summarize(df: pd.DataFrame) -> Summary:
    if df.empty:
        return Summary(0, 0, 0.0, 0.0, 0.0, 0)
    duration = float(df["t"].max())
    hosts = pd.concat([df["src"], df["dst"]]).dropna().nunique()
    return Summary(
        packets=len(df),
        bytes=int(df["length"].sum()),
        duration_s=duration,
        avg_mbps=to_mbps(float(df["length"].sum()), max(duration, 1.0)),
        peak_mbps=float(throughput(df)["mbps"].max()),
        hosts=int(hosts),
    )


def breakdown(df: pd.DataFrame, column: str) -> pd.DataFrame:
    """Packets and bytes per value of `column` (e.g. "proto" or "service")."""
    out = (
        df.groupby(column)
        .agg(packets=("length", "size"), bytes=("length", "sum"))
        .sort_values("bytes", ascending=False)
        .reset_index()
    )
    out["share"] = out["bytes"] / out["bytes"].sum()
    return out


def top_talkers(df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Hosts ranked by bytes sent, with bytes received alongside."""
    ip = df.dropna(subset=["src"])
    sent = ip.groupby("src").agg(packets_sent=("length", "size"),
                                 bytes_sent=("length", "sum"))
    received = ip.groupby("dst").agg(bytes_received=("length", "sum"))
    out = sent.join(received, how="outer").fillna(0).astype(int)
    out["share_sent"] = out["bytes_sent"] / max(out["bytes_sent"].sum(), 1)
    out.index.name = "host"
    return out.sort_values("bytes_sent", ascending=False).head(n).reset_index()


def conversations(df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Host pairs ranked by total bytes in both directions."""
    ip = df.dropna(subset=["src", "dst"])
    if ip.empty:
        return pd.DataFrame(columns=["host_a", "host_b", "packets", "bytes",
                                     "first_seen", "last_seen", "mbps"])
    src, dst = ip["src"].to_numpy(), ip["dst"].to_numpy()
    a = np.where(src < dst, src, dst)
    b = np.where(src < dst, dst, src)
    out = (
        ip.assign(host_a=a, host_b=b)
        .groupby(["host_a", "host_b"])
        .agg(packets=("length", "size"), bytes=("length", "sum"),
             first_seen=("t", "min"), last_seen=("t", "max"))
        .sort_values("bytes", ascending=False)
        .head(n)
        .reset_index()
    )
    span = (out["last_seen"] - out["first_seen"]).clip(lower=1.0)
    out["mbps"] = out["bytes"] * 8 / 1e6 / span
    return out


def retransmissions(df: pd.DataFrame) -> pd.DataFrame:
    """TCP data segments seen again with the same flow and sequence number.

    A repeated (src, dst, sport, dport, seq) carrying payload means the sender
    gave up waiting for an ACK and resent it, which is a classic sign of loss
    or congestion on the path.
    """
    data = df[(df["proto"] == "TCP") & (df["payload_len"] > 0)]
    key = ["src", "dst", "sport", "dport", "seq"]
    dup = data.duplicated(subset=key, keep="first")
    flows = data.assign(retransmitted=dup).groupby(["src", "dst", "sport", "dport"])
    out = flows.agg(segments=("retransmitted", "size"),
                    retransmitted=("retransmitted", "sum")).reset_index()
    out["rate"] = out["retransmitted"] / out["segments"]
    return out.sort_values("retransmitted", ascending=False, ignore_index=True)
