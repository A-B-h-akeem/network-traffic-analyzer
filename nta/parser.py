"""Turn packets (from a pcap/pcapng file or a live capture) into a pandas DataFrame.

One row per packet. Every later step (statistics, detectors, dashboard) works on
this table, so it doesn't matter where the packets came from.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import pandas as pd
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet
from scapy.utils import PcapReader

# Application protocol guessed from the well-known port of either endpoint.
WELL_KNOWN_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    161: "SNMP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 3306: "MySQL",
    3389: "RDP", 5353: "mDNS", 8080: "HTTP-alt",
}

COLUMNS = [
    "time", "length", "src_mac", "dst_mac", "src", "dst", "proto", "service",
    "sport", "dport", "tcp_flags", "seq", "payload_len", "icmp_type",
    "arp_op", "arp_hwsrc", "dns_query",
]
_INT_COLUMNS = ["sport", "dport", "seq", "payload_len", "icmp_type", "arp_op"]


def _service(proto: str, sport: int | None, dport: int | None) -> str:
    for port in (dport, sport):
        if port in WELL_KNOWN_PORTS:
            return WELL_KNOWN_PORTS[port]
    return proto


def packet_to_record(pkt: Packet) -> dict:
    """Extract the fields the analysis needs from one packet."""
    rec: dict = {"time": float(pkt.time), "length": len(pkt)}

    if pkt.haslayer(Ether):
        rec["src_mac"] = pkt[Ether].src
        rec["dst_mac"] = pkt[Ether].dst

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        rec.update(proto="ARP", service="ARP", src=arp.psrc, dst=arp.pdst,
                   arp_op=int(arp.op), arp_hwsrc=arp.hwsrc)
        return rec

    if pkt.haslayer(IP):
        rec["src"], rec["dst"] = pkt[IP].src, pkt[IP].dst
    elif pkt.haslayer(IPv6):
        rec["src"], rec["dst"] = pkt[IPv6].src, pkt[IPv6].dst
    else:
        rec.update(proto="Other", service="Other")
        return rec

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        rec.update(proto="TCP", sport=tcp.sport, dport=tcp.dport,
                   tcp_flags=str(tcp.flags), seq=tcp.seq,
                   payload_len=len(tcp.payload))
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        rec.update(proto="UDP", sport=udp.sport, dport=udp.dport,
                   payload_len=len(udp.payload))
    elif pkt.haslayer(ICMP):
        rec.update(proto="ICMP", icmp_type=int(pkt[ICMP].type))
    else:
        rec["proto"] = "IPv6" if pkt.haslayer(IPv6) else "IP"

    rec["service"] = _service(rec["proto"], rec.get("sport"), rec.get("dport"))

    if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR):
        rec["dns_query"] = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")

    return rec


def packets_to_frame(packets: Iterable[Packet]) -> pd.DataFrame:
    return records_to_frame([packet_to_record(p) for p in packets])


def records_to_frame(records: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame.from_records(records, columns=COLUMNS)
    for col in _INT_COLUMNS:
        df[col] = df[col].astype("Int64")
    df["time"] = df["time"].astype(float)
    df["length"] = df["length"].astype(int)
    df = df.sort_values("time", ignore_index=True)
    # Seconds since the first packet: easier to read than epoch timestamps.
    df["t"] = df["time"] - df["time"].min() if len(df) else df["time"]
    return df


def load_pcap(path: str | Path, max_packets: int | None = None) -> pd.DataFrame:
    """Read a .pcap or .pcapng file (format is detected automatically)."""

    def _iter():
        with PcapReader(str(path)) as reader:
            for i, pkt in enumerate(reader):
                if max_packets is not None and i >= max_packets:
                    break
                yield pkt

    return packets_to_frame(_iter())
