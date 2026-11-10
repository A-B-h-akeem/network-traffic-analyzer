"""Generate synthetic but realistic pcap files for testing and demos.

Live capture needs admin rights and a capture driver (Npcap on Windows), and a
real network rarely gets attacked on cue. These files let you run and verify
the analyzer anywhere:

* ``normal``: one minute of a small office LAN (DNS lookups, HTTPS browsing,
  routine ARP). The analyzer should raise no alerts.
* ``demo``: the same baseline plus a port scan, ARP spoofing, a large download
  that saturates a 10 Mbit/s link, a SYN flood and an ICMP flood.
* ``advanced``: the baseline plus an SSH password-guessing attack from the
  internet and data exfiltration over DNS from an infected host.
"""

from __future__ import annotations

import random
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap

START = 1_762_765_200.0  # 2025-11-10 09:00 UTC; any fixed epoch works
DURATION = 60.0
MSS = 1460

GATEWAY = ("192.168.1.1", "00:11:22:33:44:01")
WEB_SERVER = ("192.168.1.20", "00:11:22:33:44:20")
CLIENTS = [(f"192.168.1.{i}", f"00:11:22:33:44:{i:02x}") for i in range(10, 15)]
ATTACKER = ("192.168.1.66", "de:ad:be:ef:00:66")
INFECTED = ("192.168.1.77", "00:11:22:33:44:77")
DNS_SERVER = "8.8.8.8"
INTERNET = {
    "142.250.183.14": "www.google.com",
    "151.101.1.69": "cdn.example-video.com",
    "104.16.132.229": "api.cloudflare.com",
    "13.107.42.14": "outlook.office.com",
}
BROADCAST = "ff:ff:ff:ff:ff:ff"


class _Trace:
    """Collects packets with timestamps, then writes them in time order."""

    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.packets: list[Packet] = []

    def add(self, t: float, pkt: Packet) -> None:
        pkt.time = START + t
        self.packets.append(pkt)

    def write(self, path: Path) -> None:
        self.packets.sort(key=lambda p: p.time)
        wrpcap(str(path), self.packets)


def _l2(src_mac: str, dst_mac: str) -> Ether:
    return Ether(src=src_mac, dst=dst_mac)


def _dns_lookup(tr: _Trace, t: float, client, name: str, answer: str) -> None:
    ip, mac = client
    sport, qid = tr.rng.randint(49152, 65535), tr.rng.randint(0, 65535)
    query = DNS(id=qid, rd=1, qd=DNSQR(qname=name))
    tr.add(t, _l2(mac, GATEWAY[1]) / IP(src=ip, dst=DNS_SERVER)
           / UDP(sport=sport, dport=53) / query)
    reply = DNS(id=qid, qr=1, rd=1, ra=1, qd=DNSQR(qname=name),
                an=DNSRR(rrname=name, rdata=answer, ttl=300))
    tr.add(t + tr.rng.uniform(0.01, 0.04), _l2(GATEWAY[1], mac)
           / IP(src=DNS_SERVER, dst=ip) / UDP(sport=53, dport=sport) / reply)


def _tcp_session(tr: _Trace, t: float, client, server_ip: str, server_mac: str,
                 dport: int, segments: int, rate_mbps: float,
                 loss: float = 0.003) -> float:
    """A full TCP connection: handshake, server-to-client data, FIN.

    Returns the time the session ends. `loss` is the chance a data segment is
    retransmitted, which is how congestion shows up in a capture.
    """
    cip, cmac = client
    sport = tr.rng.randint(49152, 65535)
    c_seq, s_seq = tr.rng.getrandbits(32), tr.rng.getrandbits(32)
    rtt = tr.rng.uniform(0.01, 0.03)

    def c2s(when, flags, seq, ack, payload=b""):
        tr.add(when, _l2(cmac, server_mac) / IP(src=cip, dst=server_ip)
               / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack) / payload)

    def s2c(when, flags, seq, ack, payload=b""):
        tr.add(when, _l2(server_mac, cmac) / IP(src=server_ip, dst=cip)
               / TCP(sport=dport, dport=sport, flags=flags, seq=seq, ack=ack) / payload)

    c2s(t, "S", c_seq, 0)
    s2c(t + rtt / 2, "SA", s_seq, c_seq + 1)
    c2s(t + rtt, "A", c_seq + 1, s_seq + 1)
    request = Raw(b"\x16\x03\x01" + bytes(tr.rng.randint(200, 500)))
    c2s(t + rtt + 0.001, "PA", c_seq + 1, s_seq + 1, request)
    c_seq += 1 + len(request)

    gap = MSS * 8 / (rate_mbps * 1e6)  # time to send one segment at this rate
    now, seq = t + rtt * 1.5, s_seq + 1
    for i in range(segments):
        size = MSS if i < segments - 1 else tr.rng.randint(100, MSS)
        payload = Raw(bytes(size))
        s2c(now, "PA" if i == segments - 1 else "A", seq, c_seq, payload)
        if tr.rng.random() < loss:  # the segment was lost and sent again
            s2c(now + rtt * 2, "A", seq, c_seq, payload)
        if i % 2:
            c2s(now + rtt / 2, "A", c_seq, seq + size)
        seq += size
        now += gap * tr.rng.uniform(0.8, 1.2)

    c2s(now + 0.05, "FA", c_seq, seq)
    s2c(now + 0.05 + rtt / 2, "FA", seq, c_seq + 1)
    c2s(now + 0.05 + rtt, "A", c_seq + 1, seq + 1)
    return now + 0.05 + rtt


def _baseline(tr: _Trace) -> None:
    """Ordinary office traffic: browsing plus routine ARP."""
    names = list(INTERNET.items())
    for client in CLIENTS:
        t = tr.rng.uniform(0, 3)
        while t < DURATION - 3:
            server_ip, name = tr.rng.choice(names)
            _dns_lookup(tr, t, client, name, server_ip)
            t = _tcp_session(tr, t + 0.05, client, server_ip, GATEWAY[1], 443,
                             segments=tr.rng.randint(10, 60),
                             rate_mbps=tr.rng.uniform(1, 3))
            t += tr.rng.uniform(1.5, 5)
    # Clients occasionally re-resolve the gateway; the real gateway answers.
    for t in range(2, int(DURATION), 10):
        ip, mac = tr.rng.choice(CLIENTS)
        tr.add(t, _l2(mac, BROADCAST) / ARP(op=1, hwsrc=mac, psrc=ip, pdst=GATEWAY[0]))
        tr.add(t + 0.002, _l2(GATEWAY[1], mac)
               / ARP(op=2, hwsrc=GATEWAY[1], psrc=GATEWAY[0], hwdst=mac, pdst=ip))


def _port_scan(tr: _Trace, start: float, ports=range(1, 501), open_ports=(22, 80, 443)):
    """TCP SYN scan (like `nmap -sS`) of the web server from the attacker."""
    a_ip, a_mac = ATTACKER
    v_ip, v_mac = WEB_SERVER
    sport = 40000
    for i, port in enumerate(ports):
        t = start + i * 0.005
        seq = tr.rng.getrandbits(32)
        tr.add(t, _l2(a_mac, v_mac) / IP(src=a_ip, dst=v_ip)
               / TCP(sport=sport, dport=port, flags="S", seq=seq))
        if port in open_ports:
            tr.add(t + 0.001, _l2(v_mac, a_mac) / IP(src=v_ip, dst=a_ip)
                   / TCP(sport=port, dport=sport, flags="SA", seq=tr.rng.getrandbits(32),
                         ack=seq + 1))
            tr.add(t + 0.002, _l2(a_mac, v_mac) / IP(src=a_ip, dst=v_ip)
                   / TCP(sport=sport, dport=port, flags="R", seq=seq + 1))
        else:
            tr.add(t + 0.001, _l2(v_mac, a_mac) / IP(src=v_ip, dst=a_ip)
                   / TCP(sport=port, dport=sport, flags="RA", seq=0, ack=seq + 1))


def _arp_spoof(tr: _Trace, start: float, end: float):
    """Attacker repeatedly tells every client 'the gateway is at my MAC'."""
    a_mac = ATTACKER[1]
    t = start
    while t < end:
        for ip, mac in CLIENTS:
            tr.add(t, _l2(a_mac, mac)
                   / ARP(op=2, hwsrc=a_mac, psrc=GATEWAY[0], hwdst=mac, pdst=ip))
        t += 2


def _bulk_download(tr: _Trace, start: float):
    """A ~6 s download at ~11 Mbit/s, more than the 10 Mbit/s link can carry,
    so it also suffers retransmissions."""
    _tcp_session(tr, start, CLIENTS[2], "151.101.1.69", GATEWAY[1], 443,
                 segments=5600, rate_mbps=11.0, loss=0.06)


def _syn_flood(tr: _Trace, start: float, count: int = 2500, seconds: float = 4):
    """Spoofed-source SYN flood on the web server's port 80. The server answers
    the first few hundred, then its backlog is full and it goes quiet."""
    v_ip, v_mac = WEB_SERVER
    for i in range(count):
        t = start + i * seconds / count
        src = f"{tr.rng.randint(11, 223)}.{tr.rng.randint(0, 255)}." \
              f"{tr.rng.randint(0, 255)}.{tr.rng.randint(1, 254)}"
        sport, seq = tr.rng.randint(1024, 65535), tr.rng.getrandbits(32)
        tr.add(t, _l2(GATEWAY[1], v_mac) / IP(src=src, dst=v_ip)
               / TCP(sport=sport, dport=80, flags="S", seq=seq))
        if i < 256:
            tr.add(t + 0.0005, _l2(v_mac, GATEWAY[1]) / IP(src=v_ip, dst=src)
                   / TCP(sport=80, dport=sport, flags="SA",
                         seq=tr.rng.getrandbits(32), ack=seq + 1))


def _icmp_flood(tr: _Trace, start: float, count: int = 400, seconds: float = 2):
    """Ping flood with large payloads from an infected LAN host."""
    s_ip, s_mac = INFECTED
    v_ip, v_mac = WEB_SERVER
    for i in range(count):
        t = start + i * seconds / count
        tr.add(t, _l2(s_mac, v_mac) / IP(src=s_ip, dst=v_ip)
               / ICMP(type=8, id=0x4242, seq=i) / Raw(bytes(1000)))
        if i % 2 == 0:
            tr.add(t + 0.0004, _l2(v_mac, s_mac) / IP(src=v_ip, dst=s_ip)
                   / ICMP(type=0, id=0x4242, seq=i) / Raw(bytes(1000)))


def _ssh_brute_force(tr: _Trace, start: float, attempts: int = 120,
                     seconds: float = 30):
    """An internet host guessing SSH passwords on the web server: each attempt
    is a short connection (handshake, banner, failed login, close)."""
    a_ip = "203.0.113.50"  # documentation range (TEST-NET-3)
    v_ip, v_mac = WEB_SERVER
    for i in range(attempts):
        t = start + i * seconds / attempts
        sport = 50000 + i
        c, s = tr.rng.getrandbits(32), tr.rng.getrandbits(32)

        def c2s(dt, flags, seq, ack, payload=b""):
            tr.add(t + dt, _l2(GATEWAY[1], v_mac) / IP(src=a_ip, dst=v_ip)
                   / TCP(sport=sport, dport=22, flags=flags, seq=seq, ack=ack) / payload)

        def s2c(dt, flags, seq, ack, payload=b""):
            tr.add(t + dt, _l2(v_mac, GATEWAY[1]) / IP(src=v_ip, dst=a_ip)
                   / TCP(sport=22, dport=sport, flags=flags, seq=seq, ack=ack) / payload)

        banner = Raw(b"SSH-2.0-OpenSSH_9.6\r\n")
        login = Raw(bytes(tr.rng.randint(80, 160)))
        c2s(0, "S", c, 0)
        s2c(0.02, "SA", s, c + 1)
        c2s(0.04, "A", c + 1, s + 1)
        s2c(0.05, "PA", s + 1, c + 1, banner)
        c2s(0.07, "PA", c + 1, s + 1 + len(banner), login)
        s2c(0.12, "FA", s + 1 + len(banner), c + 1 + len(login))
        c2s(0.14, "RA", c + 1 + len(login), s + 2 + len(banner))


def _dns_tunnel(tr: _Trace, start: float, queries: int = 200, seconds: float = 40):
    """An infected host leaking data by encoding it in DNS query names under
    a domain the attacker controls (how tools like iodine and dnscat work)."""
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"  # base32
    for i in range(queries):
        chunk = "".join(tr.rng.choice(alphabet) for _ in range(52))
        name = f"{chunk}.{i:04x}.tunnel.example"
        _dns_lookup(tr, start + i * seconds / queries, INFECTED, name, "10.0.0.1")


SCENARIOS = ("demo", "normal", "advanced")


def generate(path: str | Path, scenario: str = "demo", seed: int = 7) -> Path:
    if scenario not in SCENARIOS:
        raise ValueError(f"scenario must be one of {SCENARIOS}")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tr = _Trace(seed)
    _baseline(tr)
    if scenario == "demo":
        _port_scan(tr, start=10)
        _arp_spoof(tr, start=18, end=DURATION)
        _bulk_download(tr, start=26)
        _syn_flood(tr, start=40)
        _icmp_flood(tr, start=50)
    elif scenario == "advanced":
        _ssh_brute_force(tr, start=8)
        _dns_tunnel(tr, start=15)
    tr.write(path)
    return path
