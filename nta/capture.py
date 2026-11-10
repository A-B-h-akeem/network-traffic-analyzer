"""Live packet capture with Scapy.

Capturing needs privileges and a capture driver:
* Windows: install Npcap (https://npcap.com) and run as Administrator.
* Linux/macOS: run with sudo (or grant the capture capability).
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

from scapy.config import conf
from scapy.plist import PacketList
from scapy.sendrecv import sniff


@dataclass(frozen=True)
class Interface:
    name: str
    description: str
    ip: str


def capture_status() -> tuple[bool, str]:
    """Whether live capture can work here, and why not if it can't."""
    if sys.platform == "win32":
        if not conf.use_pcap:
            return False, (
                "Npcap is not installed. Download it from https://npcap.com, "
                "install it with \"WinPcap API-compatible mode\" ticked, then "
                "restart this program as Administrator."
            )
        return True, "Npcap found. If capture fails, run as Administrator."
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        return False, "Live capture needs root. Restart with sudo."
    return True, "Ready to capture."


def list_interfaces() -> list[Interface]:
    if conf.ifaces is None:
        return []
    found = []
    for iface in conf.ifaces.values():
        found.append(Interface(
            name=iface.network_name or iface.name,
            description=getattr(iface, "description", "") or iface.name,
            ip=iface.ip or "",
        ))
    return sorted(found, key=lambda i: (not i.ip, i.description))


def default_interface() -> str | None:
    iface = conf.iface
    return getattr(iface, "network_name", None) or (str(iface) if iface else None)


def capture(iface: str | None, seconds: float, bpf_filter: str | None = None,
            max_packets: int = 0) -> PacketList:
    """Capture for `seconds` (or until `max_packets` if that is reached first)."""
    return sniff(iface=iface, timeout=seconds, filter=bpf_filter or None,
                 count=max_packets, store=True)
