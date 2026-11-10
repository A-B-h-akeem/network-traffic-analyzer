"""Continuous monitoring: collect packets in the background while the dashboard
or CLI repeatedly analyzes everything that has arrived so far.

Two feeds are supported:
* a network interface (live, needs Npcap/root, see `nta.capture`), and
* replay of a saved capture at its original pace (or faster), which behaves
  exactly like live traffic and works on any machine.
"""

from __future__ import annotations

import tempfile
import threading
import time
from collections import deque
from itertools import islice
from pathlib import Path

import numpy as np
import pandas as pd
from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer
from scapy.utils import PcapReader, wrpcap

from nta import parser


class Monitor:
    """Collects packets from one feed; analyze them with `snapshot()`.

    Only the newest `max_packets` are kept, so memory stays bounded on a long
    run and the analysis covers a rolling window.
    """

    def __init__(self, max_packets: int = 200_000):
        self._max = max_packets
        # Arrivals not yet in the table: packet records from a live interface,
        # or ready-made row blocks from a replay. `snapshot()` converts only
        # these, so a refresh costs time for the new packets, not the buffer.
        self._pending: list[dict | pd.DataFrame] = []
        self._frame = parser.records_to_frame([])
        self._received = 0
        self._packets: deque[Packet] = deque(maxlen=max_packets)
        self._replay_path: Path | None = None
        self._lock = threading.Lock()
        self._snapshot_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sniffer: AsyncSniffer | None = None
        self._error: str | None = None
        self.description = ""

    def _on_packet(self, pkt: Packet) -> None:
        try:
            rec = parser.packet_to_record(pkt)
        except Exception:  # a malformed packet must not kill the monitor
            return
        with self._lock:
            self._pending.append(rec)
            self._packets.append(pkt)
            self._received += 1

    # --- Feeds ---------------------------------------------------------------

    def start_live(self, iface: str | None, bpf_filter: str | None = None) -> None:
        self.description = f"Live traffic on {iface or 'default interface'}"
        self._sniffer = AsyncSniffer(iface=iface, filter=bpf_filter or None,
                                     prn=self._on_packet, store=False)
        self._sniffer.start()

    def start_replay(self, path: str | Path, speed: float = 1.0,
                     frame: pd.DataFrame | None = None) -> None:
        """Feed a capture file in at `speed` times its recorded pace.

        The file is decoded once up front (pass `frame` if it is already
        parsed) and its rows are released on schedule. Decoding packets during
        the replay instead would cost as much CPU as a real capture, so a fast
        replay of a busy file would fall behind and starve the dashboard.
        """
        self._replay_path = Path(path)
        self.description = f"Replay of {self._replay_path.name} at {speed:g}x speed"

        def run() -> None:
            try:
                rows = frame if frame is not None else parser.load_pcap(path)
                offsets = (rows["time"] - rows["time"].min()).to_numpy()
                began, sent = time.monotonic(), 0
                while sent < len(rows):
                    now = (time.monotonic() - began) * speed  # capture time reached
                    due = int(np.searchsorted(offsets, now, side="right"))
                    if due > sent:
                        with self._lock:
                            self._pending.append(rows.iloc[sent:due])
                            self._received += due - sent
                        sent = due
                    if sent < len(rows):
                        wait = (offsets[sent] - now) / speed
                        # wait() returns True as soon as stop() is called
                        if self._stop.wait(min(max(wait, 0.01), 0.2)):
                            return
            except Exception as exc:
                self._error = str(exc)

        self._thread = threading.Thread(target=run, daemon=True, name="nta-replay")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._sniffer is not None and self._sniffer.running:
            try:
                self._sniffer.stop()
            except Exception as exc:
                self._error = str(exc)
        if self._thread is not None:
            self._thread.join(timeout=2)

    # --- State ---------------------------------------------------------------

    @property
    def running(self) -> bool:
        if self._sniffer is not None:
            return self._sniffer.running and self._sniffer.exception is None
        return self._thread is not None and self._thread.is_alive()

    @property
    def error(self) -> str | None:
        if self._sniffer is not None and self._sniffer.exception is not None:
            return str(self._sniffer.exception)
        return self._error

    def __len__(self) -> int:
        with self._lock:
            return min(self._received, self._max)

    def snapshot(self) -> pd.DataFrame:
        """The newest `max_packets` received so far, as a packet table ready for
        analysis. Treat the result as read-only: it is shared between calls."""
        with self._snapshot_lock:
            with self._lock:
                pending, self._pending = self._pending, []
            if pending:
                records = [p for p in pending if isinstance(p, dict)]
                parts = [p for p in pending if isinstance(p, pd.DataFrame)]
                if records:
                    parts.append(parser.records_to_frame(records))
                if not self._frame.empty:
                    parts.insert(0, self._frame)
                frame = pd.concat(parts, ignore_index=True)
                if len(frame) > self._max:
                    frame = frame.iloc[-self._max:].reset_index(drop=True)
                frame["t"] = frame["time"] - frame["time"].min()
                self._frame = frame
            return self._frame

    def pcap_bytes(self) -> bytes:
        """The packets currently in the buffer, as a pcap file."""
        with self._lock:
            received = self._received
            packets = list(self._packets)
        if self._replay_path is not None:
            # A replay keeps rows, not packets: re-read what was played out.
            with PcapReader(str(self._replay_path)) as reader:
                packets = list(islice(reader, received))[-self._max:]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "monitor.pcap"
            wrpcap(str(path), packets)
            return path.read_bytes()
