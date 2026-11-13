# Network traffic analyzer

Computer Networks course project. Monitors and analyzes network traffic to find
**bottlenecks** (link saturation, hosts hogging bandwidth, TCP retransmissions)
and **attacks** (port scans, SYN floods, ICMP floods, ARP spoofing, brute-force
logins, DNS tunnelling). Works on live traffic or on `.pcap`/`.pcapng` files
saved by Wireshark or tcpdump. Comes with a web dashboard and a CLI.

**Quick start on Windows:** double-click `run_dashboard.bat`. The first run
creates a Python environment and installs the packages (Python 3.10+ needed);
the dashboard then opens in your browser with a demo capture loaded.

| Folder / file | Contents |
| --- | --- |
| `docs/Student_Project_Report.pdf` | Project report in the college format (24 pages) |
| `docs/Project_Report.pdf` | Technical report (20 pages) |
| `docs/screenshots/` | Screenshots of the running dashboard |
| `nta/` | Core package: parser, statistics, detectors, monitor, capture, sample generator |
| `streamlit_app.py`, `cli.py` | Dashboard and command-line tool |
| `samples/` | Test captures: `normal.pcap`, `demo.pcap`, `advanced.pcap` |
| `evaluate.py` | Accuracy, precision, recall, F1 and detection time against ground truth |
| `tests/` | Automated tests (`python -m pytest`) |

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\activate            # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

**Live capture only:** on Windows, install [Npcap](https://npcap.com) (tick
"WinPcap API-compatible mode") and run the terminal as Administrator. On
Linux/macOS, run with `sudo`. Analyzing files and samples needs neither.

## Usage

```powershell
streamlit run streamlit_app.py              # dashboard at http://localhost:8501 (or double-click run_dashboard.bat)

python cli.py generate                      # create the sample captures in samples/
python cli.py analyze samples/demo.pcap     # text report
python cli.py analyze my.pcap --json report.json  # also save summary + alerts as JSON
python cli.py analyze my.pcap --capacity 100
python cli.py interfaces                    # list capture interfaces
python cli.py capture -d 30 -f "tcp or udp" -o mine.pcap   # capture live, save, analyze
python cli.py monitor                       # real-time: print alerts the moment they appear
python cli.py monitor --replay samples/demo.pcap --speed 5  # same, fed from a file

python evaluate.py                          # accuracy / precision / recall / F1 / detection time
python -m pytest                            # run the tests
```

In the dashboard, the **Live** source is a real-time monitor that refreshes every
2 seconds. Its **Replay** feed streams a saved capture at its recorded pace (1–10x),
so the monitor can be demonstrated without capture rights; **Interface** watches
a real network card.
```

## How it works

```
 live capture (Scapy sniff) ─┐
                             ├─> parser ──> packet table ──┬─> analysis  (statistics)
 .pcap / .pcapng file ───────┘   (one row      (pandas)    └─> detectors (alerts)
                                  per packet)                     │
                                                    dashboard / CLI report
```

For real-time monitoring, `nta/monitor.py` collects packets on a background
thread (from an interface or a replayed file) into a bounded buffer, and the
dashboard/CLI re-run the analysis on that buffer every few seconds.

| Module | Role |
| --- | --- |
| `nta/parser.py` | Decodes each packet (Ethernet, ARP, IPv4/IPv6, TCP, UDP, ICMP, DNS) into a table row: time, addresses, ports, TCP flags/sequence numbers, length, service. |
| `nta/analysis.py` | Throughput per second, protocol/service breakdown, top talkers, top conversations, TCP retransmissions. |
| `nta/detectors.py` | Rule-based detectors with adjustable thresholds (`Thresholds`). |
| `nta/capture.py` | Live capture and interface listing; reports why capture is unavailable. |
| `nta/monitor.py` | Continuous monitoring: background sniffer or paced replay, rolling packet buffer. |
| `nta/samplegen.py` | Builds realistic synthetic captures for demos and tests. |
| `streamlit_app.py` | Dashboard: KPIs, alerts, throughput timeline, service mix, top talkers, conversations, packet explorer. |
| `cli.py` | Same analysis from the terminal. |

### Detection rules

| Alert | Rule (default threshold) | Why it works |
| --- | --- | --- |
| Link saturation | Any second above 80% of link capacity (10 Mbit/s) | Queues fill and latency rises before a link hits 100%. Reports the flow responsible. |
| Dominant talker | One host sends ≥ 50% of all bytes (once ≥ 1 MB is captured) | A single host can starve the others on a shared link. |
| High retransmission rate / lossy flow | ≥ 3% of TCP data segments resent (same flow and sequence number seen twice) | TCP resends after loss; loss on a busy path means congestion. |
| Port scan | One source sends SYNs to ≥ 20 distinct ports on one host | Normal clients connect to one or two service ports; scanners probe many. Open ports are the ones that answered SYN-ACK. |
| SYN flood | ≥ 100 SYNs per second to one host:port | Half-open connections fill the server's backlog; many distinct sources indicates spoofing. |
| ICMP flood | ≥ 50 echo requests per second to one host | Ping floods consume bandwidth and CPU. |
| ARP spoofing | The same IP announced by two or more MAC addresses in ARP replies | The basis of LAN man-in-the-middle attacks (e.g. claiming to be the gateway). |
| Brute-force login | One source opens ≥ 20 connections to one login service (SSH, RDP, FTP, Telnet, POP3, IMAP, MySQL, VNC) | A person logs in once; a password-guessing tool reconnects every few guesses. |
| DNS tunnelling | One host queries ≥ 30 unique names under one domain, averaging ≥ 40 characters | Normal lookups reuse a few short, cached names; tunnels encode data in long one-off names. |

All thresholds can be changed in the dashboard sidebar. The dashboard can download
the alerts as CSV, and `cli.py analyze --json` saves them for other tools.

### Sample captures

`python cli.py generate` (or the dashboard's **Sample** source) builds three
one-minute captures of a small office LAN (`192.168.1.0/24`, gateway `.1`, web
server `.20`, clients `.10–.14`):

* **normal**: DNS lookups, HTTPS browsing, routine ARP. Expected result: no alerts.
* **demo**: the same baseline plus a SYN scan of ports 1–500 from `.66` (t ≈ 10 s),
  ARP spoofing of the gateway by `.66` (from t ≈ 18 s), an 11 Mbit/s download to
  `.12` that saturates the 10 Mbit/s link with 6% loss (t ≈ 26 s), a spoofed SYN
  flood on `.20:80` (t ≈ 40 s) and a ping flood from `.77` (t ≈ 50 s).
* **advanced**: the baseline plus SSH password guessing on `.20:22` from
  `203.0.113.50` (120 attempts in 30 s) and DNS tunnelling from `.77`
  (200 long encoded names under `tunnel.example`).

The tests check that the normal capture raises nothing and that every injected
event in the demo and advanced captures is detected with the right hosts.

## Limitations

* Rule-based thresholds: floods below the per-second rates aren't flagged, and
  busy networks may need higher thresholds. Port scans are counted over the whole
  capture, so slow scans are caught in files; the live monitor only sees scans
  within its rolling buffer (newest 200,000 packets).
* Encrypted payloads aren't inspected; services are inferred from port numbers.
* Large captures are parsed in Python (roughly 3–4k packets/s); the dashboard
  analyzes up to 300,000 packets per upload.
