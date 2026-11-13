"""Build docs/Student_Project_Report.pdf from report.html.

Run from the project root:  python docs/report_src/build_report.py
Needs (dev only, not in requirements.txt):  pip install playwright pymupdf
                                            python -m playwright install chromium

Steps: draw the figures (the bandwidth chart from samples/demo.pcap), print the
HTML to PDF with headless Chromium, find each chapter's page, print again with
those page numbers in the contents, and put an unnumbered cover page in front.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pymupdf
from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
from nta import analysis, parser  # noqa: E402

OUT = ROOT / "docs" / "Student_Project_Report.pdf"

STUDENT = {
    "name": "Abdul Hakeem K",
    "roll": "1CR24AI003",
    "class": "5A",
    "dept": "Department of AIML",
    "college": "CMR Institute of Technology",
    "course": "Computer Networks",
    "date": "November 2026",
}

CHAPTERS = [
    ("1.", "Introduction"), ("2.", "Literature Review"),
    ("3.", "Problem Definition and Objectives"), ("4.", "Existing and Proposed Systems"),
    ("5.", "System Architecture and Design"), ("6.", "Methodology and Algorithms"),
    ("7.", "Implementation"), ("8.", "Results and Discussion"),
    ("9.", "Performance Evaluation"), ("10.", "Conclusion and Future Scope"),
    ("", "References"), ("", "Appendices"),
]

# From `python evaluate.py` (seconds of attack traffic before the alert, 0.25 s steps).
DELAYS = [("Port scan", 0.25), ("ARP spoofing", 0.25), ("SYN flood", 0.25),
          ("ICMP flood", 0.5), ("Link saturation", 1.0),
          ("Brute-force login", 4.75), ("DNS tunnelling", 6.0)]
# Attack windows in demo.pcap (seconds since capture start), shaded on the chart.
ATTACK_WINDOWS = [("Port scan", 9.8, 12.3), ("SYN flood", 39.8, 43.8), ("ICMP flood", 49.8, 51.8)]

FONT = "font-family='Arial, Helvetica, sans-serif'"
INK, QUIET, EDGE, ACCENT, GREY = "#000", "#444", "#333", "#1f4e9a", "#a6a6a6"


def arch_svg() -> str:
    def box(x, y, w, h, title, lines, hi=False):
        fill = "#e8eef8" if hi else "none"
        stroke, sw = (ACCENT, 2) if hi else (EDGE, 1.2)
        out = [f"<rect x='{x}' y='{y}' width='{w}' height='{h}' rx='6' fill='{fill}' "
               f"stroke='{stroke}' stroke-width='{sw}'/>",
               f"<text x='{x + 12}' y='{y + 24}' font-size='13' font-weight='bold' fill='{INK}'>{title}</text>"]
        for i, line in enumerate(lines):
            out.append(f"<text x='{x + 12}' y='{y + 44 + 16 * i}' font-size='11.5' fill='{QUIET}'>{line}</text>")
        return "".join(out)

    arrows = ["M128 128V176", "M504 92H472", "M318 128V212H232", "M418 128V296", "M128 248V296",
              "M188 352V400", "M548 352V400", "M188 472V520", "M548 472V520"]
    paths = "".join(f"<path d='{d}' marker-end='url(#a)'/>" for d in arrows)
    labels = [(326, 172, "replay"), (426, 172, "read whole file"), (136, 276, "packets"),
              (196, 500, "statistics"), (556, 500, "alerts")]
    label_svg = "".join(f"<text x='{x}' y='{y}' font-size='11' fill='{QUIET}'>{t}</text>" for x, y, t in labels)
    return (
        f"<svg viewBox='0 0 736 640' xmlns='http://www.w3.org/2000/svg' {FONT}>"
        f"<defs><marker id='a' viewBox='0 0 10 10' refX='9' refY='5' markerWidth='7' markerHeight='7' "
        f"orient='auto-start-reverse'><path d='M0 0L10 5L0 10z' fill='{EDGE}'/></marker></defs>"
        f"<g fill='none' stroke='{EDGE}' stroke-width='1.2'>{paths}</g>{label_svg}"
        + box(24, 56, 208, 72, "Network interface", ["Live capture via Npcap", "or libpcap (needs admin)"])
        + box(264, 56, 208, 72, "Capture file", [".pcap or .pcapng from", "Wireshark or tcpdump"])
        + box(504, 56, 208, 72, "Sample generator", ["Test captures with known", "attacks (ground truth)"])
        + box(24, 176, 208, 72, "Real-time monitor", ["Background thread,", "rolling packet buffer"])
        + box(24, 296, 688, 56, "Packet parser and feature extraction",
              ["Decodes Ethernet, ARP, IP, TCP, UDP, ICMP and DNS into one table, one row per packet"])
        + box(24, 400, 328, 72, "Traffic analysis",
              ["Throughput per second, protocol and service mix,", "top talkers, conversations, retransmissions"])
        + box(384, 400, 328, 72, "Attack and bottleneck detection",
              ["3 bottleneck rules and 6 attack rules;", "each alert carries its evidence"], hi=True)
        + f"<rect x='24' y='520' width='688' height='104' rx='6' fill='#f2f2f2' stroke='{EDGE}' stroke-width='1.2'/>"
        f"<text x='36' y='542' font-size='13' font-weight='bold' fill='{INK}'>Visualisation and report generation</text>"
        + box(40, 552, 312, 56, "Dashboard (Streamlit)", ["KPIs, alerts, charts; live view every 2 s"])
        + box(384, 552, 312, 56, "Command-line tool", ["Text, CSV and JSON reports; live alerts"])
        + "</svg>"
    )


def bandwidth_svg() -> str:
    tp = analysis.throughput(parser.load_pcap(ROOT / "samples" / "demo.pcap"))
    left, right, top_y, base, ymax = 52, 740, 34, 280, 16.0
    n = len(tp)
    band = (right - left) / n
    X = lambda s: left + s * band  # noqa: E731
    Y = lambda v: base - v / ymax * (base - top_y)  # noqa: E731
    out = [f"<svg viewBox='0 0 760 330' xmlns='http://www.w3.org/2000/svg' {FONT}>"]
    for name, a, b in ATTACK_WINDOWS:
        out.append(f"<rect x='{X(a):.1f}' y='{top_y}' width='{X(b) - X(a):.1f}' height='{base - top_y}' fill='#ececec'/>"
                   f"<text x='{X(a):.1f}' y='{top_y - 6}' font-size='11' fill='{QUIET}'>{name}</text>")
    for v in range(0, 17, 4):
        out.append(f"<line x1='{left}' x2='{right}' y1='{Y(v):.1f}' y2='{Y(v):.1f}' stroke='#d9d9d9'/>"
                   f"<text x='{left - 8}' y='{Y(v) + 4:.1f}' font-size='11' text-anchor='end' fill='{QUIET}'>{v}</text>")
    for r in tp.itertuples():
        colour = ACCENT if r.mbps >= 8 else GREY
        out.append(f"<rect x='{X(r.second) + band * 0.15:.1f}' y='{Y(r.mbps):.1f}' width='{band * 0.7:.1f}' "
                   f"height='{base - Y(r.mbps):.1f}' fill='{colour}'/>")
    peak = tp.loc[tp["mbps"].idxmax()]
    out.append(f"<text x='{X(peak.second) + band / 2:.1f}' y='{Y(peak.mbps) - 6:.1f}' font-size='11' "
               f"font-weight='bold' text-anchor='middle' fill='{INK}'>{peak.mbps:.1f}</text>")
    out.append(f"<line x1='{left}' x2='{right}' y1='{Y(10):.1f}' y2='{Y(10):.1f}' stroke='{INK}' stroke-width='1.2' stroke-dasharray='6 4'/>"
               f"<text x='{right}' y='{Y(10) - 6:.1f}' font-size='11' text-anchor='end' fill='{INK}'>Link capacity 10 Mbit/s</text>"
               f"<line x1='{left}' x2='{right}' y1='{Y(8):.1f}' y2='{Y(8):.1f}' stroke='{QUIET}' stroke-dasharray='2 3'/>"
               f"<text x='{right}' y='{Y(8) + 14:.1f}' font-size='11' text-anchor='end' fill='{QUIET}'>Saturation threshold 8 Mbit/s (80%)</text>")
    out.append(f"<line x1='{left}' x2='{right}' y1='{base}' y2='{base}' stroke='{EDGE}'/>")
    for s in range(0, n, 10):
        out.append(f"<text x='{X(s) + band / 2:.1f}' y='{base + 16}' font-size='11' text-anchor='middle' fill='{QUIET}'>{s}</text>")
    out.append(f"<text x='{(left + right) / 2}' y='{base + 36}' font-size='11.5' text-anchor='middle' fill='{INK}'>Seconds since capture start</text>"
               f"<text x='14' y='{top_y - 6}' font-size='11.5' fill='{INK}'>Mbit/s</text></svg>")
    return "".join(out)


def delay_svg() -> str:
    left, right, top_y, row = 150, 700, 30, 32
    xmax = 7.0
    X = lambda v: left + v / xmax * (right - left)  # noqa: E731
    base = top_y + row * len(DELAYS) + 4
    out = [f"<svg viewBox='0 0 760 {base + 50}' xmlns='http://www.w3.org/2000/svg' {FONT}>"]
    for t in range(8):
        out.append(f"<line x1='{X(t):.1f}' x2='{X(t):.1f}' y1='{top_y - 6}' y2='{base}' stroke='#d9d9d9'/>"
                   f"<text x='{X(t):.1f}' y='{base + 16}' font-size='11' text-anchor='middle' fill='{QUIET}'>{t}</text>")
    for i, (name, d) in enumerate(DELAYS):
        y = top_y + i * row
        colour = ACCENT if d > 2 else GREY
        out.append(f"<text x='{left - 10}' y='{y + 15}' font-size='12' text-anchor='end' fill='{INK}'>{name}</text>"
                   f"<rect x='{left}' y='{y + 3}' width='{X(d) - left:.1f}' height='17' fill='{colour}'/>"
                   f"<text x='{X(d) + 6:.1f}' y='{y + 16}' font-size='11' fill='{QUIET}'>{d:.2f} s</text>")
    mean = sum(d for _, d in DELAYS) / len(DELAYS)
    out.append(f"<line x1='{X(mean):.1f}' x2='{X(mean):.1f}' y1='{top_y - 6}' y2='{base}' stroke='{INK}' stroke-dasharray='4 4'/>"
               f"<text x='{X(mean) + 6:.1f}' y='{top_y - 10}' font-size='11' fill='{INK}'>Mean {mean:.2f} s</text>"
               f"<text x='{(left + right) / 2}' y='{base + 36}' font-size='11.5' text-anchor='middle' fill='{INK}'>Detection delay (seconds)</text></svg>")
    return "".join(out)


def toc_html(pages: dict[str, int] | None) -> str:
    rows = []
    for num, title in CHAPTERS:
        page = pages.get(title, "") if pages else "00"
        rows.append(f"<li><span class='n'>{num}</span><span class='t'>{title}</span><span class='p'>{page}</span></li>")
    return "<ul class='toc'>" + "".join(rows) + "</ul>"


def cover_html() -> str:
    s = STUDENT
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><style>
      @page {{ size: A4; margin: 30mm 25mm; }}
      body {{ font-family: "Times New Roman", Times, serif; text-align: center; color: #000; }}
      .top {{ margin-top: 30mm; font-size: 14pt; }} .title {{ font-size: 26pt; font-weight: bold; margin: 8mm 0 4mm; }}
      .sub {{ font-size: 13pt; font-style: italic; }} .block {{ margin-top: 28mm; font-size: 13pt; line-height: 1.7; }}
      .rule {{ width: 60%; margin: 10mm auto; border-top: 1pt solid #000; }} .bottom {{ margin-top: 30mm; font-size: 13pt; line-height: 1.7; }}
    </style></head><body>
      <div class="top">A Project Report on</div>
      <div class="title">NETWORK TRAFFIC ANALYSIS</div>
      <div class="sub">Detecting network bottlenecks and attacks from live traffic and packet captures</div>
      <div class="rule"></div>
      <div class="block">Course: <b>{s['course']}</b><br><br>Submitted by<br><b>{s['name']}</b><br>
        Roll No.: {s['roll']} &nbsp;&middot;&nbsp; Class: {s['class']}</div>
      <div class="bottom">{s['dept']}<br><b>{s['college']}</b><br>{s['date']}</div>
    </body></html>"""


FOOTER = ("<div style='width:100%;font-family:\"Times New Roman\",serif;font-size:10pt;text-align:center;"
          "color:#000;'><span class='pageNumber'></span></div>")


def render(page, html: str, path: Path, numbered: bool) -> None:
    src = HERE / "_render.html"  # beside report.html so relative image paths resolve
    src.write_text(html, encoding="utf-8")
    page.goto(src.as_uri())
    page.wait_for_load_state("networkidle")
    page.pdf(path=str(path), format="A4", print_background=True, prefer_css_page_size=True,
             display_header_footer=numbered, header_template="<div></div>",
             footer_template=FOOTER if numbered else "<div></div>")
    src.unlink()


def chapter_pages(pdf: Path) -> dict[str, int]:
    with pymupdf.open(pdf) as doc:
        texts = [p.get_text() for p in doc]
    toc_index = next(i for i, t in enumerate(texts) if "Chapter Contents" in t)
    pages = {}
    for num, title in CHAPTERS:
        heading = f"{num} {title}".strip()
        for i in range(toc_index + 1, len(texts)):
            first_line = texts[i].strip().splitlines()[0] if texts[i].strip() else ""
            if first_line.startswith(heading):
                pages[title] = i + 1
                break
    return pages


def main() -> None:
    template = (HERE / "report.html").read_text(encoding="utf-8")
    body = (template.replace("{{ARCH_SVG}}", arch_svg())
                    .replace("{{BANDWIDTH_SVG}}", bandwidth_svg())
                    .replace("{{DELAY_SVG}}", delay_svg()))
    with tempfile.TemporaryDirectory() as tmp, sync_playwright() as p:
        tmp = Path(tmp)
        browser = p.chromium.launch()
        page = browser.new_page()
        render(page, body.replace("{{TOC}}", toc_html(None)), tmp / "pass1.pdf", True)
        pages = chapter_pages(tmp / "pass1.pdf")
        missing = [t for _, t in CHAPTERS if t not in pages]
        if missing:
            raise SystemExit(f"Could not locate chapters: {missing}")
        render(page, body.replace("{{TOC}}", toc_html(pages)), tmp / "body.pdf", True)
        render(page, cover_html(), tmp / "cover.pdf", False)
        browser.close()

        with pymupdf.open(tmp / "cover.pdf") as out, pymupdf.open(tmp / "body.pdf") as body_pdf:
            out.insert_pdf(body_pdf)
            out.set_metadata({"title": "Network Traffic Analysis - Project Report",
                              "author": STUDENT["name"], "subject": "Computer Networks course project"})
            out.save(OUT)
            total = out.page_count
    print(f"Wrote {OUT} ({total} pages); chapters start on body pages {pages}")


if __name__ == "__main__":
    main()
