"""Network traffic analyzer dashboard.

Run with:  streamlit run streamlit_app.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Literal

import pandas as pd
import streamlit as st

from nta import analysis, capture, detectors, parser, samplegen
from nta.monitor import Monitor

SAMPLES_DIR = Path(__file__).parent / "samples"
SAMPLE_LABELS = {
    "demo": "Demo: attacks and congestion",
    "normal": "Normal office traffic",
    "advanced": "Advanced: brute force and DNS tunnelling",
}
MAX_PACKETS = 300_000
LIVE_REFRESH_S = 2
LIVE_TABLE_ROWS = 2_000
SEVERITY_COLORS: dict[str, Literal["red", "orange", "blue"]] = {
    "High": "red", "Medium": "orange", "Low": "blue",
}

st.set_page_config(page_title="Network traffic analyzer", page_icon=":material/lan:",
                   layout="wide")

if "monitor" not in st.session_state:
    st.session_state.monitor = None  # the Monitor for this browser session


def sample_path(scenario: str) -> Path:
    path = SAMPLES_DIR / f"{scenario}.pcap"
    if not path.exists():
        samplegen.generate(path, scenario)
    return path


@st.cache_data(show_spinner="Loading sample capture...")
def load_sample(scenario: str) -> pd.DataFrame:
    return parser.load_pcap(sample_path(scenario))


@st.cache_data(show_spinner="Parsing capture...", max_entries=5)
def load_upload(data: bytes) -> pd.DataFrame:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "upload.pcap"
        path.write_bytes(data)
        return parser.load_pcap(path, MAX_PACKETS)


def start_monitor(mode: str, scenario: str, speed: float, iface: str | None,
                  bpf: str) -> None:
    stop_monitor()
    mon = Monitor()
    if mode == "Replay":
        mon.start_replay(sample_path(scenario), speed, frame=load_sample(scenario))
    else:
        mon.start_live(iface, bpf)
    st.session_state.monitor = mon


def stop_monitor() -> None:
    if st.session_state.monitor is not None:
        st.session_state.monitor.stop()


def render_analysis(df: pd.DataFrame, th: detectors.Thresholds, live: bool) -> None:
    """Everything below the title: KPIs, alerts, charts and tables."""
    summary = analysis.summarize(df)
    alerts = detectors.run_all(df, th)
    n_attacks = sum(a.category == "Attack" for a in alerts)

    with st.grid(4, gap="small", min_column_width=150):
        st.metric("Packets", f"{summary.packets:,}", border=True, height="stretch")
        st.metric("Data", f"{summary.bytes / 1e6:.2f} MB", border=True, height="stretch")
        st.metric("Duration", f"{summary.duration_s:.1f} s", border=True, height="stretch")
        st.metric("Hosts", f"{summary.hosts:,}", border=True, height="stretch")
        st.metric("Average throughput", f"{summary.avg_mbps:.2f} Mbit/s", border=True,
                  height="stretch")
        st.metric("Peak throughput", f"{summary.peak_mbps:.2f} Mbit/s", border=True,
                  height="stretch",
                  help=f"Highest one-second rate; link capacity is "
                       f"{th.link_capacity_mbps:g} Mbit/s.")
        st.metric("Attacks detected", n_attacks, border=True, height="stretch")
        st.metric("Bottlenecks detected", len(alerts) - n_attacks, border=True,
                  height="stretch")

    with st.container(border=True):
        st.subheader("Alerts")
        if not alerts:
            st.success("No bottlenecks or attacks detected with the current thresholds.",
                       icon=":material/check_circle:")
        for a in alerts:
            with st.container(horizontal=True, vertical_alignment="center", gap="small"):
                st.badge(a.severity, color=SEVERITY_COLORS[a.severity])
                st.markdown(f"**{a.kind}** · {a.category} · "
                            f"`{a.source}` → `{a.target}` · "
                            f"{a.first_seen:.1f}–{a.last_seen:.1f} s")
            st.caption(a.detail)
        if alerts:
            st.download_button(
                "Download alerts (.csv)", detectors.alerts_frame(alerts).to_csv(index=False),
                file_name="alerts.csv", mime="text/csv", icon=":material/download:",
                key="alerts_csv")

    # Throughput over time, with the link limit and alert windows marked.
    tp = analysis.throughput(df)
    # Shade only short-lived events; one spanning most of the capture (ARP
    # spoofing, a dominant talker) would cover the chart and its label would
    # collide with the others.
    # Overlapping events are shaded once: alerts come most severe first, so
    # e.g. "Link saturation" wins over the "Lossy TCP flow" it caused.
    mark_areas: list[list[dict]] = []
    for a in alerts:
        if a.last_seen - a.first_seen >= 0.3 * summary.duration_s:
            continue
        if any(a.first_seen < area[1]["xAxis"] and area[0]["xAxis"] < a.last_seen
               for area in mark_areas):
            continue
        mark_areas.append([{"name": a.kind, "xAxis": round(a.first_seen, 2)},
                           {"xAxis": round(a.last_seen, 2)}])
    with st.container(border=True):
        st.subheader("Throughput over time")
        st.echarts_chart(
            {
                "tooltip": {"trigger": "axis", "valueFormatter": "%.2f"},
                "legend": {},
                "dataset": {"source": tp},
                "grid": {"left": 50, "right": 30, "top": 40, "bottom": 70},
                "xAxis": {"type": "value", "name": "Seconds", "nameLocation": "middle",
                          "nameGap": 28, "max": float(tp["second"].max())},
                "yAxis": [{"type": "value", "name": "Mbit/s"},
                          {"type": "value", "name": "Packets/s",
                           "splitLine": {"show": False}}],
                "dataZoom": [{"type": "inside"}, {"type": "slider", "height": 18}],
                "series": [
                    {
                        "name": "Mbit/s", "type": "line", "showSymbol": False,
                        "areaStyle": {"opacity": 0.15},
                        "encode": {"x": "second", "y": "mbps"},
                        "markLine": {
                            "symbol": "none", "silent": True,
                            "label": {"formatter": "Link capacity"},
                            "lineStyle": {"type": "dashed"},
                            "data": [{"yAxis": th.link_capacity_mbps}],
                        },
                        "markArea": {
                            "silent": True, "itemStyle": {"opacity": 0.12},
                            "label": {"fontSize": 10},
                            "data": mark_areas,
                        },
                    },
                    {
                        "name": "Packets/s", "type": "line", "showSymbol": False,
                        "yAxisIndex": 1, "lineStyle": {"width": 1},
                        "encode": {"x": "second", "y": "packets"},
                    },
                ],
            },
            height=340,
            key="throughput_chart",
            alt="Throughput in Mbit/s and packets per second over the capture, "
                "with the link capacity and alert periods marked",
        )

    col_proto, col_talkers = st.columns(2)

    with col_proto, st.container(border=True, height="stretch"):
        st.subheader("Traffic by service")
        services = analysis.breakdown(df, "service").head(10)
        services["mb"] = (services["bytes"] / 1e6).round(3)
        st.echarts_chart(
            {
                "tooltip": {"trigger": "item", "formatter": "{b}: {@mb} MB ({d}%)"},
                "legend": {"type": "scroll", "bottom": 0},
                "dataset": {"source": services[["service", "mb", "packets"]]},
                "series": [{
                    "type": "pie", "radius": ["40%", "68%"], "center": ["50%", "45%"],
                    "encode": {"itemName": "service", "value": "mb"},
                    "label": {"formatter": "{b}"},
                }],
            },
            height=320,
            key="service_chart",
            alt="Share of bytes by application protocol",
        )

    with col_talkers, st.container(border=True, height="stretch"):
        st.subheader("Top talkers")
        talkers = analysis.top_talkers(df, n=10)
        talkers["sent_mb"] = (talkers["bytes_sent"] / 1e6).round(3)
        talkers["received_mb"] = (talkers["bytes_received"] / 1e6).round(3)
        st.echarts_chart(
            {
                "tooltip": {"trigger": "axis", "valueFormatter": "%.3f MB"},
                "legend": {},
                "grid": {"left": 120, "right": 20, "top": 30, "bottom": 30},
                "dataset": {"source": talkers[["host", "sent_mb",
                                                "received_mb"]].iloc[::-1]},
                "xAxis": {"type": "value", "name": "MB"},
                "yAxis": {"type": "category"},
                "series": [
                    {"name": "Sent", "type": "bar", "stack": "total",
                     "encode": {"y": "host", "x": "sent_mb"}},
                    {"name": "Received", "type": "bar", "stack": "total",
                     "encode": {"y": "host", "x": "received_mb"}},
                ],
            },
            height=320,
            key="talkers_chart",
            alt="Hosts ranked by megabytes sent, with megabytes received",
        )

    with st.container(border=True):
        st.subheader("Top conversations")
        st.dataframe(
            analysis.conversations(df, n=15), hide_index=True,
            column_config={
                "host_a": "Host A", "host_b": "Host B",
                "packets": st.column_config.NumberColumn("Packets", format="localized"),
                "bytes": st.column_config.NumberColumn("Data", format="bytes"),
                "first_seen": st.column_config.NumberColumn("First seen", format="%.1f s"),
                "last_seen": st.column_config.NumberColumn("Last seen", format="%.1f s"),
                "mbps": st.column_config.NumberColumn("Avg rate", format="%.2f Mbit/s"),
            },
            alt="Host pairs ranked by total bytes exchanged",
        )

    with st.container(border=True):
        st.subheader("Packet explorer")
        with st.container(horizontal=True, vertical_alignment="bottom"):
            protocols = sorted(df["proto"].dropna().unique())
            chosen = st.pills("Protocol", protocols, selection_mode="multi",
                              default=protocols)
            host = st.text_input("Host contains", placeholder="IP or MAC address",
                                 key="host_filter")
        view = df[df["proto"].isin(chosen)]
        if host:
            view = view[
                view["src"].str.contains(host, regex=False, na=False)
                | view["dst"].str.contains(host, regex=False, na=False)
                | view["src_mac"].str.contains(host, regex=False, na=False)
            ]
        if live and len(view) > LIVE_TABLE_ROWS:
            st.caption(f"Newest {LIVE_TABLE_ROWS:,} of {len(view):,} matching packets "
                       f"({len(df):,} captured)")
            view = view.tail(LIVE_TABLE_ROWS).iloc[::-1]
        else:
            st.caption(f"{len(view):,} of {len(df):,} packets")
        st.dataframe(
            view,
            hide_index=True,
            column_order=["t", "src", "sport", "dst", "dport", "proto", "service",
                          "length", "tcp_flags", "icmp_type", "arp_op", "dns_query"],
            column_config={
                "t": st.column_config.NumberColumn("Time", format="%.4f s"),
                "src": "Source", "sport": "Src port", "dst": "Destination",
                "dport": "Dst port", "proto": "Protocol", "service": "Service",
                "length": st.column_config.NumberColumn("Bytes"),
                "tcp_flags": "TCP flags", "icmp_type": "ICMP type", "arp_op": "ARP op",
                "dns_query": "DNS query",
            },
            alt="Individual packets in the capture",
        )


# --- Sidebar: where the packets come from, and detection thresholds ----------

df: pd.DataFrame | None = None
source_label = ""
monitor: Monitor | None = None

with st.sidebar:
    st.header("Traffic source")
    source = st.segmented_control(
        "Traffic source", ["Sample", "Upload", "Live"], default="Sample",
        required=True, label_visibility="collapsed", width="stretch",
    )

    if source == "Sample":
        scenario = st.selectbox("Sample capture", list(SAMPLE_LABELS),
                                format_func=lambda s: SAMPLE_LABELS[s])
        df = load_sample(scenario)
        source_label = f"Sample capture · {SAMPLE_LABELS[scenario]}"
        st.caption("Synthetic one-minute captures of a small office LAN. "
                   "Regenerate with `python cli.py generate`.")

    elif source == "Upload":
        upload = st.file_uploader("Capture file", type=["pcap", "pcapng", "cap"],
                                  help="Save one from Wireshark or tcpdump.")
        if upload is not None:
            df = load_upload(upload.getvalue())
            source_label = f"Uploaded file: {upload.name}"
            if len(df) >= MAX_PACKETS:
                st.warning(f"Only the first {MAX_PACKETS:,} packets were analyzed.")

    else:
        monitor = st.session_state.monitor
        running = monitor is not None and monitor.running
        mode = st.segmented_control(
            "Feed", ["Replay", "Interface"], default="Replay", required=True,
            width="stretch", disabled=running,
            help="Replay streams a sample capture at its recorded pace, so the "
                 "monitor can be tried without capture rights.",
        )
        scenario, speed, iface, bpf, can_start = "demo", 1.0, None, "", True
        if mode == "Replay":
            scenario = st.selectbox("Capture to replay", list(SAMPLE_LABELS),
                                    format_func=lambda s: SAMPLE_LABELS[s],
                                    disabled=running)
            speed = st.segmented_control("Speed", [1, 2, 5, 10], default=1,
                                         required=True, format_func=lambda s: f"{s}x",
                                         width="stretch", disabled=running)
        else:
            ok, message = capture.capture_status()
            can_start = ok
            if not ok:
                st.warning(message, title="Live capture unavailable")
            else:
                st.caption(message)
                ifaces = capture.list_interfaces()
                names = [i.name for i in ifaces]
                labels = {i.name: f"{i.description} ({i.ip or 'no IP'})" for i in ifaces}
                default = capture.default_interface()
                iface = st.selectbox(
                    "Interface", names, format_func=lambda n: labels[n],
                    index=names.index(default) if default in names else 0,
                    disabled=running)
                bpf = st.text_input("Capture filter (BPF)", placeholder="e.g. tcp port 443",
                                    disabled=running)

        with st.container(horizontal=True):
            st.button("Start", icon=":material/play_arrow:", type="primary",
                      width="stretch", disabled=running or not can_start,
                      on_click=start_monitor, args=(mode, scenario, speed, iface, bpf))
            st.button("Stop", icon=":material/stop:", width="stretch",
                      disabled=not running, on_click=stop_monitor)

        if monitor is not None:
            if monitor.error:
                st.error(monitor.error, title="Monitor stopped")
            source_label = monitor.description + (" (running)" if running else " (stopped)")
            if not running and len(monitor):
                st.download_button("Download packets (.pcap)", monitor.pcap_bytes(),
                                   file_name="monitor.pcap", icon=":material/download:",
                                   width="stretch")

    st.header("Detection thresholds")
    capacity = st.number_input("Link capacity (Mbit/s)", min_value=0.1, value=10.0,
                               step=1.0, help="Bandwidth of the link being monitored.")
    with st.expander("Advanced thresholds"):
        defaults = detectors.Thresholds()
        th = detectors.Thresholds(
            link_capacity_mbps=capacity,
            utilization_pct=st.slider("Saturation at % of capacity", 50, 100,
                                      int(defaults.utilization_pct)),
            top_talker_share_pct=st.slider("Dominant talker share (%)", 20, 100,
                                           int(defaults.top_talker_share_pct)),
            retransmission_pct=st.number_input("Retransmission rate (%)", 0.5, 50.0,
                                               defaults.retransmission_pct, step=0.5),
            scan_distinct_ports=st.number_input("Port scan: distinct ports", 5, 5000,
                                                defaults.scan_distinct_ports),
            syn_flood_rate=st.number_input("SYN flood: SYNs per second", 10, 100_000,
                                           defaults.syn_flood_rate),
            icmp_flood_rate=st.number_input("ICMP flood: pings per second", 5, 100_000,
                                            defaults.icmp_flood_rate),
            brute_force_attempts=st.number_input("Brute force: login attempts", 3, 100_000,
                                                 defaults.brute_force_attempts),
            dns_tunnel_names=st.number_input("DNS tunnel: unique names", 5, 100_000,
                                             defaults.dns_tunnel_names),
            dns_tunnel_length=st.number_input("DNS tunnel: average name length", 10, 253,
                                              defaults.dns_tunnel_length),
        )


# --- Main page -----------------------------------------------------------------

st.title("Network traffic analyzer")

if monitor is not None:
    @st.fragment(run_every=LIVE_REFRESH_S if monitor.running else None)
    def live_view(mon: Monitor) -> None:
        if not mon.running and st.session_state.get("was_running"):
            # The feed just ended: rerun the whole app so the sidebar updates.
            st.session_state.was_running = False
            st.rerun()
        st.session_state.was_running = mon.running
        st.caption(source_label if not mon.running
                   else f"{mon.description} · updating every {LIVE_REFRESH_S}s")
        live_df = mon.snapshot()
        if live_df.empty:
            st.info("Waiting for packets...", icon=":material/hourglass_top:")
            return
        render_analysis(live_df, th, live=True)

    live_view(monitor)
    st.stop()

if df is None:
    st.caption("Monitor traffic, find bottlenecks and spot attacks.")
    st.info("Pick a **Sample**, **Upload** a .pcap/.pcapng file, or start the "
            "**Live** monitor from the sidebar.", icon=":material/info:")
    st.stop()
if df.empty:
    st.warning("The capture contains no packets.")
    st.stop()

st.caption(source_label)
render_analysis(df, th, live=False)
