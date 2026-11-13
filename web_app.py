"""Simple browser dashboard for network security assessments and attack graph generation."""

from datetime import datetime
import json
import os
from pathlib import Path
import time

import pandas as pd
import streamlit as st

from core.engine import ScanEngine, get_local_ip_hint
from utils.web_results import render_scan_result


REPORT_PATH = Path(__file__).parent / "reports" / "scan_results.json"
BACKUP_DIR  = Path(__file__).parent / "reports" / "backups"


# -------------------------------------------------------------------------
# Helper Functions
# -------------------------------------------------------------------------

def infer_network_from_data(report_dict: dict) -> str:
    """Infer CIDR network from stored report or discovered host IPs."""
    # 1. Direct field in report
    direct = report_dict.get("report", {}).get("target_network")
    if direct:
        return direct

    # 2. Infer from host list
    hosts = report_dict.get("hosts", [])
    for h in hosts:
        ip = h.get("ip") or h.get("host")
        if ip and "." in ip:
            parts = ip.split(".")
            if len(parts) == 4 and parts[0] != "127":
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    return ""


def get_all_history_options() -> list[dict]:
    """Retrieve all available assessment history records with accurate network labels."""
    options: list[dict] = []

    # 1. Latest completed assessment
    if REPORT_PATH.exists():
        try:
            with REPORT_PATH.open(encoding="utf-8") as f:
                d = json.load(f)
            r = d.get("report", {})
            s = d.get("summary", {})
            scan_id = r.get("scan_id", "Latest")
            gen_at  = r.get("generated_at", "Latest")
            target  = infer_network_from_data(d) or "Local Network"
            h_cnt   = s.get("total_hosts", len(d.get("hosts", [])))
            p_cnt   = s.get("total_open_ports", sum(len(h.get("open_ports", [])) for h in d.get("hosts", [])))
            f_cnt   = s.get("total_findings", sum(len(h.get("findings", [])) for h in d.get("hosts", [])))
            options.append({
                "id": "latest",
                "file_path": REPORT_PATH,
                "scan_id": scan_id,
                "generated_at": gen_at,
                "target_network": target,
                "hosts_count": h_cnt,
                "ports_count": p_cnt,
                "findings_count": f_cnt,
                "label": f"📌 Latest [{target}] — {gen_at} ({h_cnt} hosts)",
            })
        except Exception:
            pass

    # 2. Historical backups in reports/backups/
    if BACKUP_DIR.exists():
        for bf in sorted(BACKUP_DIR.glob("scan_*.json"),
                         key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                with bf.open(encoding="utf-8") as f:
                    d = json.load(f)
                r   = d.get("report", {})
                s   = d.get("summary", {})
                sid = r.get("scan_id", bf.stem.replace("scan_", ""))
                gat = r.get("generated_at", sid)
                tgt = infer_network_from_data(d) or "LAN"
                hc  = s.get("total_hosts", len(d.get("hosts", [])))
                pc  = s.get("total_open_ports", sum(len(h.get("open_ports", [])) for h in d.get("hosts", [])))
                fc  = s.get("total_findings",   sum(len(h.get("findings",   [])) for h in d.get("hosts", [])))
                options.append({
                    "id": bf.name,
                    "file_path": bf,
                    "scan_id": sid,
                    "generated_at": gat,
                    "target_network": tgt,
                    "hosts_count": hc,
                    "ports_count": pc,
                    "findings_count": fc,
                    "label": f"🕒 {gat} [{tgt}] — {hc} hosts, {pc} ports",
                })
            except Exception:
                continue

    return options


def load_assessment_from_file(file_path: Path) -> dict | None:
    """Load and adapt any JSON report file for the browser dashboard."""
    try:
        with file_path.open(encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None

    report   = data.get("report", {})
    hosts: list[dict]    = []
    services: list[dict] = []
    findings: list[dict] = []

    for asset in data.get("hosts", []):
        host = {
            "host": asset.get("ip", "Unknown"),
            "operating_system": asset.get("os", "Unknown"),
            "open_ports": asset.get("open_ports", []),
            "services":   [],
            "findings":   [],
            "risk":       asset.get("risk", "UNKNOWN"),
            "risk_score": asset.get("risk_score", 0),
        }
        for svc in asset.get("services", []):
            item = {"host": host["host"], **svc}
            host["services"].append(item)
            services.append(item)
        for fnd in asset.get("findings", []):
            item = {"host": host["host"], **fnd}
            host["findings"].append(item)
            findings.append(item)
        hosts.append(host)

    scan_id        = report.get("scan_id") or file_path.stem.replace("scan_", "")
    gen_at         = report.get("generated_at") or scan_id
    target_network = infer_network_from_data(data)

    return {
        "target":         target_network or f"Assessment {scan_id}",
        "target_network": target_network,
        "scanned_at":     gen_at,
        "scan_id":        scan_id,
        "hosts":          hosts,
        "services":       services,
        "findings":       findings,
    }


# -------------------------------------------------------------------------
# Page Setup
# -------------------------------------------------------------------------

st.set_page_config(
    page_title="Attack Graph Generator",
    page_icon=":material/security:",
    layout="wide",
)

# -------------------------------------------------------------------------
# SIDEBAR — History Selector
# -------------------------------------------------------------------------

history_options = get_all_history_options()
selected_assessment_file = REPORT_PATH   # default

with st.sidebar:
    st.header("📜 Scan History")
    st.caption(f"{len(history_options)} saved assessments")

    if history_options:
        selected_option = st.selectbox(
            "Select assessment:",
            options=history_options,
            format_func=lambda o: o["label"],
            index=0,
            key="history_selector",
        )
        if selected_option:
            selected_assessment_file = selected_option["file_path"]

        sel = selected_option or history_options[0]
        st.markdown("---")
        st.markdown("**Selected scan details**")
        st.markdown(f"🎯 Network: `{sel.get('target_network', 'Unknown')}`")
        st.markdown(f"🆔 Scan ID: `{sel.get('scan_id')}`")
        st.markdown(f"🕐 Time: `{sel.get('generated_at')}`")
        col_a, col_b = st.columns(2)
        col_a.metric("Hosts",    sel.get("hosts_count", 0))
        col_b.metric("Ports",    sel.get("ports_count", 0))
        col_a.metric("Findings", sel.get("findings_count", 0))

        st.markdown("---")
        with st.expander("📋 All scans table", expanded=False):
            rows = [
                {
                    "Target":     o.get("target_network", "—"),
                    "Scan ID":    o.get("scan_id"),
                    "Generated":  o.get("generated_at"),
                    "Hosts":      o.get("hosts_count", 0),
                    "Ports":      o.get("ports_count", 0),
                }
                for o in history_options
            ]
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.info("No scan history found. Run a scan to get started.")

# -------------------------------------------------------------------------
# MAIN — Header
# -------------------------------------------------------------------------

st.title(":material/security: Attack Graph Generator")
st.caption(
    "Latest completed security assessment. "
    "Exposure findings require validation; they are not confirmed exploits."
)

# -------------------------------------------------------------------------
# MAIN — New Network Scan Form
# -------------------------------------------------------------------------

current_lan = get_local_ip_hint()

with st.container(border=True):
    st.subheader("New network scan", divider="gray")
    col1, col2, col3 = st.columns([3, 1.5, 1])

    with col1:
        target_network = st.text_input(
            "Target Network / IP (CIDR):",
            value=current_lan,
            help="Enter network to scan. Detected active network is pre-filled.",
        )
    with col2:
        scan_mode_choice = st.selectbox(
            "Scan Mode:",
            options=["Fast Scan (Top 120+ Ports)", "Full Deep Scan (1-65535 Ports)"],
            index=0,
            help="Fast scan checks key services in seconds. Full scan checks all 65 535 TCP ports.",
        )
    with col3:
        st.write("")
        st.write("")
        run_scan = st.button("🚀 Start Scan", type="primary", use_container_width=True)

# Scan execution
if run_scan:
    mode = "fast" if "Fast" in scan_mode_choice else "full"
    with st.status(f"Scanning `{target_network}`…", expanded=True) as status_box:
        st.write(f"Initiating **{mode.upper()}** scan on `{target_network}`…")
        engine       = ScanEngine()
        progress_bar = st.progress(0.0)

        for event in engine.scan_stream(network=target_network, scan_mode=mode, max_workers=200):
            ev = event.get("type")

            if ev == "stage":
                prog = min(1.0, max(0.0, float(event.get("progress", 0.0))))
                progress_bar.progress(prog, text=f"Stage: {event.get('title', 'Running…')}")

            elif ev == "log":
                msg = event.get("message", "")
                lvl = event.get("level", "info")
                if lvl in ("success", "header"):
                    st.write(f"**{msg}**")
                elif lvl in ("warning", "error", "danger"):
                    st.write(f":red[{msg}]")
                else:
                    st.caption(msg)

            elif ev == "complete":
                progress_bar.progress(1.0, text="Scan Complete!")
                res = event.get("result", {})
                hosts_found = res.get("hosts", [])
                
                if not hosts_found:
                    st.session_state["scan_notice"] = (
                        f"No active hosts responded on `{target_network}`. "
                        "Note: Cloud instances (Streamlit Cloud) cannot reach private home Wi-Fi networks (192.168.x.x). "
                        "To scan your local Wi-Fi, run the tool on your machine at `http://localhost:8501`."
                    )
                else:
                    st.session_state["scan_notice"] = None

                status_box.update(
                    label="Assessment completed!",
                    state="complete", expanded=False,
                )
                st.toast("Scan completed!", icon="✅")
                time.sleep(0.5)
                st.rerun()

# -------------------------------------------------------------------------
# MAIN — Assessment Results
# -------------------------------------------------------------------------

if st.session_state.get("scan_notice"):
    st.warning(st.session_state["scan_notice"], icon=":material/warning:")

assessment = load_assessment_from_file(selected_assessment_file)

if assessment is None:
    st.warning(
        "No completed assessment found. Run a scan first, then refresh.",
        icon=":material/info:",
    )
elif not assessment["hosts"]:
    st.info("The selected assessment did not contain any hosts.")
else:
    viewed_target  = assessment.get("target_network", "")
    viewed_scan_id = assessment.get("scan_id", "")
    viewed_at      = assessment.get("scanned_at", "")
    is_latest      = (selected_assessment_file == REPORT_PATH)

    # Informative Banner
    if is_latest:
        st.info(
            f"**Latest assessment** · Target Network: **`{viewed_target}`** · Scan ID: `{viewed_scan_id}` · Generated: `{viewed_at}`",
            icon=":material/check_circle:",
        )
    else:
        st.warning(
            f"**Historical scan record** · Target Network: **`{viewed_target}`** · Scan ID: `{viewed_scan_id}` · Generated: `{viewed_at}`",
            icon=":material/history:",
        )

    render_scan_result(assessment, key_prefix="active_assessment")
