"""Focused result view shared by live and saved web scans."""

from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from analysis.recommendations import RecommendationEngine
from utils.web_flow import create_attack_flow


def _host_records(scan: dict) -> list[dict]:
    """Return hosts in the current scan, including a fallback for old history."""
    if scan.get("hosts"):
        return scan["hosts"]

    services_by_host: dict[str, list[dict]] = {}
    findings_by_host: dict[str, list[dict]] = {}
    for service in scan.get("services", []):
        services_by_host.setdefault(service.get("host", scan["target"]), []).append(service)
    for finding in scan.get("findings", []):
        findings_by_host.setdefault(finding.get("host", scan["target"]), []).append(finding)

    host_names = set(services_by_host) | set(findings_by_host) or {scan["target"]}
    return [
        {
            "host": host,
            "operating_system": "Unknown",
            "risk": "UNKNOWN",
            "risk_score": 0,
            "open_ports": [service["port"] for service in services_by_host.get(host, [])],
            "services": services_by_host.get(host, []),
            "findings": findings_by_host.get(host, []),
        }
        for host in sorted(host_names)
    ]


def render_scan_result(scan: dict, *, key_prefix: str) -> None:
    """Render only the assessment details needed to triage a scan."""
    hosts = _host_records(scan)
    scanned_at = scan.get("scanned_at", datetime.now().isoformat(timespec="seconds"))
    scan_id = scan.get("scan_id", scanned_at.replace("-", "").replace(":", "").replace("T", "_")[:15])
    target_net = scan.get("target_network") or scan.get("target") or "Unknown"

    total_ports = sum(len(host.get("open_ports", [])) for host in hosts)
    high_risk_hosts = sum(
        host.get("risk") in {"HIGH", "CRITICAL"} for host in hosts
    )

    with st.container(border=True):
        st.subheader("Assessment details", divider="gray")
        col_d1, col_d2, col_d3 = st.columns([1.5, 1.5, 2])
        col_d1.markdown(f"**Target Network:** `{target_net}`")
        col_d2.markdown(f"**Scan ID:** `{scan_id}`")
        col_d3.markdown(f"**Generated:** `{scanned_at}`")

    with st.container(horizontal=True):
        st.metric("Hosts", len(hosts), border=True)
        st.metric("Open ports", total_ports, border=True)
        st.metric("Exposure findings", len(scan.get("findings", [])), border=True)
        st.metric("High-risk hosts", high_risk_hosts, border=True)

    with st.container(border=True):
        st.subheader("Hosts", divider="gray")
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Host": host["host"],
                        "Operating system": host.get("operating_system", "Unknown"),
                        "Open ports": len(host.get("open_ports", [])),
                        "Findings": len(host.get("findings", [])),
                        "Risk": host.get("risk", "UNKNOWN"),
                        "Risk score": host.get("risk_score", 0),
                    }
                    for host in hosts
                ]
            ),
            use_container_width=True,
        )

    selected_host = st.selectbox(
        "Inspect host",
        hosts,
        format_func=lambda host: host["host"],
        key=f"{key_prefix}_host",
    )
    selected_services = selected_host.get("services", [])
    selected_findings = selected_host.get("findings", [])

    services_column, findings_column = st.columns(2)
    with services_column:
        with st.container(border=True):
            st.subheader(f"Exposed services — {selected_host['host']}", divider="gray")
            if selected_services:
                st.dataframe(
                    pd.DataFrame(
                        [
                            {"Port": service["port"], "Service": service.get("service", "UNKNOWN")}
                            for service in selected_services
                        ]
                    ),
                    use_container_width=True,
                )
            else:
                st.info("No supported TCP services responded on this host.")
    with findings_column:
        with st.container(border=True):
            st.subheader("Findings", divider="gray")
            if selected_findings:
                st.dataframe(
                    pd.DataFrame(
                        [
                            {
                                "Severity": finding.get("severity", "UNKNOWN"),
                                "Finding": finding.get("title", "Unknown finding"),
                                "Port": finding.get("port", "—"),
                                "Reason": finding.get("reason", "No reason provided."),
                            }
                            for finding in selected_findings
                        ]
                    ),
                    use_container_width=True,
                )
            else:
                st.success("No exposure findings for this host.")

    st.subheader("Attack graph", divider="gray")
    st.caption("Host → exposed service → finding")
    st.graphviz_chart(create_attack_flow(selected_host), width="stretch", height=650)

    # Optional full interactive PyVis graph
    graph_path = Path("reports") / "attack_graph.html"
    if graph_path.exists():
        with st.expander("🌐 View Full Interactive PyVis Network Graph", expanded=False):
            try:
                with open(graph_path, "r", encoding="utf-8") as gf:
                    components.html(gf.read(), height=650, scrolling=True)
            except Exception:
                pass

    if selected_findings:
        recommendations = RecommendationEngine()
        with st.expander("Recommended next steps", expanded=True):
            for finding in selected_findings:
                recommendation = recommendations.generate(finding)
                st.write(
                    f"**{finding.get('title', 'Finding')}** — "
                    f"{recommendation['recommendation']}"
                )
