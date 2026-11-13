"""Create a concise left-to-right security assessment flowchart."""

import json


_FINDING_COLORS = {
    "LOW": "#86EFAC",
    "MEDIUM": "#FBBF24",
    "HIGH": "#F87171",
    "CRITICAL": "#991B1B",
}


def _dot_string(value: object) -> str:
    """Quote a value safely for the DOT language."""
    return json.dumps(str(value))


def create_attack_flow(host: dict) -> str:
    """Return Host → service → finding flow for a selected host."""
    lines = [
        "digraph attack_flow {",
        '  graph [rankdir="LR", bgcolor="white", pad="0.35", nodesep="0.55", ranksep="1.0"];',
        '  node [fontname="Arial", fontsize="13", color="#111827", penwidth="1.5"];',
        '  edge [fontname="Arial", fontsize="11", color="#111827", penwidth="1.3"];',
    ]

    host_id = "host"
    host_label = (
        f"{host['host']}\nRisk: {host.get('risk', 'UNKNOWN')} "
        f"({host.get('risk_score', 0)})"
    )
    lines.append(
        f"  {host_id} [label={_dot_string(host_label)}, "
        'shape="box", style="filled", fillcolor="#F59E0B"];'
    )

    findings_by_port: dict[object, list[dict]] = {}
    for finding in host.get("findings", []):
        findings_by_port.setdefault(finding.get("port"), []).append(finding)

    for index, service in enumerate(host.get("services", [])):
        port = service["port"]
        service_id = f"service_{index}"
        service_label = f"{service.get('service', 'UNKNOWN')}\nPort {port}"
        lines.append(
            f"  {service_id} [label={_dot_string(service_label)}, "
            'shape="ellipse", style="filled", fillcolor="#38BDF8"];'
        )
        lines.append(f'  {host_id} -> {service_id} [label="exposes"];')

        for finding_index, finding in enumerate(findings_by_port.get(port, [])):
            finding_id = f"finding_{index}_{finding_index}"
            severity = finding.get("severity", "UNKNOWN")
            finding_label = f"{severity}\n{finding.get('title', 'Finding')}"
            lines.append(
                f"  {finding_id} [label={_dot_string(finding_label)}, "
                f'shape="diamond", style="filled", fillcolor="{_FINDING_COLORS.get(severity, "#D1D5DB")}"];'
            )
            lines.append(f'  {service_id} -> {finding_id} [label="has finding"];')

    lines.append("}")
    return "\n".join(lines)
