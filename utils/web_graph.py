"""Build the existing interactive attack graph for web scan results."""

from graph.visualizer import GraphVisualizer


def create_attack_graph(scan: dict) -> str:
    """Return a self-contained PyVis graph for a live or saved scan."""
    visualizer = GraphVisualizer(cdn_resources="in_line")
    known_hosts = set()

    for host in scan.get("hosts", []):
        ip = host["host"]
        visualizer.add_host(ip, host.get("risk", "UNKNOWN"), host.get("risk_score", 0))
        known_hosts.add(ip)

    for service in scan.get("services", []):
        ip = service.get("host", scan.get("target", "Unknown host"))
        if ip not in known_hosts:
            visualizer.add_host(ip, "UNKNOWN", 0)
            known_hosts.add(ip)
        visualizer.add_port(ip, service["port"], service.get("service", "UNKNOWN"))

    for finding in scan.get("findings", []):
        ip = finding.get("host", scan.get("target", "Unknown host"))
        port = finding.get("port")
        if port is None:
            continue
        if ip not in known_hosts:
            visualizer.add_host(ip, "UNKNOWN", 0)
            known_hosts.add(ip)
        visualizer.add_finding(ip, port, finding)
        if finding.get("severity") in {"MEDIUM", "HIGH", "CRITICAL"}:
            visualizer.add_risk_path(ip, port, finding["severity"])

    return visualizer.net.generate_html(notebook=False)
