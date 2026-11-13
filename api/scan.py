"""Small, deliberately scoped scanner for local dashboard previews.

It only accepts private or loopback IPv4 targets and checks a focused set of
common TCP services. It is not enabled in the hosted Vercel environment.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import ipaddress
import socket

from analysis.findings import SecurityFindings
from core.asset import Asset
from graph.risk_engine import RiskEngine
from scanner.service_detection import ServiceDetection


# Use the project's complete service catalogue rather than a short dashboard-only list.
COMMON_PORTS = tuple(sorted(ServiceDetection.SERVICES))
MAX_HOSTS = 256
TIMEOUT_SECONDS = 0.25
MAX_WORKERS = 256


def _targets(target):
    """Return allowed target addresses, rejecting public or excessively wide CIDRs."""
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as error:
        raise ValueError("Enter a valid IPv4 address or CIDR range.") from error

    if network.version != 4 or not (network.is_private or network.is_loopback):
        raise ValueError("Only private or loopback IPv4 targets can be scanned locally.")

    addresses = list(network.hosts()) if network.prefixlen < 32 else [network.network_address]
    if not addresses:
        addresses = [network.network_address]
    if len(addresses) > MAX_HOSTS:
        raise ValueError("Use a target with at most 256 hosts (for example, a /24 range).")
    return [str(address) for address in addresses]


def _is_open(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT_SECONDS):
            return ip, port
    except OSError:
        return None


def run_scan(target, progress_callback=None):
    """Scan an authorised local target and return JSON-ready dashboard data.

    ``progress_callback`` receives the completed and total connection checks so
    an interactive caller can show live progress without saving partial data.
    """
    hosts = _targets(target)
    services = ServiceDetection()
    finding_engine = SecurityFindings()
    risk_engine = RiskEngine()
    open_by_host = {ip: [] for ip in hosts}

    total_checks = len(hosts) * len(COMMON_PORTS)
    worker_count = min(MAX_WORKERS, total_checks)
    completed_checks = 0
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [executor.submit(_is_open, ip, port) for ip in hosts for port in COMMON_PORTS]
        for future in as_completed(futures):
            result = future.result()
            completed_checks += 1
            if result:
                ip, port = result
                open_by_host[ip].append(port)
            if progress_callback:
                progress_callback(completed_checks, total_checks)

    findings = []
    mapped_services = []
    host_results = []
    for ip, ports in open_by_host.items():
        asset = Asset(ip)
        asset.open_ports = sorted(ports)
        host_services = []
        host_findings = []

        for port in sorted(ports):
            service = services.get_info(port)
            service["host"] = ip
            mapped_services.append(service)
            host_services.append(service)
            asset.add_service(service)
            for finding in finding_engine.analyze(port):
                enriched_finding = {"host": ip, **finding}
                findings.append(enriched_finding)
                host_findings.append(enriched_finding)
                asset.add_vulnerability(enriched_finding)

        os_analysis = services.detect_os(asset.open_ports)
        asset.os = os_analysis["os"]
        risk_analysis = risk_engine.analyze(asset)
        host_results.append(
            {
                "host": ip,
                "operating_system": os_analysis["os"],
                "os_confidence": os_analysis["confidence"],
                "open_ports": asset.open_ports,
                "services": host_services,
                "findings": host_findings,
                "risk": risk_analysis["risk"],
                "risk_score": risk_analysis["score"],
            }
        )

    priority_paths = sum(
        finding["severity"] in {"HIGH", "CRITICAL"} for finding in findings
    )
    return {
        "target": target,
        "scan_id": datetime.now().strftime("%Y%m%d_%H%M%S"),
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
        "hosts_in_scope": len(hosts),
        "hosts_with_services": sum(bool(ports) for ports in open_by_host.values()),
        "hosts": host_results,
        "services": mapped_services,
        "findings": findings,
        "priority_paths": priority_paths,
    }
