"""Core scanning and attack graph engine.

Coordinates host discovery, port scanning, service detection,
security findings analysis, risk calculation, attack path discovery,
report generation, and graph visualization.
"""

from datetime import datetime
import ipaddress
import socket
from typing import Generator, Any, Dict, List, Optional

from analysis.attack_path import AttackPath
from analysis.findings import SecurityFindings
from analysis.recommendations import RecommendationEngine
from core.asset import Asset
from graph.risk_engine import RiskEngine
from graph.visualizer import GraphVisualizer
from scanner.host_discovery import HostDiscovery
from scanner.port_scanner import PortScanner
from scanner.service_detection import ServiceDetection
from utils.json_report import JsonReport


# Curated high-priority & common services for fast/responsive scanning
COMMON_PORTS = tuple(sorted(set(
    list(ServiceDetection.SERVICES.keys()) + [
        # Remote & Management
        21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 137, 138, 139, 143, 161, 389,
        443, 445, 465, 500, 587, 631, 636, 873, 902, 912, 993, 995, 1080,
        1433, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 2181, 2870, 2874,
        3000, 3128, 3306, 3389, 4200, 5000, 5040, 5432, 5500, 5501, 5672,
        5900, 5985, 5986, 6379, 7001, 7547, 8000, 8008, 8080, 8081, 8443,
        8501, 8888, 9000, 9080, 9090, 9200, 9418, 11211, 27017, 33349,
        46547, 49664, 49665, 49666, 49667, 49668, 49670, 52235
    ]
)))


def get_local_ip_hint() -> str:
    """Return local subnet hint (e.g. 192.168.1.0/24)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        return "192.168.1.0/24"


class ScanEngine:
    """Unified Scanning and Attack Graph Execution Engine."""

    def __init__(self):
        self.host_scanner = HostDiscovery()
        self.port_scanner = PortScanner()
        self.service_detector = ServiceDetection()
        self.findings_engine = SecurityFindings()
        self.recommendation_engine = RecommendationEngine()
        self.risk_engine = RiskEngine()
        self.attack_path_engine = AttackPath()
        self.visualizer = GraphVisualizer()
        self.reporter = JsonReport()

    def get_ports_for_mode(self, mode: str, custom_ports: Optional[List[int]] = None) -> Optional[List[int]]:
        """Return port range/list according to selected scan profile."""
        mode = mode.lower()
        if mode == "fast":
            return list(COMMON_PORTS)
        elif mode == "standard":
            # Ports 1-1024 plus common enterprise/db services
            standard = set(range(1, 1025)) | set(COMMON_PORTS)
            return sorted(list(standard))
        elif mode == "full":
            return None  # Will scan 1-65535
        elif mode == "custom" and custom_ports:
            return sorted(list(set(custom_ports)))
        return list(COMMON_PORTS)

    def scan_stream(
        self,
        network: str,
        scan_mode: str = "fast",
        custom_ports: Optional[List[int]] = None,
        max_workers: int = 200,
    ) -> Generator[Dict[str, Any], None, Dict[str, Any]]:
        """Run full scanning pipeline, yielding real-time events for UI streaming."""
        network = network.strip()
        if not network:
            yield {"type": "error", "message": "Target network/IP cannot be empty."}
            return {}

        self.port_scanner.max_workers = max_workers
        ports_to_scan = self.get_ports_for_mode(scan_mode, custom_ports)
        port_desc = "1-65535 (Full)" if ports_to_scan is None else f"{len(ports_to_scan)} targeted ports ({scan_mode.upper()})"

        yield {
            "type": "log",
            "message": f"[*] Starting Scan on target: {network} [Mode: {scan_mode.upper()} - {port_desc}]",
            "level": "info",
        }

        # ----------------------------------------------------
        # Stage 1: Host Discovery
        # ----------------------------------------------------
        yield {"type": "stage", "stage": "host_discovery", "progress": 0.05, "title": "Host Discovery"}
        yield {"type": "log", "message": f"========== HOST DISCOVERY ==========", "level": "header"}
        yield {"type": "log", "message": f"[*] Target Network: {network}", "level": "info"}

        discovered_hosts = []

        def on_host_found(ip):
            discovered_hosts.append(ip)

        # Run discovery
        hosts = self.host_scanner.scan(network, on_host_found=on_host_found)

        if not hosts:
            yield {"type": "log", "message": "[-] No active hosts discovered on target network.", "level": "warning"}
            yield {"type": "stage", "stage": "completed", "progress": 1.0, "title": "Scan Complete"}
            empty_result = {
                "target": network,
                "hosts": [],
                "summary": {"total_hosts": 0, "open_ports": 0, "findings": 0},
                "attack_paths": [],
            }
            yield {"type": "complete", "result": empty_result}
            return empty_result

        yield {"type": "log", "message": f"[+] Discovered {len(hosts)} Active Hosts: {', '.join(hosts)}", "level": "success"}
        yield {
            "type": "hosts_discovered",
            "hosts": hosts,
            "count": len(hosts)
        }

        # ----------------------------------------------------
        # Stage 2: Port, Service, OS & Risk Analysis per Host
        # ----------------------------------------------------
        yield {"type": "stage", "stage": "port_scanning", "progress": 0.20, "title": "Port & Vulnerability Scanning"}
        assets = []
        total_hosts = len(hosts)

        for host_idx, ip in enumerate(hosts, start=1):
            host_progress = 0.20 + (0.55 * (host_idx - 1) / total_hosts)
            yield {
                "type": "stage",
                "stage": "scanning_host",
                "progress": host_progress,
                "title": f"Scanning Host {host_idx}/{total_hosts}: {ip}"
            }
            yield {"type": "log", "message": f"\n[+] Scanning Host: {ip} ({host_idx}/{total_hosts})", "level": "header"}
            yield {"type": "log", "message": f"[*] Target: {ip} | Scan: {port_desc} | Workers: {max_workers}", "level": "info"}

            asset = Asset(ip)
            open_ports_list = []

            def on_port_found(target_ip, port):
                open_ports_list.append(port)

            open_ports = self.port_scanner.scan(
                ip,
                ports=ports_to_scan,
                on_port_found=on_port_found
            )
            asset.open_ports = open_ports

            # Service & Security Findings Detection
            services = []
            findings = []

            for port in open_ports:
                service = self.service_detector.detect(port)
                service_data = {"port": port, "service": service}
                services.append(service_data)
                asset.add_service(service_data)

                yield {
                    "type": "port_discovered",
                    "ip": ip,
                    "port": port,
                    "service": service,
                }
                yield {"type": "log", "message": f"    [+] {ip}:{port} OPEN ({service})", "level": "success"}

                # Findings Analysis
                port_findings = self.findings_engine.analyze(port)
                for finding in port_findings:
                    findings.append(finding)
                    asset.add_vulnerability(finding)
                    yield {
                        "type": "finding_discovered",
                        "ip": ip,
                        "port": port,
                        "finding": finding,
                    }
                    yield {
                        "type": "log",
                        "message": f"    [!] [{finding.get('severity', 'LOW')}] Port {port}: {finding.get('title')}",
                        "level": "warning" if finding.get('severity') == "MEDIUM" else "error",
                    }

            # OS Detection
            os_analysis = self.service_detector.detect_os(open_ports)
            asset.os = os_analysis["os"]
            yield {
                "type": "log",
                "message": f"    [*] OS Detected: {os_analysis['os']} ({os_analysis['confidence']} confidence)",
                "level": "info",
            }

            # Risk Engine Analysis
            risk_analysis = self.risk_engine.analyze(asset)
            risk = risk_analysis["risk"]
            risk_score = risk_analysis["score"]
            yield {
                "type": "log",
                "message": f"    [*] Risk Score: {risk_score} | Level: {risk}",
                "level": "warning" if risk in ["HIGH", "CRITICAL"] else "info",
            }

            # Compile Asset Data
            asset_data = {
                "ip": asset.ip,
                "hostname": asset.hostname,
                "os": asset.os,
                "open_ports": asset.open_ports,
                "services": asset.services,
                "findings": asset.vulnerabilities,
                "risk": risk,
                "risk_score": risk_score,
                "risk_analysis": risk_analysis,
            }
            assets.append(asset_data)

            # Add to PyVis Visualizer
            self.visualizer.add_host(ip, risk, risk_score)
            for service_data in services:
                self.visualizer.add_port(ip, service_data["port"], service_data["service"])

            for finding in asset.vulnerabilities:
                finding_port = finding.get("port")
                if finding_port is not None:
                    self.visualizer.add_finding(ip, finding_port, finding)
                    severity = finding.get("severity", "LOW")
                    if severity in ["MEDIUM", "HIGH", "CRITICAL"]:
                        self.visualizer.add_risk_path(ip, finding_port, severity)

            yield {
                "type": "host_completed",
                "asset": asset_data,
                "ip": ip,
                "completed": host_idx,
                "total": total_hosts,
            }

        # ----------------------------------------------------
        # Stage 3: Attack Path Analysis & Risk Paths
        # ----------------------------------------------------
        yield {"type": "stage", "stage": "attack_paths", "progress": 0.85, "title": "Attack Path Analysis"}
        yield {"type": "log", "message": f"\n========== POTENTIAL RISK PATHS ==========", "level": "header"}

        paths = self.attack_path_engine.find_paths(assets)
        if not paths:
            yield {"type": "log", "message": "No potential risk paths detected.", "level": "info"}
        else:
            for path in paths:
                p_risk = path.get("risk", "UNKNOWN")
                target = path.get("target", "Unknown")
                reason = path.get("reason", "")
                port = path.get("port")
                service = path.get("service")
                if port is not None:
                    msg = f"[{p_risk}] {target}:{port} ({service}) - {reason}"
                else:
                    msg = f"[{p_risk}] {target} - {reason}"
                yield {"type": "log", "message": msg, "level": "warning" if p_risk == "MEDIUM" else "error"}

                if target and port is not None and p_risk in ["MEDIUM", "HIGH", "CRITICAL"]:
                    self.visualizer.add_risk_path(target, port, p_risk)

        # ----------------------------------------------------
        # Stage 4: Report and Attack Graph Output
        # ----------------------------------------------------
        yield {"type": "stage", "stage": "saving_reports", "progress": 0.92, "title": "Saving Reports & Graph"}

        # Save JSON Report
        report_file = None
        try:
            self.reporter.save(assets, target_network=network)
            report_file = "reports/scan_results.json"
            yield {"type": "log", "message": "[+] JSON Security Report Saved Successfully: reports/scan_results.json", "level": "success"}
        except Exception as e:
            yield {"type": "log", "message": f"[!] Warning: Could not save JSON report: {e}", "level": "warning"}

        # Save HTML Attack Graph
        graph_file = None
        try:
            self.visualizer.save()
            graph_file = "reports/attack_graph.html"
            yield {"type": "log", "message": "[+] Attack Graph Generated Successfully: reports/attack_graph.html", "level": "success"}
        except Exception as e:
            yield {"type": "log", "message": f"[!] Warning: Could not save Attack Graph: {e}", "level": "warning"}

        # Final Summary
        total_open_ports = sum(len(a["open_ports"]) for a in assets)
        total_findings = sum(len(a["findings"]) for a in assets)
        high_risk_hosts = sum(1 for a in assets if a["risk"] in ["HIGH", "CRITICAL"])

        yield {"type": "log", "message": "\n========== SCAN COMPLETE ==========", "level": "header"}
        yield {"type": "log", "message": f"Hosts Scanned : {len(assets)}", "level": "info"}
        yield {"type": "log", "message": f"Open Ports    : {total_open_ports}", "level": "info"}
        yield {"type": "log", "message": f"Findings      : {total_findings}", "level": "info"}
        yield {"type": "log", "message": f"High Risk     : {high_risk_hosts}", "level": "info"}

        scan_result = {
            "target": network,
            "scanned_at": datetime.now().isoformat(timespec="seconds"),
            "scan_id": datetime.now().strftime("%Y%m%d_%H%M%S"),
            "hosts": assets,
            "summary": {
                "total_hosts": len(assets),
                "total_open_ports": total_open_ports,
                "total_findings": total_findings,
                "high_risk_hosts": high_risk_hosts,
            },
            "attack_paths": paths,
            "report_file": report_file,
            "graph_file": graph_file,
        }

        yield {"type": "stage", "stage": "completed", "progress": 1.0, "title": "Completed"}
        yield {"type": "complete", "result": scan_result}
        return scan_result
