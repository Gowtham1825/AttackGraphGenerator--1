"""Command-line interface for network attack surface discovery and graph generation."""

import sys
from core.asset import Asset
from scanner.host_discovery import HostDiscovery
from scanner.port_scanner import PortScanner
from scanner.service_detection import ServiceDetection
from analysis.attack_path import AttackPath
from analysis.findings import SecurityFindings
from analysis.recommendations import RecommendationEngine
from graph.risk_engine import RiskEngine
from graph.visualizer import GraphVisualizer
from utils.json_report import JsonReport


def main():
    print("=" * 45)
    print("       ATTACK GRAPH GENERATOR CLI")
    print("=" * 45)

    network = input("Enter Network CIDR or IP (e.g. 192.168.1.0/24): ").strip()
    if not network:
        print("[!] Error: Target network cannot be empty.")
        sys.exit(1)

    host_scanner = HostDiscovery()
    port_scanner = PortScanner()
    service_detector = ServiceDetection()
    findings_engine = SecurityFindings()
    recommendation_engine = RecommendationEngine()
    risk_engine = RiskEngine()
    attack_path_engine = AttackPath()
    visualizer = GraphVisualizer()
    reporter = JsonReport()

    print(f"\n[*] Discovering active hosts on {network}...")
    hosts = host_scanner.scan(network)
    print(f"[+] Discovered {len(hosts)} active host(s): {hosts}")

    if not hosts:
        print("[-] No active hosts found. Exiting.")
        return

    assets = []
    print("\n[*] Starting port scan, service enumeration, and risk assessment...")

    for ip in hosts:
        print(f"\n[+] Analyzing Host: {ip}")
        asset = Asset(ip)

        open_ports = port_scanner.scan(ip)
        asset.open_ports = open_ports
        print(f"    Open Ports : {open_ports if open_ports else 'None'}")

        services = []
        for port in open_ports:
            service_name = service_detector.detect(port)
            service_data = {"port": port, "service": service_name}
            services.append(service_data)
            asset.add_service(service_data)

            for finding in findings_engine.analyze(port):
                asset.add_vulnerability(finding)

        os_analysis = service_detector.detect_os(open_ports)
        asset.os = os_analysis.get("os", "Unknown")
        print(f"    Inferred OS: {asset.os} ({os_analysis.get('confidence', 'low')} confidence)")

        risk_analysis = risk_engine.analyze(asset)
        risk = risk_analysis["risk"]
        risk_score = risk_analysis["score"]
        print(f"    Risk Rating: {risk} (Score: {risk_score})")

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

        # Graph node generation
        visualizer.add_host(ip, risk, risk_score)
        for s in services:
            visualizer.add_port(ip, s["port"], s["service"])

        for finding in asset.vulnerabilities:
            finding_port = finding.get("port")
            if finding_port is not None:
                visualizer.add_finding(ip, finding_port, finding)
                if finding.get("severity") in ("MEDIUM", "HIGH", "CRITICAL"):
                    visualizer.add_risk_path(ip, finding_port, finding["severity"])

    # Summary
    print("\n" + "=" * 45)
    print("               SCAN SUMMARY")
    print("=" * 45)
    total_ports = sum(len(a["open_ports"]) for a in assets)
    total_findings = sum(len(a["findings"]) for a in assets)
    high_hosts = sum(1 for a in assets if a["risk"] in ("HIGH", "CRITICAL"))

    print(f"Total Hosts Scanned : {len(assets)}")
    print(f"High/Critical Hosts : {high_hosts}")
    print(f"Total Open Ports    : {total_ports}")
    print(f"Total Findings      : {total_findings}")

    # Security findings & recommendations
    print("\n" + "=" * 45)
    print("           SECURITY FINDINGS")
    print("=" * 45)
    has_findings = False
    for a in assets:
        if not a["findings"]:
            continue
        has_findings = True
        print(f"\nHost {a['ip']}:")
        for finding in a["findings"]:
            rec = recommendation_engine.generate(finding)
            print(f"  [{finding.get('severity')}] {finding.get('title')}")
            print(f"    Reason        : {finding.get('reason')}")
            print(f"    Recommendation: {rec['recommendation']}")

    if not has_findings:
        print("No exposure findings identified across discovered hosts.")

    # Risk traversal paths
    print("\n" + "=" * 45)
    print("            ATTACK PATHS")
    print("=" * 45)
    paths = attack_path_engine.find_paths(assets)
    if paths:
        for p in paths:
            port_str = f":{p['port']} ({p.get('service', '')})" if p.get("port") else ""
            print(f"  [{p.get('risk')}] {p.get('target')}{port_str} -> {p.get('reason')}")
            if p.get("target") and p.get("port") and p.get("risk") in ("MEDIUM", "HIGH", "CRITICAL"):
                visualizer.add_risk_path(p["target"], p["port"], p["risk"])
    else:
        print("No significant attack traversal paths detected.")

    # Save outputs
    try:
        reporter.save(assets, target_network=network)
        print("\n[✓] Saved structured JSON report to reports/scan_results.json")
    except Exception as err:
        print(f"[!] Warning: Could not save JSON report: {err}")

    try:
        visualizer.save()
        print("[✓] Generated interactive attack graph: reports/attack_graph.html")
    except Exception as err:
        print(f"[!] Warning: Could not save attack graph: {err}")

    print("\n[✓] Assessment finished successfully.")


if __name__ == "__main__":
    main()
