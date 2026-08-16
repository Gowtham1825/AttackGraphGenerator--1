from core import asset
from scanner.host_discovery import HostDiscovery
from scanner.port_scanner import PortScanner
from scanner.service_detection import ServiceDetection

from analysis.attack_path import AttackPath
from analysis.findings import SecurityFindings
from analysis.recommendations import RecommendationEngine

from core.asset import Asset

from graph.risk_engine import RiskEngine
from graph.visualizer import GraphVisualizer

from utils.json_report import JsonReport


def main():

    print("MAIN STARTED")

    # ==========================================
    # NETWORK INPUT
    # ==========================================

    network = input("Enter Network (Example: 192.168.1.0/24): ").strip()

    if not network:
        print("ERROR: Network cannot be empty.")
        return

    # ==========================================
    # INITIALIZE MODULES
    # ==========================================

    host_scanner = HostDiscovery()
    port_scanner = PortScanner()
    service_detector = ServiceDetection()

    findings_engine = SecurityFindings()
    recommendation_engine = RecommendationEngine()

    risk_engine = RiskEngine()
    attack_path = AttackPath()

    visualizer = GraphVisualizer()
    report = JsonReport()

    assets = []

    # ==========================================
    # HOST DISCOVERY
    # ==========================================

    print("\n========== HOST DISCOVERY ==========")

    hosts = host_scanner.scan(network)

    print(f"Discovered Hosts: {len(hosts)}")

    if not hosts:
        print("No active hosts discovered.")
        return

    print("Hosts:", hosts)
    print("====================================")

    # ==========================================
    # HOST / PORT / SERVICE ANALYSIS
    # ==========================================

    for ip in hosts:

        print(f"\n[+] Scanning Host: {ip}")

        # --------------------------------------
        # Create Asset
        # --------------------------------------

        asset = Asset(ip)

        # --------------------------------------
        # Port Scanning
        # --------------------------------------

        open_ports = port_scanner.scan(ip)

        asset.open_ports = open_ports

        print(f"    Open Ports: {open_ports}")

        # --------------------------------------
        # Service + Findings Analysis
        # --------------------------------------

        services = []
        findings = []

        for port in open_ports:

            # ----------------------------------
            # Service Detection
            # ----------------------------------

            service = service_detector.detect(port)

            service_data = {"port": port, "service": service}

            services.append(service_data)

            # Store service in Asset
            asset.add_service(service_data)

            # ----------------------------------
            # Security Findings
            # ----------------------------------

            port_findings = findings_engine.analyze(port)

            for finding in port_findings:

                findings.append(finding)

                # Store finding in Asset
                asset.add_vulnerability(finding)

        # ======================================
        # OS DETECTION
        # ======================================

        os_analysis = service_detector.detect_os(open_ports)

        asset.os = os_analysis["os"]

        print(
            f"    OS: {os_analysis['os']} " f"({os_analysis['confidence']} confidence)"
        )

        # ======================================
        # RISK ANALYSIS
        # ======================================

        risk_analysis = risk_engine.analyze(asset)

        risk = risk_analysis["risk"]
        risk_score = risk_analysis["score"]

        print(f"    Risk Score: {risk_score}")
        print(f"    Risk Level: {risk}")

        # ======================================
        # STORE ASSET INFORMATION
        # ======================================

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

        # ======================================
        # GRAPH - HOST
        # ======================================

        visualizer.add_host(ip, risk, risk_score)

        for service_data in services:

            port = service_data["port"]
            service = service_data["service"]

            # Add HOST → PORT
            visualizer.add_port(ip, port, service)

        # Use findings already stored in Asset
        for finding in asset.vulnerabilities:

            finding_port = finding.get("port")

        if finding_port != port:
            continue

        # Add PORT → FINDING
        visualizer.add_finding(ip, port, finding)

        # Add FINDING → RISK PATH
        if finding.get("severity") in ["MEDIUM", "HIGH", "CRITICAL"]:

            visualizer.add_risk_path(ip, port, finding.get("severity"))

            # ----------------------------------
            # Risk Path
            # ----------------------------------

            if port_findings and risk in ["MEDIUM", "HIGH", "CRITICAL"]:

                visualizer.add_risk_path(ip, port, risk)

    # ==========================================
    # SCAN SUMMARY
    # ==========================================

    print("\n========== SCAN SUMMARY ==========")

    total_hosts = len(assets)

    low_hosts = 0
    medium_hosts = 0
    high_hosts = 0
    critical_hosts = 0

    total_ports = 0
    total_findings = 0

    for asset_data in assets:

        asset_risk = asset_data["risk"]

        if asset_risk == "LOW":
            low_hosts += 1

        elif asset_risk == "MEDIUM":
            medium_hosts += 1

        elif asset_risk == "HIGH":
            high_hosts += 1

        elif asset_risk == "CRITICAL":
            critical_hosts += 1

        total_ports += len(asset_data["open_ports"])

        total_findings += len(asset_data["findings"])

    print(f"Total Hosts       : {total_hosts}")
    print(f"Low Risk Hosts    : {low_hosts}")
    print(f"Medium Risk       : {medium_hosts}")
    print(f"High Risk         : {high_hosts}")
    print(f"Critical Hosts    : {critical_hosts}")
    print(f"Open Ports        : {total_ports}")
    print(f"Findings          : {total_findings}")

    print("==================================")

    # ==========================================
    # SECURITY FINDINGS + RECOMMENDATIONS
    # ==========================================

    print("\n========== SECURITY FINDINGS ==========")

    findings_found = False

    for asset_data in assets:

        if not asset_data["findings"]:
            continue

        findings_found = True

        print(f"\nHost: {asset_data['ip']}")

        for finding in asset_data["findings"]:

            severity = finding.get("severity", "UNKNOWN")

            title = finding.get("title", "Unknown Finding")

            reason = finding.get("reason", "No reason provided")

            print(f"\n  [{severity}] {title}")

            print(f"  Reason: {reason}")

            # Recommendation
            recommendation = recommendation_engine.generate(finding)

            print(f"  Priority: " f"{recommendation['priority']}")

            print(f"  Recommendation: " f"{recommendation['recommendation']}")

    if not findings_found:

        print("No security findings detected.")

    print("\n=======================================")

    # ==========================================
    # ATTACK PATH ANALYSIS
    # ==========================================

    print("\n========== POTENTIAL RISK PATHS ==========")

    paths = attack_path.find_paths(assets)

    if not paths:

        print("No potential risk paths detected.")

    else:

        for path in paths:

            path_risk = path.get("risk", "UNKNOWN")

            target = path.get("target", "Unknown")

            reason = path.get("reason", "No reason provided")

            port = path.get("port", None)

            service = path.get("service", None)

            if port is not None:

                print(
                    f"[{path_risk}] " f"{target}:{port} " f"({service}) - " f"{reason}"
                )

            else:

                print(f"[{path_risk}] " f"{target} - " f"{reason}")

    print("==========================================")

    # ==========================================
    # ADD ATTACK PATHS TO GRAPH
    # ==========================================

    for path in paths:

        ip = path.get("target")

        port = path.get("port")
        risk = path.get("risk", "LOW")

    if ip and port is not None:
        if risk in ["MEDIUM", "HIGH", "CRITICAL"]:
            visualizer.add_risk_path(ip, port, risk)

    # ==========================================
    # JSON REPORT
    # ==========================================

    try:

        report.save(assets)

        print("\nJSON Security Report Generated.")

    except Exception as error:

        print("\nWARNING: " f"Could not save JSON report: " f"{error}")

    # ==========================================
    # ATTACK GRAPH
    # ==========================================

    try:

        visualizer.save()

        print("\nAttack Graph Generated Successfully!")

        print("Open: " "reports/graphs/attack_graph.html")

    except Exception as error:

        print("\nWARNING: " f"Could not save attack graph: " f"{error}")

    # ==========================================
    # FINAL STATUS
    # ==========================================

    print("\n========== SCAN COMPLETE ==========")

    print(f"Hosts Scanned : {total_hosts}")

    print(f"Open Ports    : {total_ports}")

    print(f"Findings      : {total_findings}")

    print("===================================")


# ==============================================
# PROGRAM ENTRY POINT
# ==============================================

if __name__ == "__main__":
    main()
