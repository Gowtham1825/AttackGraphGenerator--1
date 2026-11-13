"""Risk scoring engine computing weighted exposure scores for network assets."""

from typing import Dict, Any


class RiskEngine:
    """Calculates weighted security risk metrics for network assets based on exposure."""

    PORT_WEIGHTS: Dict[int, int] = {
        # High-risk / legacy services
        21: 4,      # FTP
        23: 5,      # Telnet
        445: 4,     # SMB
        3389: 4,    # RDP
        # Remote administration
        22: 2,      # SSH
        # Mail
        25: 2,
        110: 2,
        143: 2,
        # Network
        53: 1,
        # Web
        80: 2,
        443: 1,
        8080: 2,
        8443: 1,
        # Databases
        3306: 4,
        5432: 4,
        1433: 4,
        6379: 4,
        27017: 4,
    }

    SEVERITY_WEIGHTS: Dict[str, int] = {
        "LOW": 1,
        "MEDIUM": 3,
        "HIGH": 5,
        "CRITICAL": 8,
    }

    def calculate_score(self, asset: Any) -> int:
        open_ports = getattr(asset, "open_ports", [])
        findings = getattr(asset, "vulnerabilities", [])

        port_score = sum(self.PORT_WEIGHTS.get(p, 0) for p in open_ports)
        finding_score = sum(
            self.SEVERITY_WEIGHTS.get(f.get("severity", "LOW").upper(), 0)
            for f in findings
        )
        return port_score + finding_score

    def calculate_risk(self, asset: Any) -> str:
        score = self.calculate_score(asset)
        if score >= 15:
            return "HIGH"
        elif score >= 6:
            return "MEDIUM"
        return "LOW"

    def analyze(self, asset: Any) -> Dict[str, Any]:
        open_ports = getattr(asset, "open_ports", [])
        findings = getattr(asset, "vulnerabilities", [])

        port_score = 0
        high_risk_ports = []
        for port in open_ports:
            weight = self.PORT_WEIGHTS.get(port, 0)
            port_score += weight
            if weight >= 4:
                high_risk_ports.append(port)

        finding_score = 0
        finding_severities = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for finding in findings:
            severity = finding.get("severity", "LOW").upper()
            weight = self.SEVERITY_WEIGHTS.get(severity, 0)
            finding_score += weight
            if severity in finding_severities:
                finding_severities[severity] += 1

        total_score = port_score + finding_score
        if total_score >= 15:
            risk = "HIGH"
        elif total_score >= 6:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        return {
            "score": total_score,
            "risk": risk,
            "port_score": port_score,
            "finding_score": finding_score,
            "open_ports": len(open_ports),
            "high_risk_ports": high_risk_ports,
            "finding_severity": finding_severities,
        }
