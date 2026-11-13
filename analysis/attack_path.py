"""Attack path builder identifying risk traversal relationships."""

from typing import List, Dict, Any


class AttackPath:
    """Builds logical risk relationships across Host -> Service -> Finding."""

    def find_paths(self, assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        paths = []

        for asset in assets:
            ip = asset.get("ip", "Unknown")
            risk = asset.get("risk", "LOW")
            risk_score = asset.get("risk_score", 0)
            services = asset.get("services", [])
            findings = asset.get("findings", [])

            if not services and not findings:
                continue

            if risk in ["HIGH", "MEDIUM"]:
                paths.append({
                    "target": ip,
                    "risk": risk,
                    "risk_score": risk_score,
                    "reason": f"{risk}-risk asset with exposed service surface",
                })

            for service in services:
                port = service.get("port", "Unknown")
                service_name = service.get("service", "Unknown Service")

                related_findings = [
                    f for f in findings
                    if service_name.lower() in f.get("title", "").lower()
                ]

                for finding in related_findings:
                    paths.append({
                        "target": ip,
                        "port": port,
                        "service": service_name,
                        "risk": finding.get("severity", "LOW"),
                        "risk_score": risk_score,
                        "finding": finding.get("title", "Security Finding"),
                        "reason": finding.get("reason", "Security issue detected"),
                    })

        return paths
