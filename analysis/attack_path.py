class AttackPath:
    """
    Analyzes discovered assets and generates
    potential security risk paths.

    This module identifies relationships between:
        Host -> Service -> Finding -> Risk

    It does NOT perform exploitation.
    """

    def find_paths(self, assets):

        paths = []

        for asset in assets:

            ip = asset.get("ip", "Unknown")
            risk = asset.get("risk", "LOW")
            risk_score = asset.get("risk_score", 0)

            services = asset.get("services", [])
            findings = asset.get("findings", [])

            # ------------------------------------------
            # Ignore hosts with no meaningful exposure
            # ------------------------------------------

            if not services and not findings:
                continue

            # ------------------------------------------
            # HIGH / MEDIUM host risk
            # ------------------------------------------

            if risk in ["HIGH", "MEDIUM"]:

                paths.append({
                    "target": ip,
                    "risk": risk,
                    "risk_score": risk_score,
                    "reason": (
                        f"{risk}-risk asset with "
                        f"potentially exposed services"
                    )
                })

            # ------------------------------------------
            # Service-based paths
            # ------------------------------------------

            for service in services:

                port = service.get(
                    "port",
                    "Unknown"
                )

                service_name = service.get(
                    "service",
                    "Unknown Service"
                )

                # Find findings related to this service
                related_findings = []

                for finding in findings:

                    title = finding.get(
                        "title",
                        ""
                    )

                    # Match common service names
                    if service_name.lower() in title.lower():
                        related_findings.append(
                            finding
                        )

                # --------------------------------------
                # Create service risk path
                # --------------------------------------

                for finding in related_findings:

                    severity = finding.get(
                        "severity",
                        "LOW"
                    )

                    title = finding.get(
                        "title",
                        "Security Finding"
                    )

                    reason = finding.get(
                        "reason",
                        "Security issue detected"
                    )

                    paths.append({
                        "target": ip,
                        "port": port,
                        "service": service_name,
                        "risk": severity,
                        "risk_score": risk_score,
                        "finding": title,
                        "reason": reason
                    })

        return paths