class AttackPath:
    """
    Analyzes discovered assets and identifies potential
    security risk paths.

    Path model:

        HOST
          ↓
      OPEN PORT
          ↓
       FINDING
          ↓
       RISK

    This is a defensive risk-analysis model.
    It does not perform exploitation.
    """

    SEVERITY_WEIGHT = {
        "LOW": 1,
        "MEDIUM": 3,
        "HIGH": 5,
        "CRITICAL": 8
    }

    def __init__(self):

        self.paths = []

    # ==================================================
    # FIND POTENTIAL PATHS
    # ==================================================

    def find_paths(self, assets):

        self.paths = []

        for asset in assets:

            ip = asset.get(
                "ip",
                "Unknown"
            )

            risk = asset.get(
                "risk",
                "LOW"
            )

            risk_score = asset.get(
                "risk_score",
                0
            )

            services = asset.get(
                "services",
                []
            )

            findings = asset.get(
                "findings",
                []
            )

            # ------------------------------------------
            # Finding-based paths
            # ------------------------------------------

            for finding in findings:

                severity = finding.get(
                    "severity",
                    "LOW"
                )

                title = finding.get(
                    "title",
                    "Unknown Finding"
                )

                reason = finding.get(
                    "reason",
                    "No reason provided."
                )

                # Find related port
                related_port = self._find_port(
                    finding,
                    services
                )

                path_risk = self._calculate_path_risk(
                    severity,
                    risk
                )

                self.paths.append({
                    "source": ip,
                    "target": title,
                    "port": related_port,
                    "risk": path_risk,
                    "risk_score": risk_score,
                    "reason": reason,
                    "path": self._build_path(
                        ip,
                        related_port,
                        title
                    )
                })

            # ------------------------------------------
            # Host-level risk path
            # ------------------------------------------

            if not findings and risk in (
                "MEDIUM",
                "HIGH",
                "CRITICAL"
            ):

                self.paths.append({
                    "source": ip,
                    "target": ip,
                    "port": None,
                    "risk": risk,
                    "risk_score": risk_score,
                    "reason": (
                        "Host has elevated risk "
                        "based on exposed services."
                    ),
                    "path": [
                        ip,
                        "Elevated Risk"
                    ]
                })

        return self.paths

    # ==================================================
    # FIND RELATED PORT
    # ==================================================

    def _find_port(
        self,
        finding,
        services
    ):

        title = finding.get(
            "title",
            ""
        )

        service_map = {
            "FTP Service Detected": 21,
            "SSH Service Detected": 22,
            "Telnet Service Detected": 23,
            "SMTP Service Detected": 25,
            "DNS Service Detected": 53,
            "HTTP Service Detected": 80,
            "POP3 Service Detected": 110,
            "IMAP Service Detected": 143,
            "HTTPS Service Detected": 443,
            "MYSQL Service Detected": 3306,
            "RDP Service Detected": 3389,
            "SMB Service Detected": 445,
            "PostgreSQL Service Detected": 5432
        }

        expected_port = service_map.get(
            title
        )

        if expected_port is not None:
            return expected_port

        # Fallback: inspect service information
        for service in services:

            if not isinstance(
                service,
                dict
            ):
                continue

            if service.get(
                "service",
                ""
            ).upper() in title.upper():

                return service.get(
                    "port"
                )

        return None

    # ==================================================
    # CALCULATE PATH RISK
    # ==================================================

    def _calculate_path_risk(
        self,
        finding_severity,
        host_risk
    ):

        finding_weight = self.SEVERITY_WEIGHT.get(
            finding_severity,
            0
        )

        host_weight = self.SEVERITY_WEIGHT.get(
            host_risk,
            0
        )

        highest_weight = max(
            finding_weight,
            host_weight
        )

        if highest_weight >= 8:
            return "CRITICAL"

        elif highest_weight >= 5:
            return "HIGH"

        elif highest_weight >= 3:
            return "MEDIUM"

        return "LOW"

    # ==================================================
    # BUILD PATH
    # ==================================================

    def _build_path(
        self,
        ip,
        port,
        finding
    ):

        path = [
            ip
        ]

        if port is not None:

            path.append(
                f"Port {port}"
            )

        path.append(
            finding
        )

        path.append(
            "Potential Risk"
        )

        return path

    # ==================================================
    # GET HIGHEST RISK PATH
    # ==================================================

    def get_highest_risk_path(self):

        if not self.paths:
            return None

        priority = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4
        }

        return max(
            self.paths,
            key=lambda path:
                priority.get(
                    path.get("risk"),
                    0
                )
        )

    # ==================================================
    # SUMMARY
    # ==================================================

    def summary(self):

        summary = {
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 0
        }

        for path in self.paths:

            risk = path.get(
                "risk",
                "LOW"
            )

            if risk in summary:
                summary[risk] += 1

        return summary