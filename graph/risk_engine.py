class RiskEngine:
    """
    Calculates explainable security risk for a network asset.

    This is a heuristic exposure model.
    It does NOT confirm exploitable vulnerabilities.
    """

    # ==========================================
    # PORT RISK WEIGHTS
    # ==========================================

    PORT_WEIGHTS = {

        # High-risk / legacy
        21: 4,       # FTP
        23: 5,       # Telnet
        445: 4,      # SMB
        3389: 4,     # RDP

        # Remote administration
        22: 2,       # SSH

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

    # ==========================================
    # FINDING SEVERITY
    # ==========================================

    SEVERITY_WEIGHTS = {
        "LOW": 1,
        "MEDIUM": 3,
        "HIGH": 5,
        "CRITICAL": 8
    }

    # ==========================================
    # CALCULATE SCORE
    # ==========================================

    def calculate_score(self, asset):

        score = 0

        open_ports = getattr(
            asset,
            "open_ports",
            []
        )

        findings = getattr(
            asset,
            "vulnerabilities",
            []
        )

        # --------------------------------------
        # Port Exposure
        # --------------------------------------

        for port in open_ports:

            # Known ports get their configured weight.
            # Unknown ports get 0 instead of 1.
            score += self.PORT_WEIGHTS.get(
                port,
                0
            )

        # --------------------------------------
        # Finding Severity
        # --------------------------------------

        for finding in findings:

            severity = finding.get(
                "severity",
                "LOW"
            ).upper()

            score += self.SEVERITY_WEIGHTS.get(
                severity,
                0
            )

        return score

    # ==========================================
    # CALCULATE RISK LEVEL
    # ==========================================

    def calculate_risk(self, asset):

        score = self.calculate_score(asset)

        if score >= 15:
            return "HIGH"

        elif score >= 6:
            return "MEDIUM"

        else:
            return "LOW"

    # ==========================================
    # DETAILED ANALYSIS
    # ==========================================

    def analyze(self, asset):

        open_ports = getattr(
            asset,
            "open_ports",
            []
        )

        findings = getattr(
            asset,
            "vulnerabilities",
            []
        )

        # --------------------------------------
        # Port score
        # --------------------------------------

        port_score = 0

        high_risk_ports = []

        for port in open_ports:

            weight = self.PORT_WEIGHTS.get(
                port,
                0
            )

            port_score += weight

            if weight >= 4:
                high_risk_ports.append(port)

        # --------------------------------------
        # Finding score
        # --------------------------------------

        finding_score = 0

        finding_severities = {
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 0
        }

        for finding in findings:

            severity = finding.get(
                "severity",
                "LOW"
            ).upper()

            weight = self.SEVERITY_WEIGHTS.get(
                severity,
                0
            )

            finding_score += weight

            if severity in finding_severities:
                finding_severities[severity] += 1

        # --------------------------------------
        # Final score
        # --------------------------------------

        score = (
            port_score +
            finding_score
        )

        # --------------------------------------
        # Risk level
        # --------------------------------------

        if score >= 15:
            risk = "HIGH"

        elif score >= 6:
            risk = "MEDIUM"

        else:
            risk = "LOW"

        return {
            "score": score,
            "risk": risk,

            "port_score": port_score,
            "finding_score": finding_score,

            "open_ports": len(open_ports),

            "high_risk_ports": high_risk_ports,

            "finding_severity": finding_severities
        }