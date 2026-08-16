class Asset:
    """
    Represents a discovered network asset.

    Stores host identity, exposed ports, detected services,
    security findings, and calculated risk information.
    """

    def __init__(self, ip):
        self.ip = ip
        self.hostname = None
        self.os = None

        self.open_ports = []
        self.services = []
        self.vulnerabilities = []

        self.risk_score = 0
        self.risk = "LOW"

    # ==========================================
    # PORT MANAGEMENT
    # ==========================================

    def add_port(self, port):
        """Add an open port to the asset."""
        if port not in self.open_ports:
            self.open_ports.append(port)

    # ==========================================
    # SERVICE MANAGEMENT
    # ==========================================

    def add_service(self, service):
        """Add a detected service to the asset."""
        if service not in self.services:
            self.services.append(service)

    # ==========================================
    # VULNERABILITY MANAGEMENT
    # ==========================================

    def add_vulnerability(self, vulnerability):
        """Add a security finding to the asset."""
        if vulnerability not in self.vulnerabilities:
            self.vulnerabilities.append(vulnerability)

    # ==========================================
    # RISK MANAGEMENT
    # ==========================================

    def set_risk(self, score, risk):
        """Set the calculated risk score and risk level."""
        self.risk_score = score
        self.risk = risk

    # ==========================================
    # REPRESENTATION
    # ==========================================

    def __repr__(self):
        return (
            f"Asset("
            f"ip='{self.ip}', "
            f"ports={self.open_ports}, "
            f"risk='{self.risk}', "
            f"score={self.risk_score}"
            f")"
        )