"""Asset model representing an individual network host."""

from typing import List, Dict, Any, Optional


class Asset:
    """Represents a discovered network asset with associated ports, services, and findings."""

    def __init__(self, ip: str):
        self.ip: str = ip
        self.hostname: Optional[str] = None
        self.os: Optional[str] = None

        self.open_ports: List[int] = []
        self.services: List[Dict[str, Any]] = []
        self.vulnerabilities: List[Dict[str, Any]] = []

        self.risk_score: int = 0
        self.risk: str = "LOW"

    def add_port(self, port: int) -> None:
        """Register an open port on the asset."""
        if port not in self.open_ports:
            self.open_ports.append(port)

    def add_service(self, service: Dict[str, Any]) -> None:
        """Register a discovered service running on the asset."""
        if service not in self.services:
            self.services.append(service)

    def add_vulnerability(self, vulnerability: Dict[str, Any]) -> None:
        """Attach a security finding or vulnerability to the asset."""
        if vulnerability not in self.vulnerabilities:
            self.vulnerabilities.append(vulnerability)

    def set_risk(self, score: int, risk: str) -> None:
        """Update calculated risk score and rating."""
        self.risk_score = score
        self.risk = risk

    def __repr__(self) -> str:
        return f"<Asset ip={self.ip} risk={self.risk} ports={len(self.open_ports)}>"
