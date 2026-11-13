"""Recommendation engine for generating actionable security remediations."""

from typing import Dict, Any


class RecommendationEngine:
    """Generates remediation advice based on discovered security findings."""

    RECOMMENDATIONS: Dict[str, str] = {
        "FTP Service Detected": (
            "Disable FTP if not required. Migrate to secure protocols such as SFTP or FTPS."
        ),
        "SSH Service Detected": (
            "Restrict SSH access to trusted IPs, enforce key-based authentication, "
            "disable root login, and keep OpenSSH updated."
        ),
        "Telnet Service Detected": (
            "Decommission Telnet immediately in favor of SSH to prevent credential sniffing."
        ),
        "SMTP Service Detected": (
            "Enforce STARTTLS, restrict open relay configuration, and require strong authentication."
        ),
        "DNS Service Detected": (
            "Restrict DNS recursion to internal clients, disable open zone transfers, and patch daemon."
        ),
        "HTTP Service Detected": (
            "Implement automatic 301 redirection to HTTPS and enable HSTS."
        ),
        "POP3 Service Detected": (
            "Require POP3 over TLS (port 995) or migrate users to IMAPS/modern webmail."
        ),
        "HTTPS Service Detected": (
            "Audit TLS configuration with SSL Labs, disable legacy TLS 1.0/1.1, and monitor certificate expiry."
        ),
        "SMB Service Detected": (
            "Block port 445 at boundary firewalls, disable SMBv1, and enable SMB signing."
        ),
        "RDP Service Detected": (
            "Place RDP behind a VPN or RD Gateway, require Network Level Authentication (NLA) and MFA."
        ),
        "MySQL Service Detected": (
            "Bind MySQL to 127.0.0.1 or internal VPC interface, and enforce strong user credentials."
        ),
        "PostgreSQL Service Detected": (
            "Ensure pg_hba.conf only permits trusted application hosts and require SSL connections."
        ),
        "HTTP Alternative Service Detected": (
            "Verify what application is running on port 8080 and enforce reverse proxying via HTTPS."
        ),
    }

    def generate(self, finding: Dict[str, Any]) -> Dict[str, str]:
        severity = finding.get("severity", "UNKNOWN")
        title = finding.get("title", "Unknown Finding")

        recommendation = self.RECOMMENDATIONS.get(
            title,
            "Review this service exposure and apply principle of least privilege access controls."
        )

        return {
            "priority": severity,
            "recommendation": recommendation,
        }
