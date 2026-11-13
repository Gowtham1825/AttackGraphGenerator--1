"""Security findings engine for evaluating network service exposure."""

from typing import List, Dict, Any


class SecurityFindings:
    """Evaluates security exposure and baseline risks for discovered network services."""

    RULES: Dict[int, Dict[str, str]] = {
        21: {
            "severity": "HIGH",
            "title": "FTP Service Detected",
            "reason": "FTP transmits credentials in plaintext depending on configuration. Consider SFTP or FTPS.",
        },
        22: {
            "severity": "LOW",
            "title": "SSH Service Detected",
            "reason": "SSH is exposed for remote administration. Ensure strong key-based auth and rate-limiting.",
        },
        23: {
            "severity": "HIGH",
            "title": "Telnet Service Detected",
            "reason": "Legacy Telnet protocol provides unencrypted remote administration. Prefer SSH.",
        },
        25: {
            "severity": "MEDIUM",
            "title": "SMTP Service Detected",
            "reason": "SMTP is exposed. Verify mail relay controls to prevent unauthorized relay abuse.",
        },
        53: {
            "severity": "LOW",
            "title": "DNS Service Detected",
            "reason": "DNS service detected. Check zone transfer restrictions and recursion settings.",
        },
        80: {
            "severity": "MEDIUM",
            "title": "HTTP Service Detected",
            "reason": "Cleartext HTTP traffic detected. Enforce HTTPS / TLS redirection for sensitive data.",
        },
        110: {
            "severity": "MEDIUM",
            "title": "POP3 Service Detected",
            "reason": "Cleartext POP3 mail retrieval service exposed without mandatory TLS.",
        },
        443: {
            "severity": "LOW",
            "title": "HTTPS Service Detected",
            "reason": "HTTPS service is available. Review certificate validity and modern cipher suites.",
        },
        445: {
            "severity": "HIGH",
            "title": "SMB Service Detected",
            "reason": "SMB is exposed to the network. Restrict access to trusted subnets to mitigate lateral movement.",
        },
        3306: {
            "severity": "HIGH",
            "title": "MySQL Service Detected",
            "reason": "Database server exposed externally. Restrict listening interfaces and configure firewalls.",
        },
        3389: {
            "severity": "MEDIUM",
            "title": "RDP Service Detected",
            "reason": "Remote Desktop Protocol exposed. Enforce NLA, MFA, and trusted network isolation.",
        },
        5432: {
            "severity": "HIGH",
            "title": "PostgreSQL Service Detected",
            "reason": "PostgreSQL database port exposed. Ensure pg_hba.conf restricts unauthorized CIDRs.",
        },
        8080: {
            "severity": "MEDIUM",
            "title": "HTTP Alternative Service Detected",
            "reason": "Alternative web port exposed without default TLS encapsulation.",
        },
    }

    def analyze(self, port: int) -> List[Dict[str, Any]]:
        finding = self.RULES.get(port)
        if not finding:
            return []

        return [{
            "port": port,
            "severity": finding["severity"],
            "title": finding["title"],
            "reason": finding["reason"],
        }]
