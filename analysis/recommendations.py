class RecommendationEngine:
    """
    Generates security recommendations based on
    detected security findings.
    """

    def generate(self, finding):
        """
        Generate a recommendation for a security finding.
        """

        severity = finding.get(
            "severity",
            "UNKNOWN"
        )

        title = finding.get(
            "title",
            "Unknown Finding"
        )

        # ==========================================
        # FTP
        # ==========================================

        if title == "FTP Service Detected":

            return {
                "priority": severity,
                "recommendation": (
                    "Disable FTP if it is not required. "
                    "Prefer secure file-transfer protocols "
                    "such as SFTP or FTPS."
                )
            }

        # ==========================================
        # SSH
        # ==========================================

        elif title == "SSH Service Detected":

            return {
                "priority": severity,
                "recommendation": (
                    "Restrict SSH access to trusted hosts, "
                    "use strong authentication, disable "
                    "unnecessary authentication methods, "
                    "and keep the SSH service updated."
                )
            }

        # ==========================================
        # Telnet
        # ==========================================

        elif title == "Telnet Service Detected":

            return {
                "priority": severity,
                "recommendation": (
                    "Disable Telnet and use a secure, "
                    "encrypted remote-access protocol "
                    "such as SSH."
                )
            }

        # ==========================================
        # SMTP
        # ==========================================

        elif title == "SMTP Service Detected":

            return {
                "priority": severity,
                "recommendation": (
                    "Restrict SMTP access, prevent "
                    "unauthorized mail relay, require "
                    "appropriate authentication, and "
                    "keep the mail service updated."
                )
            }

        # ==========================================
        # DNS
        # ==========================================

        elif title == "DNS Service Detected":

            return {
                "priority": severity,
                "recommendation": (
                    "Restrict DNS access to trusted hosts, "
                    "avoid unnecessary exposure, and keep "
                    "DNS software updated."
                )
            }

        # ==========================================
        # HTTP
        # ==========================================

        elif title == "HTTP Service Detected":

            return {
                "priority": severity,
                "recommendation": (
                    "Redirect HTTP traffic to HTTPS and "
                    "avoid transmitting sensitive data "
                    "over unencrypted HTTP."
                )
            }

        # ==========================================
        # POP3
        # ==========================================

        elif title == "POP3 Service Detected":

            return {
                "priority": severity,
                "recommendation": (
                    "Prefer encrypted mail retrieval such "
                    "as POP3 over TLS, restrict access where "
                    "possible, and avoid transmitting "
                    "credentials without encryption."
                )
            }

        # ==========================================
        # HTTPS
        # ==========================================

        elif title == "HTTPS Service Detected":

            return {
                "priority": severity,
                "recommendation": (
                    "Keep the TLS configuration secure, "
                    "disable outdated protocols and weak "
                    "cryptographic settings, and use "
                    "currently supported TLS versions."
                )
            }

        # ==========================================
        # SMB
        # ==========================================

        elif title == "SMB Service Detected":

            return {
                "priority": severity,
                "recommendation": (
                    "Restrict SMB access to trusted hosts "
                    "and network segments, disable unnecessary "
                    "SMB exposure, and keep the service patched."
                )
            }

        # ==========================================
        # RDP
        # ==========================================

        elif title == "RDP Service Detected":

            return {
                "priority": severity,
                "recommendation": (
                    "Restrict remote desktop access to "
                    "trusted hosts, use strong authentication, "
                    "and keep the service securely configured "
                    "and updated."
                )
            }

        # ==========================================
        # MySQL
        # ==========================================

        elif title == "MySQL Service Detected":

            return {
                "priority": severity,
                "recommendation": (
                    "Restrict MySQL access to authorized "
                    "application or administration hosts, "
                    "avoid unnecessary network exposure, "
                    "and keep the database software updated."
                )
            }

        # ==========================================
        # PostgreSQL
        # ==========================================

        elif title == "PostgreSQL Service Detected":

            return {
                "priority": severity,
                "recommendation": (
                    "Restrict PostgreSQL access to trusted "
                    "hosts, enforce strong authentication, "
                    "and keep the database software updated."
                )
            }

        # ==========================================
        # Alternative HTTP - 8080
        # ==========================================

        elif title == "HTTP Alternative Service Detected":

            return {
                "priority": severity,
                "recommendation": (
                    "Verify the application running on the "
                    "alternative HTTP port and use HTTPS/TLS "
                    "for sensitive traffic."
                )
            }

        # ==========================================
        # Unknown Finding
        # ==========================================

        return {
            "priority": severity,
            "recommendation": (
                "Review this finding and apply appropriate "
                "security controls based on the affected "
                "service, configuration, and network exposure."
            )
        }