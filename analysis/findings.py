class SecurityFindings:
    """
    Detects security findings from exposed network services.

    Note:
    An open port does not automatically mean a vulnerability.
    These findings represent security exposure / configuration
    considerations that should be reviewed.
    """

    def analyze(self, port):

        findings = []

        # ==========================================
        # FTP - Port 21
        # ==========================================

        if port == 21:

            findings.append({
                "port": port,
                "severity": "HIGH",
                "title": "FTP Service Detected",
                "reason": (
                    "FTP is exposed and may transmit credentials "
                    "without encryption depending on configuration."
                )
            })

        # ==========================================
        # SSH - Port 22
        # ==========================================

        elif port == 22:

            findings.append({
                "port": port,
                "severity": "LOW",
                "title": "SSH Service Detected",
                "reason": (
                    "SSH is exposed for remote administration. "
                    "Access should be restricted to trusted hosts "
                    "and securely configured."
                )
            })

        # ==========================================
        # Telnet - Port 23
        # ==========================================

        elif port == 23:

            findings.append({
                "port": port,
                "severity": "HIGH",
                "title": "Telnet Service Detected",
                "reason": (
                    "Telnet provides remote access without "
                    "modern transport encryption."
                )
            })

        # ==========================================
        # SMTP - Port 25
        # ==========================================

        elif port == 25:

            findings.append({
                "port": port,
                "severity": "MEDIUM",
                "title": "SMTP Service Detected",
                "reason": (
                    "SMTP is exposed and should be securely "
                    "configured to prevent unauthorized mail "
                    "relay and abuse."
                )
            })

        # ==========================================
        # DNS - Port 53
        # ==========================================

        elif port == 53:

            findings.append({
                "port": port,
                "severity": "LOW",
                "title": "DNS Service Detected",
                "reason": (
                    "DNS is exposed on this host and should "
                    "be securely configured and restricted "
                    "where appropriate."
                )
            })

        # ==========================================
        # HTTP - Port 80
        # ==========================================

        elif port == 80:

            findings.append({
                "port": port,
                "severity": "MEDIUM",
                "title": "HTTP Service Detected",
                "reason": (
                    "HTTP traffic is not protected by TLS. "
                    "Sensitive information should not be "
                    "transmitted over unencrypted HTTP."
                )
            })

        # ==========================================
        # POP3 - Port 110
        # ==========================================

        elif port == 110:

            findings.append({
                "port": port,
                "severity": "MEDIUM",
                "title": "POP3 Service Detected",
                "reason": (
                    "POP3 may expose email authentication "
                    "traffic if encryption is not configured."
                )
            })

        # ==========================================
        # HTTPS - Port 443
        # ==========================================

        elif port == 443:

            findings.append({
                "port": port,
                "severity": "LOW",
                "title": "HTTPS Service Detected",
                "reason": (
                    "HTTPS is available. TLS configuration, "
                    "certificate validity, and supported "
                    "protocols should be reviewed."
                )
            })

        # ==========================================
        # SMB - Port 445
        # ==========================================

        elif port == 445:

            findings.append({
                "port": port,
                "severity": "HIGH",
                "title": "SMB Service Detected",
                "reason": (
                    "SMB is exposed and should be restricted "
                    "to trusted hosts or network segments. "
                    "The service should be kept patched."
                )
            })

        # ==========================================
        # RDP - Port 3389
        # ==========================================

        elif port == 3389:

            findings.append({
                "port": port,
                "severity": "MEDIUM",
                "title": "RDP Service Detected",
                "reason": (
                    "Remote Desktop is exposed and should "
                    "be restricted to trusted hosts with "
                    "strong authentication and secure "
                    "configuration."
                )
            })

        # ==========================================
        # MySQL - Port 3306
        # ==========================================

        elif port == 3306:

            findings.append({
                "port": port,
                "severity": "HIGH",
                "title": "MySQL Service Detected",
                "reason": (
                    "MySQL is exposed to the network and "
                    "should normally be restricted to "
                    "authorized application or administration "
                    "hosts."
                )
            })

        # ==========================================
        # PostgreSQL - Port 5432
        # ==========================================

        elif port == 5432:

            findings.append({
                "port": port,
                "severity": "HIGH",
                "title": "PostgreSQL Service Detected",
                "reason": (
                    "PostgreSQL is exposed and should be "
                    "restricted to trusted hosts and "
                    "securely configured."
                )
            })

        # ==========================================
        # Alternative HTTP - Port 8080
        # ==========================================

        elif port == 8080:

            findings.append({
                "port": port,
                "severity": "MEDIUM",
                "title": "HTTP Alternative Service Detected",
                "reason": (
                    "An HTTP service is exposed on an "
                    "alternative web port. Verify that "
                    "sensitive traffic is protected with TLS."
                )
            })

        return findings