class ServiceDetection:
    """
    Detects commonly used TCP services and estimates
    the likely operating system from discovered ports.

    Service detection is primarily port-based.

    OS detection is heuristic and does NOT guarantee
    the actual operating system.
    """

    # ==========================================
    # COMMON TCP SERVICES
    # ==========================================

    SERVICES = {
        # Remote Access
        22: "SSH",
        23: "TELNET",
        3389: "RDP",
        5900: "VNC",
        5985: "WINRM-HTTP",
        5986: "WINRM-HTTPS",
        # File Transfer
        20: "FTP-DATA",
        21: "FTP",
        69: "TFTP",
        989: "FTPS-DATA",
        990: "FTPS",
        # Mail
        25: "SMTP",
        110: "POP3",
        143: "IMAP",
        465: "SMTPS",
        587: "SMTP-SUBMISSION",
        993: "IMAPS",
        995: "POP3S",
        # Network Services
        53: "DNS",
        123: "NTP",
        161: "SNMP",
        # Web
        80: "HTTP",
        443: "HTTPS",
        8000: "HTTP-ALT",
        8008: "HTTP-ALT",
        8080: "HTTP-ALT",
        8081: "HTTP-ALT",
        8443: "HTTPS-ALT",
        # Windows
        135: "MSRPC",
        139: "NETBIOS-SSN",
        445: "SMB",
        # Databases
        1433: "MSSQL",
        1521: "ORACLE",
        3306: "MYSQL",
        5432: "POSTGRESQL",
        6379: "REDIS",
        27017: "MONGODB",
        # Directory Services
        389: "LDAP",
        636: "LDAPS",
    }

    # ==========================================
    # SERVICE CATEGORIES
    # ==========================================

    SERVICE_CATEGORIES = {
        "SSH": "REMOTE_ACCESS",
        "TELNET": "REMOTE_ACCESS",
        "RDP": "REMOTE_ACCESS",
        "VNC": "REMOTE_ACCESS",
        "WINRM-HTTP": "REMOTE_MANAGEMENT",
        "WINRM-HTTPS": "REMOTE_MANAGEMENT",
        "FTP": "FILE_TRANSFER",
        "FTP-DATA": "FILE_TRANSFER",
        "TFTP": "FILE_TRANSFER",
        "FTPS": "FILE_TRANSFER",
        "FTPS-DATA": "FILE_TRANSFER",
        "SMTP": "MAIL",
        "SMTP-SUBMISSION": "MAIL",
        "SMTPS": "MAIL",
        "POP3": "MAIL",
        "POP3S": "MAIL",
        "IMAP": "MAIL",
        "IMAPS": "MAIL",
        "DNS": "NETWORK_SERVICE",
        "NTP": "NETWORK_SERVICE",
        "SNMP": "NETWORK_SERVICE",
        "HTTP": "WEB",
        "HTTPS": "WEB",
        "HTTP-ALT": "WEB",
        "HTTPS-ALT": "WEB",
        "MSRPC": "WINDOWS",
        "NETBIOS-SSN": "WINDOWS",
        "SMB": "WINDOWS",
        "MSSQL": "DATABASE",
        "ORACLE": "DATABASE",
        "MYSQL": "DATABASE",
        "POSTGRESQL": "DATABASE",
        "REDIS": "DATABASE",
        "MONGODB": "DATABASE",
        "LDAP": "DIRECTORY_SERVICE",
        "LDAPS": "DIRECTORY_SERVICE",
    }

    # ==========================================
    # DETECT SERVICE
    # ==========================================

    def detect(self, port):
        """
        Return the expected service for a TCP port.
        """

        return self.SERVICES.get(port, "UNKNOWN")

    # ==========================================
    # GET SERVICE CATEGORY
    # ==========================================

    def get_category(self, port):
        """
        Return the category of the detected service.
        """

        service = self.detect(port)

        return self.SERVICE_CATEGORIES.get(service, "UNKNOWN")

    # ==========================================
    # GET SERVICE INFORMATION
    # ==========================================

    def get_info(self, port):
        """
        Return structured information about a port.
        """

        service = self.detect(port)

        category = self.get_category(port)

        if service == "UNKNOWN":
            confidence = "LOW"
        else:
            confidence = "HIGH"

        return {
            "port": port,
            "service": service,
            "category": category,
            "detection": "PORT_BASED",
            "confidence": confidence,
        }

    # ==========================================
    # OS DETECTION
    # ==========================================

    def detect_os(self, open_ports):
        """
        Estimate the likely operating system from
        discovered TCP ports.

        This is heuristic detection.
        It does NOT guarantee the actual OS.
        """

        # --------------------------------------
        # OS indicators
        # --------------------------------------

        windows_ports = {135, 139, 445, 3389, 5985, 5986}

        linux_ports = {22, 111, 631, 2049}

        network_device_ports = {53, 161, 162, 7547}

        # --------------------------------------
        # Initial scores
        # --------------------------------------

        scores = {"Windows": 0, "Linux": 0, "Network Device": 0}

        # --------------------------------------
        # Calculate OS score
        # --------------------------------------

        for port in open_ports:

            if port in windows_ports:
                scores["Windows"] += 2

            if port in linux_ports:
                scores["Linux"] += 2

            if port in network_device_ports:
                scores["Network Device"] += 2

        # --------------------------------------
        # No OS indicators
        # --------------------------------------

        highest_score = max(scores.values())

        if highest_score == 0:

            return {
                "os": "Unknown",
                "confidence": "LOW",
                "method": "PORT_HEURISTIC",
                "scores": scores,
            }

        # --------------------------------------
        # Find highest scoring OS
        # --------------------------------------

        detected_os = max(scores, key=scores.get)

        # --------------------------------------
        # Confidence
        # --------------------------------------

        if highest_score >= 4:
            confidence = "HIGH"
        else:
            confidence = "MEDIUM"

        # --------------------------------------
        # Return result
        # --------------------------------------

        return {
            "os": detected_os,
            "confidence": confidence,
            "method": "PORT_HEURISTIC",
            "scores": scores,
        }
