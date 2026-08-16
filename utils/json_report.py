import json
import os
from datetime import datetime


class JsonReport:
    """
    Generates a structured JSON security assessment report
    with automatic timestamped backups.
    """

    REPORT_VERSION = "3.0"

    def save(self, assets):

        # ==========================================
        # REPORT DIRECTORIES
        # ==========================================

        reports_dir = "reports"
        backup_dir = os.path.join(
            reports_dir,
            "backups"
        )

        os.makedirs(
            reports_dir,
            exist_ok=True
        )

        os.makedirs(
            backup_dir,
            exist_ok=True
        )

        # ==========================================
        # TIMESTAMP
        # ==========================================

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        generated_at = datetime.now().isoformat(
            timespec="seconds"
        )

        # ==========================================
        # SUMMARY COUNTERS
        # ==========================================

        total_hosts = len(assets)

        low_hosts = 0
        medium_hosts = 0
        high_hosts = 0
        critical_hosts = 0

        total_open_ports = 0
        total_findings = 0

        low_findings = 0
        medium_findings = 0
        high_findings = 0
        critical_findings = 0

        # ==========================================
        # ANALYZE ASSETS
        # ==========================================

        for asset in assets:

            risk = asset.get(
                "risk",
                "UNKNOWN"
            )

            # --------------------------------------
            # Host Risk
            # --------------------------------------

            if risk == "LOW":
                low_hosts += 1

            elif risk == "MEDIUM":
                medium_hosts += 1

            elif risk == "HIGH":
                high_hosts += 1

            elif risk == "CRITICAL":
                critical_hosts += 1

            # --------------------------------------
            # Open Ports
            # --------------------------------------

            if "open_ports" in asset:

                total_open_ports += len(
                    asset.get(
                        "open_ports",
                        []
                    )
                )

            else:

                total_open_ports += len(
                    asset.get(
                        "services",
                        []
                    )
                )

            # --------------------------------------
            # Findings
            # --------------------------------------

            findings = asset.get(
                "findings",
                []
            )

            total_findings += len(
                findings
            )

            for finding in findings:

                severity = finding.get(
                    "severity",
                    "UNKNOWN"
                )

                if severity == "LOW":
                    low_findings += 1

                elif severity == "MEDIUM":
                    medium_findings += 1

                elif severity == "HIGH":
                    high_findings += 1

                elif severity == "CRITICAL":
                    critical_findings += 1

        # ==========================================
        # REPORT DATA
        # ==========================================

        data = {

            "report": {

                "name": (
                    "Attack Graph "
                    "Security Assessment"
                ),

                "version": self.REPORT_VERSION,

                "generated_at":
                    generated_at,

                "scan_id":
                    timestamp
            },

            "summary": {

                "total_hosts":
                    total_hosts,

                "risk_distribution": {

                    "LOW":
                        low_hosts,

                    "MEDIUM":
                        medium_hosts,

                    "HIGH":
                        high_hosts,

                    "CRITICAL":
                        critical_hosts
                },

                "total_open_ports":
                    total_open_ports,

                "total_findings":
                    total_findings,

                "finding_severity": {

                    "LOW":
                        low_findings,

                    "MEDIUM":
                        medium_findings,

                    "HIGH":
                        high_findings,

                    "CRITICAL":
                        critical_findings
                }
            },

            "hosts": assets
        }

        # ==========================================
        # FILE PATHS
        # ==========================================

        latest_report = os.path.join(
            reports_dir,
            "scan_results.json"
        )

        backup_report = os.path.join(
            backup_dir,
            f"scan_{timestamp}.json"
        )

        # ==========================================
        # SAVE LATEST REPORT
        # ==========================================

        try:

            with open(
                latest_report,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    data,
                    file,
                    indent=4,
                    ensure_ascii=False
                )

        except OSError as error:

            print(
                f"\n[ERROR] "
                f"Could not save latest report: "
                f"{error}"
            )

            return False

        # ==========================================
        # SAVE BACKUP
        # ==========================================

        try:

            with open(
                backup_report,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    data,
                    file,
                    indent=4,
                    ensure_ascii=False
                )

        except OSError as error:

            print(
                f"\n[WARNING] "
                f"Latest report saved, "
                f"but backup failed: "
                f"{error}"
            )

        # ==========================================
        # SUCCESS MESSAGE
        # ==========================================

        print(
            "\n[+] JSON Report "
            "Saved Successfully"
        )

        print(
            f"[+] Latest: "
            f"{latest_report}"
        )

        print(
            f"[+] Backup: "
            f"{backup_report}"
        )

        print(
            f"[+] Hosts: "
            f"{total_hosts}"
        )

        print(
            f"[+] Open Ports: "
            f"{total_open_ports}"
        )

        print(
            f"[+] Findings: "
            f"{total_findings}"
        )

        return True