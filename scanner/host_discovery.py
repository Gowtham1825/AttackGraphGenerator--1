import subprocess
import platform
import ipaddress

from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import Progress


class HostDiscovery:

    def __init__(self):
        self.online_hosts = []

    def ping_host(self, ip):

        system = platform.system().lower()

        if system == "windows":
            command = [
                "ping",
                "-n",
                "1",
                "-w",
                "1000",
                ip
            ]

        else:
            command = [
                "ping",
                "-c",
                "1",
                "-W",
                "1",
                ip
            ]

        try:

            result = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            return result.returncode == 0

        except (
            subprocess.SubprocessError,
            OSError
        ):

            return False

    def scan(self, network):

        print("\n========== HOST DISCOVERY ==========")
        print(
            f"[*] Target Network: {network}"
        )

        # Reset results for every scan
        self.online_hosts = []

        # ==========================================
        # NETWORK PARSING
        # ==========================================

        if "/" in network:

            try:

                network_obj = ipaddress.ip_network(
                    network,
                    strict=False
                )

                ips = [
                    str(ip)
                    for ip in network_obj.hosts()
                ]

            except ValueError:

                print(
                    "ERROR: Invalid network format."
                )

                return []

        else:

            # Backward compatibility
            # Example: 192.168.1

            ips = [
                f"{network}.{i}"
                for i in range(1, 255)
            ]

        if not ips:

            print(
                "ERROR: No hosts found in network."
            )

            return []

        print(
            f"[*] Hosts to discover: {len(ips)}"
        )

        print(
            "[*] Starting parallel host discovery...\n"
        )

        # ==========================================
        # PARALLEL HOST DISCOVERY
        # ==========================================

        with Progress() as progress:

            task = progress.add_task(
                "[cyan]Discovering hosts...",
                total=len(ips)
            )

            with ThreadPoolExecutor(
                max_workers=100
            ) as executor:

                futures = {
                    executor.submit(
                        self.ping_host,
                        ip
                    ): ip
                    for ip in ips
                }

                for future in as_completed(
                    futures
                ):

                    ip = futures[future]

                    try:

                        is_online = future.result()

                    except Exception:

                        is_online = False

                    if is_online:

                        print(
                            f"[green][+][/green] "
                            f"{ip} Online"
                        )

                        self.online_hosts.append(
                            ip
                        )

                    progress.update(
                        task,
                        advance=1
                    )

        # ==========================================
        # SORT RESULTS
        # ==========================================

        try:

            self.online_hosts.sort(
                key=ipaddress.ip_address
            )

        except ValueError:

            self.online_hosts.sort()

        # ==========================================
        # SUMMARY
        # ==========================================

        print(
            "\n========== DISCOVERY RESULT =========="
        )

        print(
            f"[+] Active Hosts: "
            f"{len(self.online_hosts)}"
        )

        for ip in self.online_hosts:

            print(
                f"    {ip}"
            )

        print(
            "======================================"
        )

        return self.online_hosts