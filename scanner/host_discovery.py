"""Host discovery scanner supporting parallel ICMP ping and TCP fallback probing."""

import ipaddress
import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Callable, Optional


class HostDiscovery:
    """Discovers active network hosts via ICMP ping and fast TCP handshake fallback."""

    def __init__(self):
        self.online_hosts: List[str] = []

    def ping_host(self, ip: str) -> bool:
        """Perform ICMP ping check."""
        system = platform.system().lower()
        if system == "windows":
            command = ["ping", "-n", "1", "-w", "800", ip]
        else:
            command = ["ping", "-c", "1", "-W", "1", ip]

        try:
            result = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=1.5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def is_host_alive(self, ip: str) -> bool:
        """Check if host is reachable via loopback, ping, or TCP port response."""
        # 1. Loopback is always active
        if ip.startswith("127.") or ip in ("localhost", "::1"):
            return True

        # 2. ICMP ping check
        if self.ping_host(ip):
            return True

        # 3. Fallback TCP probe (if ICMP is blocked by firewall or container)
        for port in (80, 443, 22, 445, 135, 8080, 8501):
            try:
                with socket.create_connection((ip, port), timeout=0.25):
                    return True
            except OSError:
                pass

        return False

    def scan(
        self,
        network: str,
        on_host_found: Optional[Callable[[str], None]] = None,
        on_progress: Optional[Callable[[int, int, str, bool], None]] = None,
    ) -> List[str]:
        """Scan network or single IP and return discovered active hosts."""
        self.online_hosts = []
        network = network.strip()

        # Parse target CIDR or single IP
        if "/" in network:
            try:
                network_obj = ipaddress.ip_network(network, strict=False)
                ips = [str(ip) for ip in network_obj.hosts()]
                if not ips:
                    ips = [str(network_obj.network_address)]
            except ValueError:
                return []
        else:
            try:
                ip_obj = ipaddress.ip_address(network)
                ips = [str(ip_obj)]
            except ValueError:
                # Fallback for shorthand e.g. 192.168.1
                parts = network.split(".")
                if len(parts) == 3:
                    ips = [f"{network}.{i}" for i in range(1, 255)]
                else:
                    return []

        if not ips:
            return []

        # If scanning a single IP, check directly without massive threadpool
        if len(ips) == 1:
            ip = ips[0]
            alive = self.is_host_alive(ip)
            if alive:
                self.online_hosts.append(ip)
                if on_host_found:
                    on_host_found(ip)
            return self.online_hosts

        # Parallel scan across subnet
        completed = 0
        total = len(ips)
        max_workers = min(120, max(20, len(ips)))

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.is_host_alive, ip): ip for ip in ips}

            for future in as_completed(futures):
                ip = futures[future]
                is_online = False
                try:
                    is_online = future.result()
                except Exception:
                    is_online = False

                completed += 1
                if is_online:
                    self.online_hosts.append(ip)
                    if on_host_found:
                        try:
                            on_host_found(ip)
                        except Exception:
                            pass

                if on_progress:
                    try:
                        on_progress(completed, total, ip, is_online)
                    except Exception:
                        pass

        try:
            self.online_hosts.sort(key=ipaddress.ip_address)
        except Exception:
            self.online_hosts.sort()

        return self.online_hosts
