import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


class PortScanner:

    def __init__(self):
        # Full TCP port range
        self.start_port = 1
        self.end_port = 65535

        # Concurrent workers
        self.max_workers = 200

        # Connection timeout
        self.timeout = 0.2

    def scan_port(self, ip, port):
        """Check whether a TCP port is open."""

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        try:
            sock.settimeout(self.timeout)

            result = sock.connect_ex(
                (ip, port)
            )

            if result == 0:
                return port

            return None

        except (socket.timeout, socket.error, OSError):
            return None

        finally:
            sock.close()

    def scan(self, ip):
        """Scan all TCP ports and return only open ports."""

        open_ports = []

        total_ports = (
            self.end_port - self.start_port + 1
        )

        print(f"\n[*] Target: {ip}")
        print(
            f"[*] TCP Scan: "
            f"{self.start_port}-{self.end_port}"
        )
        print(
            f"[*] Workers: {self.max_workers}"
        )
        print()

        ports = range(
            self.start_port,
            self.end_port + 1
        )

        with ThreadPoolExecutor(
            max_workers=self.max_workers
        ) as executor:

            futures = {
                executor.submit(
                    self.scan_port,
                    ip,
                    port
                ): port
                for port in ports
            }

            completed = 0

            for future in as_completed(futures):

                try:
                    result = future.result()

                except Exception:
                    result = None

                completed += 1

                if result is not None:
                    open_ports.append(result)

                    print(
                        f"[+] {ip}:{result} OPEN"
                    )

                # Progress every 5%
                if (
                    completed % max(
                        1,
                        total_ports // 20
                    ) == 0
                ):
                    progress = (
                        completed /
                        total_ports
                    ) * 100

                    print(
                        f"[*] Progress: "
                        f"{progress:.0f}%"
                    )

        open_ports.sort()

        print("\n" + "=" * 45)

        if open_ports:
            print(
                f"[+] Open ports on {ip}:"
            )

            for port in open_ports:
                print(
                    f"    {port}/tcp OPEN"
                )

        else:
            print(
                f"[-] No open TCP ports found "
                f"on {ip}"
            )

        print("=" * 45)

        return open_ports