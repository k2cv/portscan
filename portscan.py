"""Async port scanner and service prober.

Copyright (c) 2026 Soar. All rights reserved.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import random
import socket
import ssl
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

console = Console()

TOP_100_PORTS: List[int] = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 162, 179, 389, 443, 445, 465, 500, 514, 515, 520, 587, 631, 636, 873,
    990, 993, 995, 1080, 1194, 1433, 1434, 1521, 1723, 1883, 2049, 2082, 2083, 2086,
    2087, 2181, 2222, 3000, 3128, 3306, 3389, 4000, 4443, 5000, 5432, 5672, 5900,
    5985, 5986, 6379, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9092,
    9200, 9300, 9418, 9999, 10000, 11211, 27017, 27018, 28017, 50000
]

SERVICES: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPCBind", 123: "NTP", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "Submission",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle",
    2049: "NFS", 3000: "Node", 3306: "MySQL", 3389: "RDP", 5000: "Flask",
    5432: "PostgreSQL", 5672: "RabbitMQ", 5900: "VNC", 6379: "Redis", 8000: "HTTP-Alt",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9000: "FastCGI", 9092: "Kafka",
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB"
}


@dataclass
class PortResult:
    port: int
    state: str
    service: str
    latency_ms: float
    banner: str = ""
    tls_info: str = ""


@dataclass
class ScanReport:
    target: str
    ip: str
    start_time: str
    duration_seconds: float
    total_ports_scanned: int
    open_ports_count: int
    results: List[PortResult]


class PortScanner:
    def __init__(
        self,
        target: str,
        ports: Sequence[int],
        concurrency: int = 150,
        timeout: float = 1.0,
        grab_banners: bool = True,
        check_tls: bool = True,
        shuffle: bool = False,
    ):
        self.target = target
        self.ports = list(ports)
        if shuffle:
            random.shuffle(self.ports)
        self.concurrency = concurrency
        self.timeout = timeout
        self.grab_banners = grab_banners
        self.check_tls = check_tls
        self.target_ip = ""
        self.semaphore = asyncio.Semaphore(concurrency)

    def resolve(self) -> str:
        try:
            self.target_ip = socket.gethostbyname(self.target)
            return self.target_ip
        except socket.gaierror as e:
            raise RuntimeError(f"Cannot resolve '{self.target}': {e}") from e

    async def _fetch_banner(self, port: int) -> str:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_ip, port),
                timeout=self.timeout
            )
            if port in (80, 8080, 8000, 3000, 5000):
                probe = f"HEAD / HTTP/1.1\r\nHost: {self.target}\r\nUser-Agent: PortScan\r\n\r\n"
                writer.write(probe.encode("latin-1"))
                await writer.drain()
            elif port not in (21, 22, 25, 110, 143):
                writer.write(b"\r\n")
                await writer.drain()

            data = await asyncio.wait_for(reader.read(512), timeout=1.0)
            writer.close()
            await writer.wait_closed()

            for line in data.decode("utf-8", errors="replace").splitlines():
                cleaned = line.strip()
                if not cleaned:
                    continue
                if cleaned.lower().startswith("server:"):
                    return cleaned
                if cleaned.startswith("SSH-") or cleaned.startswith("220"):
                    return cleaned[:80]
                return cleaned[:80]
            return ""
        except (OSError, asyncio.TimeoutError):
            return ""

    async def _fetch_tls_details(self, port: int) -> str:
        if port not in (443, 8443, 9443, 465, 993, 995) and not self.check_tls:
            return ""

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            _, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_ip, port, ssl=ctx, server_hostname=self.target),
                timeout=self.timeout + 0.5
            )
            ssl_obj = writer.get_extra_info("ssl_object")
            info = ""
            if ssl_obj:
                cipher = ssl_obj.cipher()
                version = ssl_obj.version()
                cert = ssl_obj.getpeercert(binary_form=False)
                subject = ""
                if cert and "subject" in cert:
                    for sub in cert["subject"]:
                        for k, v in sub:
                            if k == "commonName":
                                subject = f"CN={v}"
                info = f"{version} ({cipher[0] if cipher else 'TLS'}) {subject}".strip()

            writer.close()
            await writer.wait_closed()
            return info
        except (OSError, asyncio.TimeoutError, ssl.SSLError):
            return ""

    async def probe_port(self, port: int, progress: Progress, task_id: Any) -> Optional[PortResult]:
        async with self.semaphore:
            start = time.perf_counter()
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_ip, port),
                    timeout=self.timeout
                )
                latency = (time.perf_counter() - start) * 1000.0
                writer.close()
                await writer.wait_closed()

                service = SERVICES.get(port, "Unknown")
                banner = ""
                tls_info = ""

                if self.grab_banners:
                    banner = await self._fetch_banner(port)
                if port in (443, 8443, 9443, 465, 993, 995):
                    tls_info = await self._fetch_tls_details(port)

                progress.update(task_id, advance=1)
                return PortResult(
                    port=port,
                    state="open",
                    service=service,
                    latency_ms=round(latency, 2),
                    banner=banner,
                    tls_info=tls_info
                )
            except (OSError, asyncio.TimeoutError):
                progress.update(task_id, advance=1)
                return None

    async def run(self) -> ScanReport:
        self.resolve()
        start_time = datetime.now()
        start_stamp = time.perf_counter()

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("[dim]{task.completed}/{task.total} ports"),
            console=console,
            transient=True
        ) as progress:
            task_id = progress.add_task(f"Scanning {self.target}...", total=len(self.ports))
            tasks = [self.probe_port(p, progress, task_id) for p in self.ports]
            results = await asyncio.gather(*tasks)
            open_results = [r for r in results if r is not None]

        open_results.sort(key=lambda r: r.port)
        duration = time.perf_counter() - start_stamp

        return ScanReport(
            target=self.target,
            ip=self.target_ip,
            start_time=start_time.isoformat(),
            duration_seconds=round(duration, 2),
            total_ports_scanned=len(self.ports),
            open_ports_count=len(open_results),
            results=open_results
        )


def parse_port_argument(port_arg: str) -> List[int]:
    arg_lower = port_arg.strip().lower()
    if arg_lower == "top100":
        return sorted(TOP_100_PORTS)
    if arg_lower == "all":
        return list(range(1, 65536))

    ports: set[int] = set()
    segments = [s.strip() for s in port_arg.split(",") if s.strip()]
    for seg in segments:
        if "-" in seg:
            start_s, end_s = seg.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end or start < 1 or end > 65535:
                raise ValueError(f"Invalid port range: {seg}")
            ports.update(range(start, end + 1))
        else:
            p = int(seg)
            if p < 1 or p > 65535:
                raise ValueError(f"Port outside valid range (1-65535): {p}")
            ports.add(p)

    return sorted(ports)


def render_banner():
    banner_text = "[bold cyan]PortScan[/bold cyan] [dim white]by Soar (2026)[/dim white]"
    console.print(Panel(banner_text, border_style="cyan", expand=False))


def display_results(report: ScanReport):
    if not report.results:
        console.print(f"\n[red]No open ports detected on {report.target} ({report.ip}).[/red]\n")
        return

    table = Table(title=f"Open Ports: {report.target} ({report.ip})", border_style="bright_blue", show_lines=True)
    table.add_column("Port", style="bold green", justify="right")
    table.add_column("State", style="bold white")
    table.add_column("Service", style="bold yellow")
    table.add_column("Latency", justify="right", style="cyan")
    table.add_column("Banner / Info", style="dim white")

    for r in report.results:
        extra_detail = r.banner
        if r.tls_info:
            extra_detail = f"{r.tls_info} | {r.banner}" if r.banner else r.tls_info
        table.add_row(
            f"{r.port}/tcp",
            r.state.upper(),
            r.service,
            f"{r.latency_ms} ms",
            extra_detail or "[dim]-[/dim]"
        )

    console.print(table)

    summary_panel = Panel(
        f"[bold white]Target:[/bold white] [cyan]{report.target}[/cyan] ({report.ip})\n"
        f"[bold white]Scanned:[/bold white] {report.total_ports_scanned} ports\n"
        f"[bold white]Open Ports:[/bold white] [bold green]{report.open_ports_count}[/bold green]\n"
        f"[bold white]Duration:[/bold white] {report.duration_seconds}s",
        title="Summary",
        border_style="green",
        expand=False
    )
    console.print(summary_panel)


def export_json(report: ScanReport, filepath: str):
    data = asdict(report)
    data["author"] = "Soar"
    data["copyright"] = "Copyright (c) 2026 Soar"
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    console.print(f"[green]Saved JSON report:[/green] {filepath}")


def export_csv(report: ScanReport, filepath: str):
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Target", "IP", "Port", "State", "Service", "Latency_ms", "Banner", "TLS_Info"])
        for r in report.results:
            writer.writerow([report.target, report.ip, r.port, r.state, r.service, r.latency_ms, r.banner, r.tls_info])
    console.print(f"[green]Saved CSV report:[/green] {filepath}")


def export_html(report: ScanReport, filepath: str):
    rows = ""
    for r in report.results:
        details = r.tls_info or r.banner or "-"
        rows += f"""
        <tr>
            <td class="port">{r.port}/tcp</td>
            <td><span class="badge open">OPEN</span></td>
            <td>{r.service}</td>
            <td>{r.latency_ms} ms</td>
            <td class="details">{details}</td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>PortScan Report - {report.target}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 30px; }}
        h1 {{ color: #58a6ff; margin-bottom: 5px; }}
        .header {{ border-bottom: 1px solid #30363d; padding-bottom: 15px; margin-bottom: 25px; }}
        .meta {{ color: #8b949e; font-size: 0.9em; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #21262d; }}
        th {{ background: #161b22; color: #f0f6fc; }}
        tr:hover {{ background: #161b22; }}
        .port {{ font-weight: bold; color: #7ee787; }}
        .badge.open {{ background: #238636; color: white; padding: 3px 8px; border-radius: 12px; font-size: 0.75em; }}
        .details {{ font-family: monospace; font-size: 0.85em; color: #a5d6ff; }}
        footer {{ margin-top: 40px; font-size: 0.8em; color: #8b949e; text-align: center; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>PortScan Security Audit Report</h1>
        <div class="meta">Target: <strong>{report.target}</strong> ({report.ip}) | Duration: {report.duration_seconds}s | Ports Open: {report.open_ports_count}</div>
    </div>
    <table>
        <thead>
            <tr>
                <th>Port</th>
                <th>State</th>
                <th>Service</th>
                <th>Latency</th>
                <th>Banner / Service Info</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
    <footer>
        Generated by PortScan &bull; Copyright &copy; 2026 Soar. All rights reserved.
    </footer>
</body>
</html>
"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)
    console.print(f"[green]Saved HTML report:[/green] {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description="PortScan: asynchronous TCP port scanner and banner grabber by Soar",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python portscan.py 127.0.0.1 -p 80,443,8080\n"
               "  python portscan.py scanme.nmap.org -p top100\n"
               "  python portscan.py 192.168.1.1 -p 1-1024 -c 300 -oJ output.json\n"
    )
    parser.add_argument("target", help="Target hostname or IP address to scan")
    parser.add_argument(
        "-p", "--ports",
        default="top100",
        help="Ports to scan: 'top100', 'all', or comma/dash separated e.g. '21,22,80,443,8000-8080' (Default: top100)"
    )
    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=150,
        help="Maximum concurrent asynchronous connection workers (Default: 150)"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=1.0,
        help="Socket timeout in seconds (Default: 1.0)"
    )
    parser.add_argument(
        "--no-banners",
        action="store_true",
        help="Disable automatic service banner grabbing"
    )
    parser.add_argument(
        "--shuffle",
        action="store_true",
        help="Randomize port scan order to evade basic sequential detection"
    )
    parser.add_argument(
        "-oJ", "--json",
        metavar="FILE",
        help="Export scan results to JSON file"
    )
    parser.add_argument(
        "-oC", "--csv",
        metavar="FILE",
        help="Export scan results to CSV file"
    )
    parser.add_argument(
        "-oH", "--html",
        metavar="FILE",
        help="Export scan results to standalone HTML report"
    )

    args = parser.parse_args()

    render_banner()

    try:
        ports = parse_port_argument(args.ports)
    except ValueError as e:
        console.print(f"[bold red]Configuration Error:[/bold red] {e}")
        sys.exit(1)

    scanner = PortScanner(
        target=args.target,
        ports=ports,
        concurrency=args.concurrency,
        timeout=args.timeout,
        grab_banners=not args.no_banners,
        shuffle=args.shuffle
    )

    try:
        console.print(f"[*] Target: [bold cyan]{args.target}[/bold cyan]")
        console.print(f"[*] Port Count: [bold yellow]{len(ports)}[/bold yellow] | Concurrency: [bold yellow]{args.concurrency}[/bold yellow] workers | Timeout: [bold yellow]{args.timeout}s[/bold yellow]\n")
        report = asyncio.run(scanner.run())
        display_results(report)

        if args.json:
            export_json(report, args.json)
        if args.csv:
            export_csv(report, args.csv)
        if args.html:
            export_html(report, args.html)

    except KeyboardInterrupt:
        console.print("\n[red]Scan stopped.[/red]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
