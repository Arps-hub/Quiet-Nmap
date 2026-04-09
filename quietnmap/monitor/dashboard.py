"""Rich live dashboard for network traffic monitoring."""

from __future__ import annotations

import time

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from quietnmap.monitor.sniffer import TrafficSnapshot
from quietnmap.monitor.analyzer import (
    analyze_traffic,
    get_protocol_breakdown,
    get_recent_dns,
    get_recent_http,
    get_top_talkers,
)

console = Console()


def _format_bytes(n: int) -> str:
    if n >= 1_073_741_824:
        return f"{n / 1_073_741_824:.1f} GB"
    if n >= 1_048_576:
        return f"{n / 1_048_576:.1f} MB"
    if n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n} B"


def _format_time(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts))


def build_dashboard(snapshot: TrafficSnapshot, local_ip: str | None = None) -> Layout:
    """Build the full dashboard layout from current traffic snapshot."""
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )
    layout["body"].split_row(
        Layout(name="left", ratio=3),
        Layout(name="right", ratio=2),
    )
    layout["left"].split_column(
        Layout(name="devices", ratio=3),
        Layout(name="connections", ratio=2),
    )
    layout["right"].split_column(
        Layout(name="protocols", size=10),
        Layout(name="dns", ratio=1),
        Layout(name="http", ratio=1),
    )

    # Header
    elapsed = time.time() - snapshot.start_time
    header_text = Text()
    header_text.append(" QUIET-NMAP TRAFFIC MONITOR ", style="bold white on blue")
    header_text.append(f"  Packets: {snapshot.total_packets}", style="green")
    header_text.append(f"  Data: {_format_bytes(snapshot.total_bytes)}", style="cyan")
    header_text.append(f"  Rate: {snapshot.packets_per_second:.0f} pkt/s", style="yellow")
    header_text.append(f"  Uptime: {elapsed:.0f}s", style="dim")
    layout["header"].update(Panel(header_text, style="blue"))

    # Device activity table
    devices = analyze_traffic(snapshot, local_ip)
    dev_table = Table(title="Devices & Activity", expand=True, show_edge=False)
    dev_table.add_column("IP", style="bold", width=16)
    dev_table.add_column("Traffic", justify="right", width=10)
    dev_table.add_column("Pkts", justify="right", width=8)
    dev_table.add_column("Protocols", width=12)
    dev_table.add_column("Activity", style="cyan")

    for dev in devices[:15]:
        activity = ", ".join(dev.activities[:3]) if dev.activities else "—"
        protos = ", ".join(sorted(dev.protocols))
        style = "bold green" if dev.ip == local_ip else ""
        dev_table.add_row(
            dev.ip, _format_bytes(dev.total_bytes),
            str(dev.total_packets), protos, activity,
            style=style,
        )
    layout["devices"].update(Panel(dev_table, border_style="green"))

    # Active connections
    conn_table = Table(title="Active Connections", expand=True, show_edge=False)
    conn_table.add_column("Source", width=22)
    conn_table.add_column("Destination", width=22)
    conn_table.add_column("Proto", width=5)
    conn_table.add_column("Data", justify="right", width=9)
    conn_table.add_column("Info", style="dim")

    sorted_conns = sorted(
        snapshot.connections.values(),
        key=lambda c: c.last_seen, reverse=True,
    )
    for conn in sorted_conns[:10]:
        info = conn.info or ""
        if conn.dns_queries:
            info = f"DNS: {conn.dns_queries[-1]}"
        conn_table.add_row(
            f"{conn.key.src_ip}:{conn.key.src_port}",
            f"{conn.key.dst_ip}:{conn.key.dst_port}",
            conn.key.protocol,
            conn.bytes_display,
            info[:40],
        )
    layout["connections"].update(Panel(conn_table, border_style="yellow"))

    # Protocol breakdown
    proto_table = Table(title="Protocols", expand=True, show_edge=False)
    proto_table.add_column("Protocol", style="bold")
    proto_table.add_column("Count", justify="right")
    proto_table.add_column("%", justify="right")

    for name, count, pct in get_protocol_breakdown(snapshot):
        bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
        proto_table.add_row(name, str(count), f"{pct:.1f}% {bar}")
    layout["protocols"].update(Panel(proto_table, border_style="cyan"))

    # DNS log
    dns_table = Table(title="DNS Queries", expand=True, show_edge=False)
    dns_table.add_column("Time", width=8, style="dim")
    dns_table.add_column("From", width=16)
    dns_table.add_column("Query", style="cyan")

    for ts, src, query in get_recent_dns(snapshot, limit=8):
        dns_table.add_row(_format_time(ts), src, query)
    layout["dns"].update(Panel(dns_table, border_style="magenta"))

    # HTTP log
    http_table = Table(title="HTTP Requests", expand=True, show_edge=False)
    http_table.add_column("Time", width=8, style="dim")
    http_table.add_column("From", width=16)
    http_table.add_column("Method", width=6, style="bold")
    http_table.add_column("Host", style="green")

    for ts, src, method, host in get_recent_http(snapshot, limit=8):
        http_table.add_row(_format_time(ts), src, method, host)
    layout["http"].update(Panel(http_table, border_style="green"))

    # Footer
    footer_text = Text()
    footer_text.append(" Press Ctrl+C to stop monitoring ", style="dim")
    conns = len(snapshot.connections)
    unique_ips = len(set(
        ip for k in snapshot.connections for ip in (k.src_ip, k.dst_ip)
    ))
    footer_text.append(f"  |  {conns} connections  |  {unique_ips} unique IPs", style="dim")
    layout["footer"].update(Panel(footer_text, style="dim"))

    return layout


class TrafficDashboard:
    """Manages the Rich Live display for traffic monitoring."""

    def __init__(self, local_ip: str | None = None):
        self.local_ip = local_ip
        self._live: Live | None = None

    def start(self) -> Live:
        """Start the live display."""
        self._live = Live(
            console=console,
            refresh_per_second=4,
            screen=True,
        )
        self._live.start()
        return self._live

    def update(self, snapshot: TrafficSnapshot) -> None:
        """Update the dashboard with new data."""
        if self._live:
            layout = build_dashboard(snapshot, self.local_ip)
            self._live.update(layout)

    def stop(self) -> None:
        """Stop the live display."""
        if self._live:
            self._live.stop()
            self._live = None
