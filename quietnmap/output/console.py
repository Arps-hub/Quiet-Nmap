"""Rich console output — live dashboard and formatted results."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.columns import Columns

from quietnmap.models import HostResult, PortState, ScanSession

if TYPE_CHECKING:
    from quietnmap.core.scanner import ScanProgress

console = Console()

# Color scheme
COLORS = {
    PortState.OPEN: "bold green",
    PortState.CLOSED: "dim red",
    PortState.FILTERED: "yellow",
    PortState.OPEN_FILTERED: "bold yellow",
    PortState.UNFILTERED: "cyan",
}


def print_banner() -> None:
    """Print the QuietNmap startup banner."""
    banner = Text()
    banner.append("  ____        _      _   _   _                       \n", style="bold cyan")
    banner.append(" / __ \\      (_)    | | | \\ | |                      \n", style="bold cyan")
    banner.append("| |  | |_   _ _  ___| |_|  \\| |_ __ ___   __ _ _ __ \n", style="bold cyan")
    banner.append("| |  | | | | | |/ _ \\ __| . ` | '_ ` _ \\ / _` | '_ \\ \n", style="bold cyan")
    banner.append("| |__| | |_| | |  __/ |_| |\\  | | | | | | (_| | |_) |\n", style="bold cyan")
    banner.append(" \\___\\_\\\\__,_|_|\\___|\\__|_| \\_|_| |_| |_|\\__,_| .__/ \n", style="bold cyan")
    banner.append("                                               | |    \n", style="bold cyan")
    banner.append("                                               |_|    \n", style="bold cyan")
    banner.append("  v0.1.0 — Modern Async Network Scanner\n", style="dim")
    console.print(banner)


def print_scan_start(targets: list[str], ports: list[int], scan_type: str) -> None:
    """Print scan configuration summary."""
    info = Table(show_header=False, box=None, padding=(0, 1))
    info.add_column(style="bold white")
    info.add_column()

    target_str = ", ".join(targets[:5])
    if len(targets) > 5:
        target_str += f" (+{len(targets) - 5} more)"

    info.add_row("Targets:", target_str)
    info.add_row("Ports:", f"{len(ports)} ports")
    info.add_row("Scan type:", scan_type.upper())
    info.add_row("Started:", time.strftime("%Y-%m-%d %H:%M:%S"))

    console.print(Panel(info, title="[bold]Scan Configuration", border_style="blue"))


def print_host_result(
    host: HostResult, show_closed: bool = False,
    aliases: dict[str, str] | None = None, local_ip: str | None = None,
) -> None:
    """Print scan results for a single host."""
    from quietnmap.aliases import resolve_ip
    display_ip = resolve_ip(host.ip, aliases=aliases, local_ip=local_ip)

    if not host.is_up:
        console.print(f"  [dim]{display_ip} — Host down[/dim]")
        return

    # Host header
    header = f"[bold white]{display_ip}[/bold white]"
    if host.hostname:
        header += f" ({host.hostname})"
    if host.best_os_guess:
        header += f"  [dim]OS: {host.best_os_guess}[/dim]"

    console.print(f"\n  {header}")

    # Port table
    open_ports = [p for p in host.ports if p.is_open or show_closed]
    if not open_ports:
        console.print("  [dim]No open ports found[/dim]")
        return

    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    table.add_column("PORT", style="bold", width=10)
    table.add_column("STATE", width=14)
    table.add_column("SERVICE", width=20)
    table.add_column("VERSION", style="dim")
    table.add_column("RESPONSE", style="dim", width=10)

    for p in open_ports:
        state_style = COLORS.get(p.state, "white")
        state_text = Text(p.state.value, style=state_style)

        service_name = p.service.name if p.service.name != "unknown" else ""
        version = ""
        if p.service.product:
            version = p.service.product
            if p.service.version:
                version += f" {p.service.version}"

        response = f"{p.response_time_ms:.0f}ms" if p.response_time_ms else ""

        table.add_row(
            f"{p.port}/{p.protocol.value}",
            state_text,
            service_name,
            version,
            response,
        )

    console.print(table)


def print_summary(session: ScanSession) -> None:
    """Print scan summary statistics."""
    console.print()
    summary = Table(show_header=False, box=None, padding=(0, 1))
    summary.add_column(style="bold")
    summary.add_column()

    summary.add_row("Hosts scanned:", str(len(session.hosts)))
    summary.add_row("Hosts up:", f"[green]{len(session.hosts_up)}[/green]")
    summary.add_row("Open ports:", f"[bold green]{session.total_open_ports}[/bold green]")
    summary.add_row("Duration:", f"{session.duration:.2f}s")

    console.print(Panel(summary, title="[bold]Scan Summary", border_style="green"))


def create_live_display(progress: ScanProgress) -> tuple[Live, Progress]:
    """Create a Rich Live display for real-time scan progress."""
    prog = Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("•"),
        TextColumn("[green]{task.fields[open_ports]} open"),
        TextColumn("•"),
        TimeElapsedColumn(),
    )
    task_id = prog.add_task(
        "Scanning...", total=progress.total_tasks, open_ports=0,
    )
    live = Live(prog, console=console, refresh_per_second=10)
    return live, prog
