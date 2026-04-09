"""CLI interface for QuietNmap — Click-based with Rich live dashboard."""

from __future__ import annotations

import asyncio
import logging
import sys
import time

import click
from rich.console import Console

from quietnmap import __version__
from quietnmap.models import ScanConfig, ScanType
from quietnmap.core.scanner import Scanner
from quietnmap.output.console import (
    console,
    print_banner,
    print_host_result,
    print_scan_start,
    print_summary,
)
from quietnmap.profiles import PROFILES, apply_profile, list_profiles


def parse_ports(port_str: str) -> list[int]:
    """Parse port specification string.

    Supports: single ports (80), ranges (1-1024), comma-separated (22,80,443),
    and combinations (22,80,443,8000-8100).
    """
    ports: list[int] = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            start_port = int(start.strip())
            end_port = int(end.strip())
            if start_port < 0 or start_port > 65535:
                raise click.BadParameter(f"Port out of range: {start_port}")
            if end_port < 0 or end_port > 65535:
                raise click.BadParameter(f"Port out of range: {end_port}")
            if start_port > end_port:
                raise click.BadParameter(f"Invalid range: {part}")
            ports.extend(range(start_port, end_port + 1))
        else:
            port = int(part)
            if port < 0 or port > 65535:
                raise click.BadParameter(f"Port out of range: {port}")
            ports.append(port)
    return sorted(set(ports))


SCAN_TYPE_MAP = {
    "syn": ScanType.TCP_SYN,
    "connect": ScanType.TCP_CONNECT,
    "fin": ScanType.TCP_FIN,
    "xmas": ScanType.TCP_XMAS,
    "null": ScanType.TCP_NULL,
    "ack": ScanType.TCP_ACK,
    "udp": ScanType.UDP,
}


@click.group(invoke_without_command=True)
@click.pass_context
@click.version_option(__version__, prog_name="quietnmap")
def main(ctx: click.Context) -> None:
    """QuietNmap — A modern, async network scanner."""
    if ctx.invoked_subcommand is None:
        print_banner()
        click.echo(ctx.get_help())


@main.command()
@click.argument("targets", nargs=-1, required=True)
@click.option("-p", "--ports", default=None, help="Port specification (e.g., 22,80,443 or 1-1024)")
@click.option("-sS", "--syn", "scan_type", flag_value="syn", help="TCP SYN scan (default, needs root)")
@click.option("-sT", "--connect", "scan_type", flag_value="connect", help="TCP connect scan (no root needed)")
@click.option("-sF", "--fin", "scan_type", flag_value="fin", help="TCP FIN scan")
@click.option("-sX", "--xmas", "scan_type", flag_value="xmas", help="TCP XMAS scan")
@click.option("-sN", "--null", "scan_type", flag_value="null", help="TCP NULL scan")
@click.option("-sA", "--ack", "scan_type", flag_value="ack", help="TCP ACK scan")
@click.option("-sU", "--udp", "scan_type", flag_value="udp", help="UDP scan")
@click.option("--profile", type=click.Choice(list(PROFILES.keys())), default=None, help="Use a scan profile")
@click.option("--timeout", type=float, default=2.0, help="Timeout per probe in seconds")
@click.option("--concurrency", type=int, default=500, help="Max concurrent probes")
@click.option("--delay", type=float, default=0.0, help="Delay between probes in ms (stealth)")
@click.option("--retries", type=int, default=1, help="Max retries for filtered ports")
@click.option("-sV", "--service-detection/--no-service-detection", default=True, help="Enable service detection")
@click.option("-O", "--os-detection", is_flag=True, default=False, help="Enable OS fingerprinting")
@click.option("--randomize/--no-randomize", default=True, help="Randomize port order")
@click.option("--source-port", type=int, default=None, help="Use specific source port")
@click.option("--ttl", type=int, default=None, help="Set custom TTL value")
@click.option("-oJ", "--json-output", type=click.Path(), default=None, help="Save results as JSON")
@click.option("-oH", "--html-output", type=click.Path(), default=None, help="Save results as HTML report")
@click.option("--show-closed", is_flag=True, default=False, help="Show closed ports in output")
@click.option("-v", "--verbose", count=True, help="Increase verbosity (-v, -vv)")
def scan(
    targets: tuple[str, ...],
    ports: str | None,
    scan_type: str | None,
    profile: str | None,
    timeout: float,
    concurrency: int,
    delay: float,
    retries: int,
    service_detection: bool,
    os_detection: bool,
    randomize: bool,
    source_port: int | None,
    ttl: int | None,
    json_output: str | None,
    html_output: str | None,
    show_closed: bool,
    verbose: int,
) -> None:
    """Scan target hosts for open ports and services.

    TARGETS can be IPs, hostnames, or CIDR ranges (e.g., 192.168.1.0/24).

    \b
    Examples:
        quietnmap scan 192.168.1.1
        quietnmap scan 10.0.0.0/24 -p 22,80,443
        quietnmap scan target.com --profile aggressive
        quietnmap scan 192.168.1.1 -p 1-1024 -sT -oJ results.json
    """
    # Configure logging
    log_level = logging.WARNING
    if verbose == 1:
        log_level = logging.INFO
    elif verbose >= 2:
        log_level = logging.DEBUG
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    print_banner()

    # Build scan config
    config = ScanConfig(
        targets=list(targets),
        scan_type=SCAN_TYPE_MAP.get(scan_type or "syn", ScanType.TCP_SYN),
        timeout=timeout,
        max_concurrency=concurrency,
        delay_ms=delay,
        max_retries=retries,
        detect_services=service_detection,
        detect_os=os_detection,
        randomize_ports=randomize,
        source_port=source_port,
        ttl=ttl,
    )

    if ports:
        try:
            config.ports = parse_ports(ports)
        except (ValueError, click.BadParameter) as e:
            console.print(f"[red]Invalid port specification: {e}[/red]")
            sys.exit(1)

    # Apply profile if specified
    if profile:
        config = apply_profile(config, profile)
        console.print(f"  [dim]Using profile: {profile}[/dim]")

    resolved_ports = config.resolve_ports()
    resolved_targets = config.resolve_targets()

    print_scan_start(resolved_targets, resolved_ports, config.scan_type.value)

    # Run the scan
    scanner = Scanner(config)

    async def _run() -> None:
        async for host in scanner.run_stream():
            print_host_result(host, show_closed=show_closed)

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")

    session = scanner.session
    session.end_time = time.time()

    # Print summary
    print_summary(session)

    # Save outputs
    if json_output:
        from quietnmap.output.json_out import save_json
        path = save_json(session, json_output)
        console.print(f"  [dim]JSON saved to: {path}[/dim]")

    if html_output:
        from quietnmap.output.html_report import save_html
        path = save_html(session, html_output)
        console.print(f"  [dim]HTML report saved to: {path}[/dim]")


@main.command()
def profiles() -> None:
    """List available scan profiles."""
    from rich.table import Table

    print_banner()
    table = Table(title="Scan Profiles", show_header=True, header_style="bold cyan")
    table.add_column("Name", style="bold")
    table.add_column("Description")
    table.add_column("Concurrency", justify="right")
    table.add_column("Delay", justify="right")

    for p in list_profiles():
        table.add_row(
            p.name,
            p.description,
            str(p.overrides.get("max_concurrency", "-")),
            f"{p.overrides.get('delay_ms', 0)}ms",
        )

    console.print(table)


@main.command()
@click.argument("target")
@click.option("--timeout", type=float, default=2.0)
def ping(target: str, timeout: float) -> None:
    """Check if a host is up."""
    from quietnmap.core.host_discovery import ping_host

    print_banner()
    console.print(f"  Pinging {target}...")

    async def _ping() -> bool:
        return await ping_host(target, timeout)

    is_up = asyncio.run(_ping())
    if is_up:
        console.print(f"  [green]{target} is UP[/green]")
    else:
        console.print(f"  [red]{target} is DOWN or unreachable[/red]")


if __name__ == "__main__":
    main()
