# Quiet-Nmap

> **This project is under active development and is not a stable release. Features may change, break, or be incomplete.**

A modern, async Python network scanner — an nmap-inspired alternative built with `asyncio`, `scapy`, and `rich`.

## Features

- **7 Scan Types** — SYN, Connect, FIN, XMAS, NULL, ACK, UDP
- **Service Detection** — Banner grabbing and protocol identification
- **OS Fingerprinting** — TTL analysis, TCP window size, port heuristics
- **Stealth Options** — Inter-probe delay, port/host randomization, TTL spoofing, source port control
- **Scan Profiles** — `quiet`, `normal`, `aggressive`, `paranoid`, `quick` presets
- **Rich CLI** — Live dashboard with progress tracking
- **Multiple Output Formats** — Console, JSON, HTML report
- **Plugin System** — Extensible via entry points or local plugin directory
- **No Root Fallback** — Falls back to TCP connect scan when raw sockets aren't available

## Installation

```bash
pip install -e .
```

**Requirements:** Python 3.11+

## Quick Start

```bash
# Basic scan
quietnmap scan 192.168.1.1

# Scan specific ports
quietnmap scan 10.0.0.0/24 -p 22,80,443

# TCP connect scan (no root needed)
quietnmap scan target.com -sT

# Aggressive profile with JSON output
quietnmap scan 192.168.1.1 --profile aggressive -oJ results.json

# HTML report
quietnmap scan 192.168.1.0/24 -p 1-1024 -oH report.html

# Check if host is up
quietnmap ping 192.168.1.1

# List scan profiles
quietnmap profiles
```

## Scan Types

| Flag | Type | Description | Root Required |
|------|------|-------------|---------------|
| `-sS` | SYN | Half-open stealth scan (default) | Yes |
| `-sT` | Connect | Full TCP handshake | No |
| `-sF` | FIN | FIN flag scan | Yes |
| `-sX` | XMAS | FIN+PSH+URG flags | Yes |
| `-sN` | NULL | No flags set | Yes |
| `-sA` | ACK | ACK flag (firewall detection) | Yes |
| `-sU` | UDP | UDP scan | No |

## Scan Profiles

| Profile | Concurrency | Delay | Use Case |
|---------|-------------|-------|----------|
| `quick` | 1000 | 0ms | Fast discovery |
| `normal` | 500 | 0ms | Balanced (default) |
| `aggressive` | 2000 | 0ms | Maximum speed |
| `quiet` | 50 | 100ms | Low footprint |
| `paranoid` | 10 | 1000ms | IDS evasion |

## Project Structure

```
quiet-nmap/
├── quietnmap/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py                 # Click CLI interface
│   ├── models.py              # Data models (ScanConfig, HostResult, etc.)
│   ├── profiles.py            # Scan profile presets
│   ├── core/
│   │   ├── scanner.py         # Main scan engine (orchestrator)
│   │   ├── tcp.py             # TCP scan techniques (SYN, FIN, XMAS, etc.)
│   │   ├── udp.py             # UDP scanning
│   │   ├── host_discovery.py  # ICMP ping, TCP ping, ARP discovery
│   │   └── service.py         # Banner grabbing & service detection
│   ├── fingerprint/
│   │   ├── os_detect.py       # OS fingerprinting (TTL, window size, heuristics)
│   │   └── signatures.py      # Fingerprint signature database
│   ├── output/
│   │   ├── console.py         # Rich console output & live dashboard
│   │   ├── json_out.py        # JSON export
│   │   └── html_report.py     # Self-contained HTML report
│   └── plugins/
│       └── base.py            # Plugin system (base class & loader)
├── tests/
│   ├── test_cli.py
│   ├── test_models.py
│   ├── test_profiles.py
│   └── test_tcp.py
├── pyproject.toml
└── .gitignore
```

## Usage as a Library

```python
import asyncio
from quietnmap.models import ScanConfig, ScanType
from quietnmap.core.scanner import Scanner

async def main():
    config = ScanConfig(
        targets=["192.168.1.1"],
        ports=[22, 80, 443],
        scan_type=ScanType.TCP_CONNECT,
    )
    scanner = Scanner(config)

    async for host in scanner.run_stream():
        for port in host.open_ports:
            print(f"{host.ip}:{port.port} — {port.service.name}")

asyncio.run(main())
```

## Disclaimer

This tool is intended for **authorized security testing, educational purposes, and network administration** only. Always obtain proper authorization before scanning networks you do not own. Unauthorized scanning may violate laws and regulations.

## License

MIT
