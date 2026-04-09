# Quiet-Nmap

> **This project is under active development and is not a stable release. Features may change, break, or be incomplete.**

A modern, async Python network scanner and traffic monitor — an nmap-inspired alternative built with `asyncio`, `scapy`, and `rich`. Works as both a CLI tool and a Python library.

---

## Features

| Category | What You Get |
|----------|-------------|
| **Port Scanning** | 7 scan types — SYN, Connect, FIN, XMAS, NULL, ACK, UDP |
| **Service Detection** | Banner grabbing, protocol identification on open ports |
| **OS Fingerprinting** | TTL analysis, TCP window size, port-based heuristics |
| **Traffic Monitor** | Real-time packet sniffing — see who's talking to whom |
| **Protocol Analysis** | Identifies DNS lookups, HTTP requests, and 40+ activities |
| **Device Aliases** | Name IPs on your network (e.g., "Router", "Dad's Laptop") |
| **Auto "(this pc)"** | Your machine is auto-tagged everywhere — no setup needed |
| **Stealth Options** | Inter-probe delay, randomization, TTL spoofing, source port control |
| **Scan Profiles** | `quick`, `normal`, `aggressive`, `quiet`, `paranoid` presets |
| **Rich CLI** | Live dashboard with progress tracking |
| **Output Formats** | Console, JSON, self-contained HTML report |
| **Plugin System** | Extend via entry points or local plugin directory |
| **No Root Fallback** | Falls back to TCP connect scan when raw sockets aren't available |

---

## Installation

```bash
git clone https://github.com/Arps-hub/Quiet-Nmap.git
cd Quiet-Nmap
pip install -e .
```

**Requirements:** Python 3.11+

**Dependencies:** `scapy`, `click`, `rich` (installed automatically)

---

## Quick Start

### Scan a target
```bash
quietnmap scan 192.168.1.1                          # Default SYN scan (needs admin)
quietnmap scan 192.168.1.1 -sT                      # Connect scan (no admin needed)
quietnmap scan 10.0.0.0/24 -p 22,80,443             # Scan specific ports on a subnet
quietnmap scan 192.168.1.1 -p 1-1024 -oJ results.json -oH report.html
```

### Name your devices
```bash
quietnmap alias add 192.168.1.1 Router
quietnmap alias add 192.168.1.20 "Mom's Phone"
quietnmap alias add 192.168.1.30 "Smart TV"
quietnmap alias list
```

### Monitor network traffic
```bash
quietnmap monitor                                    # Live dashboard (needs admin)
quietnmap monitor -i Wi-Fi -d 60                     # Specific interface, 60 seconds
quietnmap monitor -f "udp port 53" -oJ dns.json      # Filter DNS traffic only
```

### Other commands
```bash
quietnmap ping 192.168.1.1                           # Check if host is up
quietnmap profiles                                   # List scan profiles
quietnmap alias list                                 # Show saved device names
```

---

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

---

## Scan Profiles

| Profile | Concurrency | Delay | Use Case |
|---------|-------------|-------|----------|
| `quick` | 1000 | 0ms | Fast discovery |
| `normal` | 500 | 0ms | Balanced (default) |
| `aggressive` | 2000 | 0ms | Maximum speed |
| `quiet` | 50 | 100ms | Low footprint |
| `paranoid` | 10 | 1000ms | IDS evasion |

```bash
quietnmap scan 192.168.1.0/24 --profile aggressive
quietnmap scan target.com --profile paranoid -sT
```

---

## Device Aliases

On a big network, raw IPs are hard to read. Aliases let you name them:

```bash
# Add aliases
quietnmap alias add 192.168.1.1 Router
quietnmap alias add 192.168.1.20 "Mom's Phone"
quietnmap alias add 192.168.1.30 "Smart TV"
quietnmap alias add 192.168.1.100 "Work Laptop"

# See all aliases
quietnmap alias list

# Remove one
quietnmap alias remove 192.168.1.30

# Clear all
quietnmap alias clear
```

**Your machine is auto-tagged as `(this pc)` everywhere — no setup needed.**

Aliases appear in:
- Scan results — `192.168.1.1 (Router)` instead of just the IP
- Traffic monitor — Device column shows `Router`, `this pc`, etc.
- Connection table — `this pc:54321 -> Router:80`
- DNS/HTTP logs — Shows device names
- HTML reports — Names embedded in the report

Stored in `~/.quietnmap/aliases.json`.

---

## Traffic Monitor

Watch what devices on your network are doing in real time:

```bash
# Start monitoring (Ctrl+C to stop)
quietnmap monitor

# Monitor a specific interface
quietnmap monitor -i Wi-Fi

# Only capture DNS and HTTP traffic
quietnmap monitor -f "udp port 53 or tcp port 80"

# Run for 2 minutes and export results
quietnmap monitor -d 120 -oJ captured.json

# Text mode (no live dashboard)
quietnmap monitor --no-dashboard -v
```

**What the dashboard shows:**
- **Devices & Activity** — Every IP, their name/alias, traffic volume, what they're doing
- **Active Connections** — Source, destination, protocol, data transferred
- **Protocol Breakdown** — TCP vs UDP vs ICMP distribution with visual bars
- **DNS Queries** — Real-time log of domain lookups (who's visiting what)
- **HTTP Requests** — Method + host for unencrypted web traffic

> Requires **admin/root** privileges for raw packet capture.

---

## Usage as a Python Library

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

---

## Project Structure

```
quiet-nmap/
├── quietnmap/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py                 # Click CLI interface
│   ├── models.py              # Data models (ScanConfig, HostResult, etc.)
│   ├── profiles.py            # Scan profile presets
│   ├── aliases.py             # Device alias manager (IP → friendly name)
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
│   ├── monitor/
│   │   ├── sniffer.py         # Packet capture & connection tracking
│   │   ├── analyzer.py        # Protocol analysis & device activity
│   │   └── dashboard.py       # Rich live traffic dashboard
│   └── plugins/
│       └── base.py            # Plugin system (base class & loader)
├── tests/
│   ├── test_aliases.py
│   ├── test_cli.py
│   ├── test_models.py
│   ├── test_monitor.py
│   ├── test_profiles.py
│   └── test_tcp.py
├── pyproject.toml
└── .gitignore
```

---

## Disclaimer

This tool is intended for **authorized security testing, educational purposes, and network administration** only. Always obtain proper authorization before scanning networks you do not own. Unauthorized scanning may violate laws and regulations.

## License

MIT

## Author

**Ayush** — [GitHub](https://github.com/Arps-hub)
