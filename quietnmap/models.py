"""Data models for QuietNmap scan targets and results."""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PortState(Enum):
    """State of a scanned port."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    UNFILTERED = "unfiltered"


class ScanType(Enum):
    """Supported scan techniques."""
    TCP_SYN = "syn"
    TCP_CONNECT = "connect"
    TCP_FIN = "fin"
    TCP_XMAS = "xmas"
    TCP_NULL = "null"
    TCP_ACK = "ack"
    UDP = "udp"
    PING = "ping"


class Protocol(Enum):
    """Transport protocol."""
    TCP = "tcp"
    UDP = "udp"


@dataclass
class ServiceInfo:
    """Detected service running on a port."""
    name: str = "unknown"
    product: str = ""
    version: str = ""
    banner: str = ""
    extra_info: str = ""

    def __str__(self) -> str:
        parts = [self.name]
        if self.product:
            parts.append(self.product)
        if self.version:
            parts.append(self.version)
        return " ".join(parts)


@dataclass
class PortResult:
    """Result of scanning a single port."""
    port: int
    protocol: Protocol
    state: PortState
    service: ServiceInfo = field(default_factory=ServiceInfo)
    reason: str = ""
    response_time_ms: float = 0.0

    @property
    def is_open(self) -> bool:
        return self.state in (PortState.OPEN, PortState.OPEN_FILTERED)


@dataclass
class OSGuess:
    """Operating system fingerprint guess."""
    name: str
    confidence: float  # 0.0 to 1.0
    family: str = ""  # e.g., "Linux", "Windows", "BSD"
    version: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        pct = int(self.confidence * 100)
        return f"{self.name} ({pct}% confidence)"


@dataclass
class HostResult:
    """Complete scan result for a single host."""
    ip: str
    hostname: str = ""
    is_up: bool = False
    ports: list[PortResult] = field(default_factory=list)
    os_guesses: list[OSGuess] = field(default_factory=list)
    mac_address: str = ""
    scan_start: float = 0.0
    scan_end: float = 0.0
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.is_open]

    @property
    def scan_duration(self) -> float:
        if self.scan_start and self.scan_end:
            return self.scan_end - self.scan_start
        return 0.0

    @property
    def best_os_guess(self) -> OSGuess | None:
        if not self.os_guesses:
            return None
        return max(self.os_guesses, key=lambda g: g.confidence)


@dataclass
class ScanConfig:
    """Configuration for a scan session."""
    targets: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    scan_type: ScanType = ScanType.TCP_SYN
    timeout: float = 2.0
    max_concurrency: int = 500
    max_retries: int = 1
    randomize_ports: bool = True
    randomize_hosts: bool = False
    detect_services: bool = True
    detect_os: bool = False
    # Stealth options
    delay_ms: float = 0.0
    decoy_ips: list[str] = field(default_factory=list)
    source_port: int | None = None
    fragment_packets: bool = False
    ttl: int | None = None

    def resolve_targets(self) -> list[str]:
        """Expand CIDR notation and ranges into individual IPs."""
        ips: list[str] = []
        for target in self.targets:
            try:
                network = ipaddress.ip_network(target, strict=False)
                ips.extend(str(ip) for ip in network.hosts())
            except ValueError:
                # Treat as hostname or single IP
                ips.append(target)
        return ips

    def resolve_ports(self) -> list[int]:
        """Return port list, defaulting to top 1000 if empty."""
        if self.ports:
            return self.ports
        return list(TOP_1000_PORTS)


@dataclass
class ScanSession:
    """Top-level scan session containing all results."""
    config: ScanConfig
    hosts: list[HostResult] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    scanner_version: str = "0.1.0"

    @property
    def duration(self) -> float:
        end = self.end_time or time.time()
        return end - self.start_time

    @property
    def hosts_up(self) -> list[HostResult]:
        return [h for h in self.hosts if h.is_up]

    @property
    def total_open_ports(self) -> int:
        return sum(len(h.open_ports) for h in self.hosts)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dictionary."""
        return {
            "scanner": "quietnmap",
            "version": self.scanner_version,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": round(self.duration, 3),
            "command": {
                "targets": self.config.targets,
                "ports": self.config.ports[:20] if len(self.config.ports) > 20 else self.config.ports,
                "scan_type": self.config.scan_type.value,
            },
            "summary": {
                "hosts_scanned": len(self.hosts),
                "hosts_up": len(self.hosts_up),
                "total_open_ports": self.total_open_ports,
            },
            "hosts": [
                {
                    "ip": h.ip,
                    "hostname": h.hostname,
                    "is_up": h.is_up,
                    "os": str(h.best_os_guess) if h.best_os_guess else None,
                    "ports": [
                        {
                            "port": p.port,
                            "protocol": p.protocol.value,
                            "state": p.state.value,
                            "service": str(p.service),
                            "banner": p.service.banner,
                            "response_time_ms": round(p.response_time_ms, 2),
                        }
                        for p in h.ports
                    ],
                }
                for h in self.hosts
            ],
        }


# Top 1000 most common ports (nmap's default set, abbreviated for prototype)
TOP_1000_PORTS: tuple[int, ...] = (
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 636, 646, 873, 990, 993,
    995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
    2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000,
    5001, 5003, 5009, 5050, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666,
    5800, 5900, 5901, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081,
    8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156,
)
