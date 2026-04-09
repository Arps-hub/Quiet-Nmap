"""Packet sniffer — captures and tracks network traffic in real time."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable

logger = logging.getLogger("quietnmap.monitor")


@dataclass
class ConnectionKey:
    """Unique identifier for a network connection."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # "TCP", "UDP", "ICMP", etc.

    def __hash__(self) -> int:
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ConnectionKey):
            return NotImplemented
        return (
            self.src_ip == other.src_ip
            and self.dst_ip == other.dst_ip
            and self.src_port == other.src_port
            and self.dst_port == other.dst_port
            and self.protocol == other.protocol
        )

    def __str__(self) -> str:
        return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} [{self.protocol}]"


@dataclass
class ConnectionStats:
    """Statistics for a tracked connection."""
    key: ConnectionKey
    packet_count: int = 0
    bytes_sent: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    flags: set[str] = field(default_factory=set)
    dns_queries: list[str] = field(default_factory=list)
    http_hosts: list[str] = field(default_factory=list)
    info: str = ""

    @property
    def duration(self) -> float:
        if self.first_seen and self.last_seen:
            return self.last_seen - self.first_seen
        return 0.0

    @property
    def bytes_display(self) -> str:
        if self.bytes_sent >= 1_048_576:
            return f"{self.bytes_sent / 1_048_576:.1f} MB"
        if self.bytes_sent >= 1024:
            return f"{self.bytes_sent / 1024:.1f} KB"
        return f"{self.bytes_sent} B"


@dataclass
class TrafficSnapshot:
    """Current state of all monitored traffic."""
    connections: dict[ConnectionKey, ConnectionStats] = field(default_factory=dict)
    total_packets: int = 0
    total_bytes: int = 0
    start_time: float = field(default_factory=time.time)
    protocol_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    top_talkers: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    dns_log: list[tuple[float, str, str]] = field(default_factory=list)  # (time, src_ip, query)
    http_log: list[tuple[float, str, str, str]] = field(default_factory=list)  # (time, src_ip, method, host)

    @property
    def duration(self) -> float:
        return time.time() - self.start_time

    @property
    def packets_per_second(self) -> float:
        d = self.duration
        return self.total_packets / d if d > 0 else 0.0


class PacketSniffer:
    """Async packet sniffer using scapy.

    Captures packets, tracks connections, and provides real-time stats.
    Requires root/admin privileges.
    """

    def __init__(
        self,
        interface: str | None = None,
        bpf_filter: str | None = None,
        local_ip: str | None = None,
    ):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.local_ip = local_ip
        self.snapshot = TrafficSnapshot()
        self._running = False
        self._callbacks: list[Callable[[TrafficSnapshot], None]] = []

    def on_update(self, callback: Callable[[TrafficSnapshot], None]) -> None:
        """Register a callback for snapshot updates."""
        self._callbacks.append(callback)

    def stop(self) -> None:
        """Signal the sniffer to stop."""
        self._running = False

    async def start(self, duration: float | None = None) -> TrafficSnapshot:
        """Start sniffing packets.

        Args:
            duration: How long to sniff in seconds. None = until stop() is called.
        """
        from scapy.all import sniff as scapy_sniff, conf, get_if_addr

        if self.local_ip is None:
            try:
                iface = self.interface or conf.iface
                self.local_ip = get_if_addr(iface)
            except Exception:
                self.local_ip = "unknown"

        self._running = True
        self.snapshot = TrafficSnapshot()
        loop = asyncio.get_running_loop()

        def _sniff_sync() -> None:
            kwargs: dict = {
                "prn": self._process_packet,
                "store": False,
                "stop_filter": lambda _: not self._running,
            }
            if self.interface:
                kwargs["iface"] = self.interface
            if self.bpf_filter:
                kwargs["filter"] = self.bpf_filter
            if duration:
                kwargs["timeout"] = duration

            try:
                scapy_sniff(**kwargs)
            except PermissionError:
                logger.error("Root/admin privileges required for packet sniffing")
            except Exception as e:
                logger.error("Sniffer error: %s", e)

        await loop.run_in_executor(None, _sniff_sync)
        return self.snapshot

    def _process_packet(self, pkt) -> None:
        """Process a single captured packet."""
        from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, Raw

        if not pkt.haslayer(IP):
            return

        ip_layer = pkt[IP]
        now = time.time()
        pkt_len = len(pkt)

        # Determine protocol and ports
        src_port = 0
        dst_port = 0
        proto = "OTHER"

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            proto = "TCP"
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            src_port = udp.sport
            dst_port = udp.dport
            proto = "UDP"
        elif pkt.haslayer(ICMP):
            proto = "ICMP"

        # Update global stats
        self.snapshot.total_packets += 1
        self.snapshot.total_bytes += pkt_len
        self.snapshot.protocol_counts[proto] += 1
        self.snapshot.top_talkers[ip_layer.src] += pkt_len

        # Track connection
        key = ConnectionKey(
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
        )

        if key not in self.snapshot.connections:
            self.snapshot.connections[key] = ConnectionStats(
                key=key, first_seen=now,
            )

        conn = self.snapshot.connections[key]
        conn.packet_count += 1
        conn.bytes_sent += pkt_len
        conn.last_seen = now

        # Track TCP flags
        if proto == "TCP":
            flags = pkt[TCP].flags
            if flags & 0x02:
                conn.flags.add("SYN")
            if flags & 0x10:
                conn.flags.add("ACK")
            if flags & 0x01:
                conn.flags.add("FIN")
            if flags & 0x04:
                conn.flags.add("RST")

        # DNS analysis
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            query = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
            if query:
                conn.dns_queries.append(query)
                self.snapshot.dns_log.append((now, ip_layer.src, query))

        # HTTP analysis (basic — look for Host header in raw payload)
        if proto == "TCP" and (dst_port == 80 or src_port == 80) and pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode("utf-8", errors="replace")
                lines = payload.split("\r\n")
                method = ""
                host = ""
                if lines and lines[0].startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "PATCH ")):
                    method = lines[0].split(" ")[0]
                for line in lines:
                    if line.lower().startswith("host:"):
                        host = line.split(":", 1)[1].strip()
                        break
                if method and host:
                    conn.http_hosts.append(host)
                    conn.info = f"{method} {host}"
                    self.snapshot.http_log.append((now, ip_layer.src, method, host))
            except Exception:
                pass

        # Notify callbacks
        for cb in self._callbacks:
            try:
                cb(self.snapshot)
            except Exception:
                pass
