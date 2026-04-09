"""Protocol analyzer — identifies what devices are doing on the network."""

from __future__ import annotations

from dataclasses import dataclass, field

from quietnmap.monitor.sniffer import ConnectionStats, TrafficSnapshot


# Well-known port to protocol/activity mapping
PORT_ACTIVITY: dict[int, str] = {
    20: "FTP Data Transfer",
    21: "FTP Control",
    22: "SSH Remote Access",
    23: "Telnet (insecure!)",
    25: "Sending Email (SMTP)",
    53: "DNS Lookup",
    67: "DHCP Server",
    68: "DHCP Client",
    80: "HTTP Web Browsing",
    110: "Checking Email (POP3)",
    123: "NTP Time Sync",
    143: "Checking Email (IMAP)",
    443: "HTTPS Secure Browsing",
    445: "Windows File Sharing (SMB)",
    465: "Sending Email (SMTPS)",
    587: "Sending Email (Submission)",
    853: "DNS over TLS",
    993: "Checking Email (IMAPS)",
    995: "Checking Email (POP3S)",
    1080: "SOCKS Proxy",
    1194: "OpenVPN",
    1433: "MS SQL Database",
    1883: "MQTT IoT Messaging",
    3306: "MySQL Database",
    3389: "Remote Desktop (RDP)",
    5060: "VoIP (SIP)",
    5222: "XMPP Chat",
    5353: "mDNS Discovery",
    5432: "PostgreSQL Database",
    5900: "VNC Remote Desktop",
    6379: "Redis Database",
    6443: "Kubernetes API",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
    8883: "MQTT over TLS",
    9200: "Elasticsearch",
    27017: "MongoDB Database",
}

# Streaming/app ports (ranges and known ports)
STREAMING_PORTS = {1935, 554, 8554}  # RTMP, RTSP
GAMING_PORTS = {25565, 27015, 27016, 3478, 3479}  # Minecraft, Source, STUN


@dataclass
class DeviceActivity:
    """Summary of what a specific device is doing."""
    ip: str
    total_bytes: int = 0
    total_packets: int = 0
    activities: list[str] = field(default_factory=list)
    dns_queries: list[str] = field(default_factory=list)
    http_sites: list[str] = field(default_factory=list)
    connections_count: int = 0
    protocols: set[str] = field(default_factory=set)


def analyze_connection(conn: ConnectionStats) -> str:
    """Describe what a connection is doing in human-readable terms."""
    port = conn.key.dst_port or conn.key.src_port

    # Check for DNS queries
    if conn.dns_queries:
        return f"DNS: {conn.dns_queries[-1]}"

    # Check for HTTP activity
    if conn.http_hosts:
        return f"Web: {conn.http_hosts[-1]}"

    # Known port activity
    if conn.key.dst_port in PORT_ACTIVITY:
        return PORT_ACTIVITY[conn.key.dst_port]
    if conn.key.src_port in PORT_ACTIVITY:
        return PORT_ACTIVITY[conn.key.src_port]

    # Streaming detection
    if port in STREAMING_PORTS:
        return "Media Streaming"
    if port in GAMING_PORTS:
        return "Gaming"

    # High port ranges heuristics
    if port >= 49152:
        return "Ephemeral/App Traffic"
    if 8000 <= port <= 9999:
        return "Web Service/API"

    return f"Port {port} Traffic"


def analyze_traffic(snapshot: TrafficSnapshot, local_ip: str | None = None) -> list[DeviceActivity]:
    """Analyze all captured traffic and summarize per-device activity.

    Args:
        snapshot: Current traffic snapshot from the sniffer.
        local_ip: Local machine IP to distinguish inbound vs outbound.

    Returns:
        List of DeviceActivity sorted by traffic volume.
    """
    devices: dict[str, DeviceActivity] = {}

    for key, conn in snapshot.connections.items():
        # Track both src and dst devices
        for ip in (key.src_ip, key.dst_ip):
            if ip not in devices:
                devices[ip] = DeviceActivity(ip=ip)

            dev = devices[ip]
            dev.protocols.add(key.protocol)

        # Attribute traffic to source
        src_dev = devices[key.src_ip]
        src_dev.total_bytes += conn.bytes_sent
        src_dev.total_packets += conn.packet_count
        src_dev.connections_count += 1

        # Determine activity
        activity = analyze_connection(conn)
        if activity and activity not in src_dev.activities:
            src_dev.activities.append(activity)

        # Aggregate DNS and HTTP
        for q in conn.dns_queries:
            if q not in src_dev.dns_queries:
                src_dev.dns_queries.append(q)
        for h in conn.http_hosts:
            if h not in src_dev.http_sites:
                src_dev.http_sites.append(h)

    # Sort by total bytes descending
    result = sorted(devices.values(), key=lambda d: d.total_bytes, reverse=True)

    # Tag local device
    if local_ip:
        for dev in result:
            if dev.ip == local_ip:
                dev.activities.insert(0, "(This machine)")
                break

    return result


def get_protocol_breakdown(snapshot: TrafficSnapshot) -> list[tuple[str, int, float]]:
    """Get protocol distribution as (name, count, percentage)."""
    total = snapshot.total_packets or 1
    result = []
    for proto, count in sorted(snapshot.protocol_counts.items(), key=lambda x: x[1], reverse=True):
        pct = (count / total) * 100
        result.append((proto, count, pct))
    return result


def get_top_talkers(snapshot: TrafficSnapshot, limit: int = 10) -> list[tuple[str, int]]:
    """Get top N IPs by traffic volume."""
    sorted_talkers = sorted(snapshot.top_talkers.items(), key=lambda x: x[1], reverse=True)
    return sorted_talkers[:limit]


def get_recent_dns(snapshot: TrafficSnapshot, limit: int = 20) -> list[tuple[float, str, str]]:
    """Get most recent DNS queries."""
    return snapshot.dns_log[-limit:]


def get_recent_http(snapshot: TrafficSnapshot, limit: int = 20) -> list[tuple[float, str, str, str]]:
    """Get most recent HTTP requests."""
    return snapshot.http_log[-limit:]
