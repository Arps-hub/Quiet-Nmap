"""Service detection — banner grabbing and service identification."""

from __future__ import annotations

import asyncio
import logging
import re
import ssl

from quietnmap.models import ServiceInfo

logger = logging.getLogger("quietnmap.service")

# Well-known port to service name mapping
KNOWN_SERVICES: dict[int, str] = {
    7: "echo", 9: "discard", 13: "daytime", 21: "ftp", 22: "ssh",
    23: "telnet", 25: "smtp", 37: "time", 53: "dns", 79: "finger",
    80: "http", 81: "http", 88: "kerberos", 106: "pop3pw", 110: "pop3",
    111: "rpcbind", 113: "ident", 119: "nntp", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 179: "bgp", 389: "ldap", 427: "svrloc", 443: "https",
    445: "microsoft-ds", 465: "smtps", 513: "rlogin", 514: "syslog",
    515: "printer", 543: "klogin", 544: "kshell", 548: "afp", 554: "rtsp",
    587: "submission", 631: "ipp", 636: "ldaps", 873: "rsync", 990: "ftps",
    993: "imaps", 995: "pop3s", 1433: "ms-sql", 1521: "oracle",
    1723: "pptp", 1883: "mqtt", 2049: "nfs", 2121: "ftp-proxy",
    3000: "http-alt", 3306: "mysql", 3389: "ms-wbt-server", 4443: "https-alt",
    5000: "http-alt", 5432: "postgresql", 5672: "amqp", 5900: "vnc",
    5901: "vnc", 6379: "redis", 6443: "kubernetes", 8000: "http-alt",
    8008: "http-alt", 8080: "http-proxy", 8081: "http-proxy", 8443: "https-alt",
    8888: "http-alt", 9090: "http-proxy", 9100: "jetdirect", 9200: "elasticsearch",
    9999: "http-alt", 10000: "webmin", 11211: "memcached", 27017: "mongodb",
}

# Regex patterns for service identification from banners
SERVICE_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("ssh", re.compile(r"SSH-[\d.]+-([\w._-]+)", re.I), "product"),
    ("ftp", re.compile(r"220[\s-]+([\w\s._()-]+)(?:FTP|ready)", re.I), "product"),
    ("smtp", re.compile(r"220[\s-]+([\w.-]+)\s+(?:ESMTP|SMTP|Postfix|Sendmail)", re.I), "product"),
    ("http", re.compile(r"HTTP/[\d.]+\s+\d+.*?\r?\nServer:\s*([\w/._-]+)", re.I | re.S), "product"),
    ("pop3", re.compile(r"\+OK\s+([\w\s._-]+)", re.I), "product"),
    ("imap", re.compile(r"\*\s+OK\s+([\w\s._-]+)", re.I), "product"),
    ("mysql", re.compile(r"([\d.]+).*?mysql", re.I), "version"),
    ("redis", re.compile(r"\-ERR.*|(\+PONG)|redis_version:([\d.]+)", re.I), "version"),
    ("vnc", re.compile(r"RFB\s+([\d.]+)", re.I), "version"),
    ("mongodb", re.compile(r"MongoDB|mongod", re.I), "product"),
]

# Probes to send for services that don't send banners first
SERVICE_PROBES: dict[str, bytes] = {
    "http": b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n",
    "https": b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n",
    "redis": b"PING\r\n",
    "memcached": b"version\r\n",
}


async def detect_service(
    ip: str, port: int, timeout: float = 3.0,
) -> ServiceInfo:
    """Detect the service running on an open port via banner grabbing."""
    service = ServiceInfo()

    # Start with known service name
    if port in KNOWN_SERVICES:
        service.name = KNOWN_SERVICES[port]

    # Try banner grab
    banner = await _grab_banner(ip, port, timeout, service.name)
    if banner:
        service.banner = banner[:512]  # Cap banner length
        _identify_service(service, banner)

    return service


async def _grab_banner(
    ip: str, port: int, timeout: float, service_hint: str,
) -> str:
    """Connect to port, optionally send probe, and read response."""
    use_ssl = port in (443, 465, 636, 990, 993, 995, 8443, 4443, 6443)

    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx),
                timeout=timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        return ""

    try:
        # Some services send a banner immediately (SSH, FTP, SMTP)
        banner = ""
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
            banner = data.decode("utf-8", errors="replace").strip()
        except asyncio.TimeoutError:
            pass

        # If no banner, send a probe
        if not banner and service_hint in SERVICE_PROBES:
            probe = SERVICE_PROBES[service_hint].replace(b"target", ip.encode())
            writer.write(probe)
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(2048), timeout=2.0)
                banner = data.decode("utf-8", errors="replace").strip()
            except asyncio.TimeoutError:
                pass

        # Generic probe as last resort
        if not banner:
            writer.write(b"\r\n")
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
                banner = data.decode("utf-8", errors="replace").strip()
            except asyncio.TimeoutError:
                pass

        return banner
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def _identify_service(service: ServiceInfo, banner: str) -> None:
    """Parse banner to identify service name, product, and version."""
    for svc_name, pattern, field_type in SERVICE_PATTERNS:
        match = pattern.search(banner)
        if match:
            if not service.name or service.name == "unknown":
                service.name = svc_name

            value = match.group(1) if match.lastindex else ""
            if value:
                value = value.strip()
                if field_type == "product":
                    service.product = value
                elif field_type == "version":
                    service.version = value

            # Try to extract version from product string
            if service.product and not service.version:
                ver_match = re.search(r"(\d+\.\d+[\w.-]*)", service.product)
                if ver_match:
                    service.version = ver_match.group(1)
            break
