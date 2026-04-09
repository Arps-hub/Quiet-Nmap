"""Host discovery — find which targets are alive before port scanning."""

from __future__ import annotations

import asyncio
import logging
import struct
import socket
import time

logger = logging.getLogger("quietnmap.discovery")


async def ping_host(ip: str, timeout: float = 2.0) -> bool:
    """Send ICMP echo request to check if host is up.

    Falls back to TCP connect on port 80 if ICMP fails (no root/admin).
    """
    # Try ICMP first
    if await _icmp_ping(ip, timeout):
        return True
    # Fallback: TCP connect to common ports
    return await _tcp_ping(ip, timeout)


async def _icmp_ping(ip: str, timeout: float) -> bool:
    """Raw ICMP echo request."""
    try:
        loop = asyncio.get_running_loop()
        return await asyncio.wait_for(
            loop.run_in_executor(None, _send_icmp_sync, ip, timeout),
            timeout=timeout + 0.5,
        )
    except (asyncio.TimeoutError, Exception):
        return False


def _send_icmp_sync(ip: str, timeout: float) -> bool:
    """Synchronous ICMP ping — runs in executor."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        # No raw socket permission — expected on non-root
        return False
    except OSError:
        return False

    try:
        sock.settimeout(timeout)
        # Build ICMP echo request
        icmp_type = 8  # Echo request
        icmp_code = 0
        icmp_id = 0x4E4D  # "NM"
        icmp_seq = 1
        payload = b"quietnmap-ping"

        # Checksum placeholder
        header = struct.pack("!BBHHH", icmp_type, icmp_code, 0, icmp_id, icmp_seq)
        checksum = _icmp_checksum(header + payload)
        header = struct.pack("!BBHHH", icmp_type, icmp_code, checksum, icmp_id, icmp_seq)

        sock.sendto(header + payload, (ip, 0))

        # Wait for reply
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            try:
                data, addr = sock.recvfrom(1024)
                # IP header is 20 bytes, ICMP starts after
                if len(data) >= 28:
                    icmp_reply_type = data[20]
                    if icmp_reply_type == 0:  # Echo reply
                        return True
            except socket.timeout:
                break
        return False
    finally:
        sock.close()


def _icmp_checksum(data: bytes) -> int:
    """Calculate ICMP checksum."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


async def _tcp_ping(ip: str, timeout: float) -> bool:
    """TCP connect to common ports as host discovery fallback."""
    probe_ports = [80, 443, 22, 445]

    async def try_port(port: int) -> bool:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (ConnectionRefusedError, OSError):
            # Connection refused = host is up, port is just closed
            return True
        except (asyncio.TimeoutError, Exception):
            return False

    tasks = [try_port(p) for p in probe_ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return any(r is True for r in results)


async def arp_discover(network: str, timeout: float = 2.0) -> list[str]:
    """ARP scan a local network to find live hosts.

    Requires scapy and root/admin privileges.
    """
    try:
        from scapy.all import ARP, Ether, srp

        loop = asyncio.get_running_loop()

        def _arp_sync() -> list[str]:
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
            answered, _ = srp(arp_request, timeout=timeout, verbose=False)
            return [received.psrc for _, received in answered]

        return await loop.run_in_executor(None, _arp_sync)
    except ImportError:
        logger.warning("scapy not available for ARP discovery")
        return []
    except Exception as e:
        logger.debug("ARP discovery failed: %s", e)
        return []
