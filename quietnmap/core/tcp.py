"""TCP scan techniques — SYN, connect, FIN, XMAS, NULL, ACK."""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from typing import TYPE_CHECKING

from quietnmap.models import PortResult, PortState, Protocol, ScanType

if TYPE_CHECKING:
    from quietnmap.models import ScanConfig

logger = logging.getLogger("quietnmap.tcp")


class _suppress_stderr:
    """Temporarily redirect stderr to devnull to silence scapy threading errors on Windows."""

    def __enter__(self):
        self._stderr_fd = sys.stderr.fileno()
        self._saved = os.dup(self._stderr_fd)
        self._devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(self._devnull, self._stderr_fd)
        return self

    def __exit__(self, *args):
        os.dup2(self._saved, self._stderr_fd)
        os.close(self._saved)
        os.close(self._devnull)


async def tcp_connect_scan(
    ip: str, port: int, timeout: float = 2.0
) -> PortResult:
    """Full TCP connect scan — works without root privileges."""
    start = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        elapsed = (time.monotonic() - start) * 1000
        writer.close()
        await writer.wait_closed()
        return PortResult(
            port=port,
            protocol=Protocol.TCP,
            state=PortState.OPEN,
            reason="syn-ack",
            response_time_ms=elapsed,
        )
    except ConnectionRefusedError:
        elapsed = (time.monotonic() - start) * 1000
        return PortResult(
            port=port,
            protocol=Protocol.TCP,
            state=PortState.CLOSED,
            reason="conn-refused",
            response_time_ms=elapsed,
        )
    except asyncio.TimeoutError:
        elapsed = (time.monotonic() - start) * 1000
        return PortResult(
            port=port,
            protocol=Protocol.TCP,
            state=PortState.FILTERED,
            reason="timeout",
            response_time_ms=elapsed,
        )
    except OSError as e:
        elapsed = (time.monotonic() - start) * 1000
        # Network unreachable, host down, etc.
        return PortResult(
            port=port,
            protocol=Protocol.TCP,
            state=PortState.FILTERED,
            reason=str(e),
            response_time_ms=elapsed,
        )


async def tcp_syn_scan(
    ip: str, port: int, timeout: float = 2.0, **kwargs: object
) -> PortResult:
    """SYN (half-open) scan using scapy raw packets.

    Requires root/admin. Falls back to connect scan if unavailable.
    """
    try:
        return await _raw_syn_scan(ip, port, timeout, **kwargs)
    except (PermissionError, ImportError, OSError) as e:
        logger.debug("SYN scan unavailable (%s), falling back to connect scan", e)
        return await tcp_connect_scan(ip, port, timeout)


async def _raw_syn_scan(
    ip: str,
    port: int,
    timeout: float,
    source_port: int | None = None,
    ttl: int | None = None,
    **_kwargs: object,
) -> PortResult:
    """Raw SYN scan implementation using scapy."""
    from scapy.all import IP, TCP, sr1, conf

    conf.verb = 0
    loop = asyncio.get_running_loop()
    start = time.monotonic()

    def _send_syn() -> PortResult:
        # Build SYN packet
        ip_layer = IP(dst=ip)
        if ttl is not None:
            ip_layer.ttl = ttl

        sport = source_port or int.from_bytes(os.urandom(2), "big") | 1024
        tcp_layer = TCP(sport=sport, dport=port, flags="S")

        pkt = ip_layer / tcp_layer
        with _suppress_stderr():
            reply = sr1(pkt, timeout=timeout, verbose=0)
        elapsed = (time.monotonic() - start) * 1000

        if reply is None:
            return PortResult(
                port=port, protocol=Protocol.TCP,
                state=PortState.FILTERED, reason="no-response",
                response_time_ms=elapsed,
            )

        tcp_reply = reply.getlayer(TCP)
        if tcp_reply is None:
            return PortResult(
                port=port, protocol=Protocol.TCP,
                state=PortState.FILTERED, reason="no-tcp-layer",
                response_time_ms=elapsed,
            )

        flags = tcp_reply.flags
        if flags == 0x12:  # SYN-ACK
            # Send RST to tear down (half-open)
            rst = IP(dst=ip) / TCP(sport=sport, dport=port, flags="R")
            with _suppress_stderr():
                sr1(rst, timeout=0.5, verbose=0)
            return PortResult(
                port=port, protocol=Protocol.TCP,
                state=PortState.OPEN, reason="syn-ack",
                response_time_ms=elapsed,
            )
        elif flags & 0x04:  # RST
            return PortResult(
                port=port, protocol=Protocol.TCP,
                state=PortState.CLOSED, reason="rst",
                response_time_ms=elapsed,
            )
        else:
            return PortResult(
                port=port, protocol=Protocol.TCP,
                state=PortState.FILTERED, reason=f"flags={flags:#x}",
                response_time_ms=elapsed,
            )

    return await loop.run_in_executor(None, _send_syn)


async def tcp_fin_scan(ip: str, port: int, timeout: float = 2.0) -> PortResult:
    """FIN scan — sends FIN flag. Open ports don't respond, closed send RST."""
    return await _stealth_flag_scan(ip, port, timeout, flags="F", scan_name="fin")


async def tcp_xmas_scan(ip: str, port: int, timeout: float = 2.0) -> PortResult:
    """XMAS scan — sends FIN+PSH+URG flags."""
    return await _stealth_flag_scan(ip, port, timeout, flags="FPU", scan_name="xmas")


async def tcp_null_scan(ip: str, port: int, timeout: float = 2.0) -> PortResult:
    """NULL scan — sends packet with no flags set."""
    return await _stealth_flag_scan(ip, port, timeout, flags="", scan_name="null")


async def tcp_ack_scan(ip: str, port: int, timeout: float = 2.0) -> PortResult:
    """ACK scan — determines if port is filtered (no RST = filtered)."""
    return await _stealth_flag_scan(ip, port, timeout, flags="A", scan_name="ack")


async def _stealth_flag_scan(
    ip: str, port: int, timeout: float, flags: str, scan_name: str,
) -> PortResult:
    """Generic stealth scan using custom TCP flags via scapy."""
    try:
        from scapy.all import IP, TCP, sr1, conf
        conf.verb = 0
    except ImportError:
        logger.warning("scapy required for %s scan", scan_name)
        return PortResult(
            port=port, protocol=Protocol.TCP,
            state=PortState.FILTERED, reason="scapy-unavailable",
        )

    loop = asyncio.get_running_loop()
    start = time.monotonic()

    def _send() -> PortResult:
        sport = int.from_bytes(os.urandom(2), "big") | 1024
        pkt = IP(dst=ip) / TCP(sport=sport, dport=port, flags=flags)
        with _suppress_stderr():
            reply = sr1(pkt, timeout=timeout, verbose=0)
        elapsed = (time.monotonic() - start) * 1000

        if reply is None:
            # No response = open|filtered for FIN/XMAS/NULL, filtered for ACK
            state = PortState.FILTERED if scan_name == "ack" else PortState.OPEN_FILTERED
            return PortResult(
                port=port, protocol=Protocol.TCP,
                state=state, reason="no-response",
                response_time_ms=elapsed,
            )

        tcp_reply = reply.getlayer(TCP)
        if tcp_reply and (tcp_reply.flags & 0x04):  # RST
            state = PortState.UNFILTERED if scan_name == "ack" else PortState.CLOSED
            return PortResult(
                port=port, protocol=Protocol.TCP,
                state=state, reason="rst",
                response_time_ms=elapsed,
            )

        return PortResult(
            port=port, protocol=Protocol.TCP,
            state=PortState.FILTERED, reason="unexpected-response",
            response_time_ms=elapsed,
        )

    return await loop.run_in_executor(None, _send)


def get_scan_function(scan_type: ScanType):
    """Return the appropriate scan function for a scan type."""
    mapping = {
        ScanType.TCP_SYN: tcp_syn_scan,
        ScanType.TCP_CONNECT: tcp_connect_scan,
        ScanType.TCP_FIN: tcp_fin_scan,
        ScanType.TCP_XMAS: tcp_xmas_scan,
        ScanType.TCP_NULL: tcp_null_scan,
        ScanType.TCP_ACK: tcp_ack_scan,
    }
    func = mapping.get(scan_type)
    if func is None:
        raise ValueError(f"Unsupported scan type: {scan_type}")
    return func
