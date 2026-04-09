"""UDP port scanning."""

from __future__ import annotations

import asyncio
import logging
import time

from quietnmap.models import PortResult, PortState, Protocol

logger = logging.getLogger("quietnmap.udp")

# Well-known UDP probes to elicit responses
UDP_PROBES: dict[int, bytes] = {
    53: b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # DNS query
    123: b"\xe3\x00\x04\xfa" + b"\x00" * 44,  # NTP version request
    161: (  # SNMPv1 public community get-request
        b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04"
        b"\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b"
        b"\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
    ),
    1900: (  # SSDP M-SEARCH
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b"MAN: \"ssdp:discover\"\r\n"
        b"MX: 1\r\n"
        b"ST: ssdp:all\r\n\r\n"
    ),
}


async def udp_scan(ip: str, port: int, timeout: float = 3.0) -> PortResult:
    """UDP scan — send a probe and check for response or ICMP unreachable."""
    start = time.monotonic()

    try:
        loop = asyncio.get_event_loop()
        transport, protocol = await asyncio.wait_for(
            loop.create_datagram_endpoint(
                lambda: _UDPProbe(port),
                remote_addr=(ip, port),
            ),
            timeout=timeout,
        )
    except (asyncio.TimeoutError, OSError) as e:
        elapsed = (time.monotonic() - start) * 1000
        return PortResult(
            port=port, protocol=Protocol.UDP,
            state=PortState.OPEN_FILTERED, reason=str(e),
            response_time_ms=elapsed,
        )

    try:
        # Send appropriate probe
        probe = UDP_PROBES.get(port, b"\x00" * 8)
        transport.sendto(probe)

        # Wait for response
        try:
            await asyncio.wait_for(protocol.response_event.wait(), timeout=timeout)
            elapsed = (time.monotonic() - start) * 1000

            if protocol.got_response:
                return PortResult(
                    port=port, protocol=Protocol.UDP,
                    state=PortState.OPEN, reason="udp-response",
                    response_time_ms=elapsed,
                )
            else:
                return PortResult(
                    port=port, protocol=Protocol.UDP,
                    state=PortState.CLOSED, reason="icmp-unreachable",
                    response_time_ms=elapsed,
                )
        except asyncio.TimeoutError:
            elapsed = (time.monotonic() - start) * 1000
            return PortResult(
                port=port, protocol=Protocol.UDP,
                state=PortState.OPEN_FILTERED, reason="no-response",
                response_time_ms=elapsed,
            )
    finally:
        transport.close()


class _UDPProbe(asyncio.DatagramProtocol):
    """Asyncio protocol for UDP probing."""

    def __init__(self, port: int):
        self.port = port
        self.got_response = False
        self.response_data = b""
        self.response_event = asyncio.Event()

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.got_response = True
        self.response_data = data
        self.response_event.set()

    def error_received(self, exc: Exception) -> None:
        # ICMP unreachable typically surfaces here
        self.got_response = False
        self.response_event.set()

    def connection_lost(self, exc: Exception | None) -> None:
        if not self.response_event.is_set():
            self.response_event.set()
