"""Tests for TCP scan module."""

import asyncio

from quietnmap.models import PortState, Protocol
from quietnmap.core.tcp import tcp_connect_scan, get_scan_function, ScanType


def test_get_scan_function():
    fn = get_scan_function(ScanType.TCP_CONNECT)
    assert fn is tcp_connect_scan

    fn_syn = get_scan_function(ScanType.TCP_SYN)
    assert fn_syn is not None


def test_get_scan_function_invalid():
    try:
        get_scan_function(ScanType.UDP)
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


def test_connect_scan_closed_port():
    """Connect scan to a port that's almost certainly closed."""
    async def _test():
        # Port 1 is almost never open
        result = await tcp_connect_scan("127.0.0.1", 1, timeout=1.0)
        assert result.port == 1
        assert result.protocol == Protocol.TCP
        assert result.state in (PortState.CLOSED, PortState.FILTERED)
        assert result.response_time_ms > 0

    asyncio.run(_test())


def test_connect_scan_timeout():
    """Connect scan to non-routable address should timeout."""
    async def _test():
        # RFC 5737 documentation address — should timeout
        result = await tcp_connect_scan("192.0.2.1", 80, timeout=0.5)
        assert result.state in (PortState.FILTERED, PortState.CLOSED)

    asyncio.run(_test())
