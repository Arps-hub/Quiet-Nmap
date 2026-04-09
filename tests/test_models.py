"""Tests for data models."""

import time

from quietnmap.models import (
    HostResult,
    OSGuess,
    PortResult,
    PortState,
    Protocol,
    ScanConfig,
    ScanSession,
    ScanType,
    ServiceInfo,
)


def test_port_result_is_open():
    p = PortResult(port=80, protocol=Protocol.TCP, state=PortState.OPEN)
    assert p.is_open is True

    p2 = PortResult(port=80, protocol=Protocol.TCP, state=PortState.CLOSED)
    assert p2.is_open is False

    p3 = PortResult(port=80, protocol=Protocol.TCP, state=PortState.OPEN_FILTERED)
    assert p3.is_open is True


def test_host_result_open_ports():
    host = HostResult(
        ip="192.168.1.1",
        is_up=True,
        ports=[
            PortResult(port=22, protocol=Protocol.TCP, state=PortState.OPEN),
            PortResult(port=80, protocol=Protocol.TCP, state=PortState.OPEN),
            PortResult(port=443, protocol=Protocol.TCP, state=PortState.CLOSED),
            PortResult(port=8080, protocol=Protocol.TCP, state=PortState.FILTERED),
        ],
    )
    assert len(host.open_ports) == 2
    assert host.open_ports[0].port == 22
    assert host.open_ports[1].port == 80


def test_host_result_best_os_guess():
    host = HostResult(
        ip="10.0.0.1",
        os_guesses=[
            OSGuess(name="Linux 5.x", confidence=0.7, family="Linux"),
            OSGuess(name="Windows 10", confidence=0.3, family="Windows"),
        ],
    )
    assert host.best_os_guess is not None
    assert host.best_os_guess.name == "Linux 5.x"

    empty_host = HostResult(ip="10.0.0.2")
    assert empty_host.best_os_guess is None


def test_scan_config_resolve_targets():
    config = ScanConfig(targets=["192.168.1.0/30"])
    ips = config.resolve_targets()
    assert "192.168.1.1" in ips
    assert "192.168.1.2" in ips

    config2 = ScanConfig(targets=["example.com"])
    ips2 = config2.resolve_targets()
    assert ips2 == ["example.com"]


def test_scan_config_resolve_ports():
    config = ScanConfig(ports=[22, 80, 443])
    assert config.resolve_ports() == [22, 80, 443]

    config_default = ScanConfig()
    ports = config_default.resolve_ports()
    assert len(ports) > 50  # Should return top 1000 ports


def test_service_info_str():
    s = ServiceInfo(name="ssh", product="OpenSSH", version="8.9")
    assert str(s) == "ssh OpenSSH 8.9"

    s2 = ServiceInfo()
    assert str(s2) == "unknown"


def test_scan_session_to_dict():
    config = ScanConfig(targets=["10.0.0.1"], ports=[22, 80])
    session = ScanSession(config=config, start_time=time.time())
    session.hosts.append(
        HostResult(
            ip="10.0.0.1",
            is_up=True,
            ports=[
                PortResult(
                    port=22, protocol=Protocol.TCP, state=PortState.OPEN,
                    service=ServiceInfo(name="ssh", product="OpenSSH", version="8.9"),
                ),
            ],
        )
    )
    session.end_time = time.time()

    data = session.to_dict()
    assert data["scanner"] == "quietnmap"
    assert data["summary"]["hosts_up"] == 1
    assert data["summary"]["total_open_ports"] == 1
    assert len(data["hosts"]) == 1
    assert data["hosts"][0]["ports"][0]["port"] == 22


def test_os_guess_str():
    g = OSGuess(name="Linux 5.x", confidence=0.85)
    assert "85%" in str(g)
    assert "Linux" in str(g)
