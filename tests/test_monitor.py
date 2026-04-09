"""Tests for the network traffic monitor module."""

import time
import pytest

from quietnmap.monitor.sniffer import ConnectionKey, ConnectionStats, TrafficSnapshot
from quietnmap.monitor.analyzer import (
    analyze_connection,
    analyze_traffic,
    get_protocol_breakdown,
    get_top_talkers,
    DeviceActivity,
)


class TestConnectionKey:
    def test_hash_and_eq(self):
        k1 = ConnectionKey("192.168.1.1", "10.0.0.1", 12345, 80, "TCP")
        k2 = ConnectionKey("192.168.1.1", "10.0.0.1", 12345, 80, "TCP")
        assert k1 == k2
        assert hash(k1) == hash(k2)

    def test_not_equal(self):
        k1 = ConnectionKey("192.168.1.1", "10.0.0.1", 12345, 80, "TCP")
        k2 = ConnectionKey("192.168.1.2", "10.0.0.1", 12345, 80, "TCP")
        assert k1 != k2

    def test_str(self):
        k = ConnectionKey("192.168.1.1", "10.0.0.1", 12345, 80, "TCP")
        assert "192.168.1.1:12345" in str(k)
        assert "10.0.0.1:80" in str(k)
        assert "TCP" in str(k)


class TestConnectionStats:
    def test_bytes_display_bytes(self):
        k = ConnectionKey("1.1.1.1", "2.2.2.2", 1000, 80, "TCP")
        c = ConnectionStats(key=k, bytes_sent=500)
        assert c.bytes_display == "500 B"

    def test_bytes_display_kb(self):
        k = ConnectionKey("1.1.1.1", "2.2.2.2", 1000, 80, "TCP")
        c = ConnectionStats(key=k, bytes_sent=2048)
        assert "KB" in c.bytes_display

    def test_bytes_display_mb(self):
        k = ConnectionKey("1.1.1.1", "2.2.2.2", 1000, 80, "TCP")
        c = ConnectionStats(key=k, bytes_sent=2_000_000)
        assert "MB" in c.bytes_display

    def test_duration(self):
        k = ConnectionKey("1.1.1.1", "2.2.2.2", 1000, 80, "TCP")
        c = ConnectionStats(key=k, first_seen=100.0, last_seen=105.0)
        assert c.duration == 5.0

    def test_duration_zero(self):
        k = ConnectionKey("1.1.1.1", "2.2.2.2", 1000, 80, "TCP")
        c = ConnectionStats(key=k)
        assert c.duration == 0.0


class TestAnalyzeConnection:
    def test_dns_activity(self):
        k = ConnectionKey("1.1.1.1", "8.8.8.8", 5000, 53, "UDP")
        c = ConnectionStats(key=k, dns_queries=["google.com"])
        result = analyze_connection(c)
        assert "DNS" in result
        assert "google.com" in result

    def test_http_activity(self):
        k = ConnectionKey("1.1.1.1", "93.184.216.34", 5000, 80, "TCP")
        c = ConnectionStats(key=k, http_hosts=["example.com"])
        result = analyze_connection(c)
        assert "Web" in result

    def test_known_port(self):
        k = ConnectionKey("1.1.1.1", "2.2.2.2", 5000, 22, "TCP")
        c = ConnectionStats(key=k)
        result = analyze_connection(c)
        assert "SSH" in result

    def test_https_port(self):
        k = ConnectionKey("1.1.1.1", "2.2.2.2", 5000, 443, "TCP")
        c = ConnectionStats(key=k)
        result = analyze_connection(c)
        assert "HTTPS" in result

    def test_unknown_port(self):
        k = ConnectionKey("1.1.1.1", "2.2.2.2", 5000, 31337, "TCP")
        c = ConnectionStats(key=k)
        result = analyze_connection(c)
        assert "31337" in result


class TestTrafficSnapshot:
    def test_packets_per_second(self):
        snap = TrafficSnapshot(total_packets=100, start_time=time.time() - 10)
        pps = snap.packets_per_second
        assert 9.0 <= pps <= 11.0

    def test_empty_snapshot(self):
        snap = TrafficSnapshot()
        assert snap.total_packets == 0
        assert snap.total_bytes == 0
        assert len(snap.connections) == 0


class TestAnalyzeTraffic:
    def _make_snapshot(self):
        snap = TrafficSnapshot()
        k1 = ConnectionKey("192.168.1.10", "8.8.8.8", 5000, 53, "UDP")
        k2 = ConnectionKey("192.168.1.10", "93.184.216.34", 5001, 443, "TCP")
        k3 = ConnectionKey("192.168.1.20", "10.0.0.1", 6000, 22, "TCP")

        snap.connections[k1] = ConnectionStats(
            key=k1, packet_count=10, bytes_sent=500,
            dns_queries=["google.com"],
        )
        snap.connections[k2] = ConnectionStats(
            key=k2, packet_count=50, bytes_sent=25000,
        )
        snap.connections[k3] = ConnectionStats(
            key=k3, packet_count=5, bytes_sent=200,
        )
        snap.total_packets = 65
        snap.total_bytes = 25700
        snap.protocol_counts = {"UDP": 10, "TCP": 55}
        snap.top_talkers = {"192.168.1.10": 25500, "192.168.1.20": 200}
        return snap

    def test_analyze_returns_devices(self):
        snap = self._make_snapshot()
        devices = analyze_traffic(snap)
        assert len(devices) > 0
        ips = [d.ip for d in devices]
        assert "192.168.1.10" in ips

    def test_sorted_by_volume(self):
        snap = self._make_snapshot()
        devices = analyze_traffic(snap)
        # First device should have the most traffic
        assert devices[0].total_bytes >= devices[-1].total_bytes

    def test_local_ip_tagged(self):
        snap = self._make_snapshot()
        devices = analyze_traffic(snap, local_ip="192.168.1.10")
        local_dev = [d for d in devices if d.ip == "192.168.1.10"][0]
        assert "(This machine)" in local_dev.activities

    def test_protocol_breakdown(self):
        snap = self._make_snapshot()
        breakdown = get_protocol_breakdown(snap)
        assert len(breakdown) == 2
        names = [b[0] for b in breakdown]
        assert "TCP" in names
        assert "UDP" in names

    def test_top_talkers(self):
        snap = self._make_snapshot()
        talkers = get_top_talkers(snap, limit=5)
        assert talkers[0][0] == "192.168.1.10"
        assert talkers[0][1] == 25500
