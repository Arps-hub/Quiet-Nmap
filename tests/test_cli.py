"""Tests for CLI port parsing."""

from quietnmap.cli import parse_ports


def test_parse_single_port():
    assert parse_ports("80") == [80]


def test_parse_multiple_ports():
    assert parse_ports("22,80,443") == [22, 80, 443]


def test_parse_port_range():
    ports = parse_ports("1-5")
    assert ports == [1, 2, 3, 4, 5]


def test_parse_mixed():
    ports = parse_ports("22,80,8000-8003")
    assert ports == [22, 80, 8000, 8001, 8002, 8003]


def test_parse_deduplicates():
    ports = parse_ports("80,80,80")
    assert ports == [80]


def test_parse_sorts():
    ports = parse_ports("443,80,22")
    assert ports == [22, 80, 443]
