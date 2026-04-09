"""Tests for the alias manager."""

import json
import pytest
from pathlib import Path
from unittest.mock import patch

from quietnmap.aliases import (
    add_alias,
    clear_aliases,
    list_aliases,
    load_aliases,
    remove_alias,
    resolve_ip,
    resolve_ip_short,
    save_aliases,
)


@pytest.fixture
def alias_file(tmp_path):
    """Use a temp file for aliases during tests."""
    alias_path = tmp_path / "aliases.json"
    with patch("quietnmap.aliases.ALIAS_FILE", alias_path), \
         patch("quietnmap.aliases.CONFIG_DIR", tmp_path):
        yield alias_path


class TestLoadSave:
    def test_load_empty(self, alias_file):
        assert load_aliases() == {}

    def test_save_and_load(self, alias_file):
        save_aliases({"192.168.1.1": "Router"})
        assert load_aliases() == {"192.168.1.1": "Router"}

    def test_load_corrupted(self, alias_file):
        alias_file.write_text("not json!", encoding="utf-8")
        assert load_aliases() == {}

    def test_save_creates_file(self, alias_file):
        assert not alias_file.exists()
        save_aliases({"10.0.0.1": "Server"})
        assert alias_file.exists()


class TestAddRemove:
    def test_add_alias(self, alias_file):
        add_alias("192.168.1.1", "Router")
        assert load_aliases()["192.168.1.1"] == "Router"

    def test_add_overwrites(self, alias_file):
        add_alias("192.168.1.1", "Router")
        add_alias("192.168.1.1", "Gateway")
        assert load_aliases()["192.168.1.1"] == "Gateway"

    def test_remove_existing(self, alias_file):
        add_alias("192.168.1.1", "Router")
        assert remove_alias("192.168.1.1") is True
        assert "192.168.1.1" not in load_aliases()

    def test_remove_nonexistent(self, alias_file):
        assert remove_alias("10.0.0.99") is False

    def test_clear(self, alias_file):
        add_alias("192.168.1.1", "Router")
        add_alias("192.168.1.2", "Printer")
        count = clear_aliases()
        assert count == 2
        assert load_aliases() == {}

    def test_list_aliases(self, alias_file):
        add_alias("192.168.1.1", "Router")
        add_alias("192.168.1.50", "Phone")
        result = list_aliases()
        assert len(result) == 2
        assert result["192.168.1.1"] == "Router"
        assert result["192.168.1.50"] == "Phone"


class TestResolveIp:
    def test_alias_takes_priority(self):
        aliases = {"192.168.1.1": "Router"}
        result = resolve_ip("192.168.1.1", aliases=aliases, local_ip="192.168.1.50")
        assert result == "192.168.1.1 (Router)"

    def test_local_ip_tagged(self):
        result = resolve_ip("192.168.1.50", aliases={}, local_ip="192.168.1.50")
        assert result == "192.168.1.50 (this pc)"

    def test_unknown_ip_raw(self):
        result = resolve_ip("10.0.0.99", aliases={}, local_ip="192.168.1.50")
        assert result == "10.0.0.99"

    def test_alias_over_local(self):
        """User alias takes priority even for local IP."""
        aliases = {"192.168.1.50": "My Laptop"}
        result = resolve_ip("192.168.1.50", aliases=aliases, local_ip="192.168.1.50")
        assert result == "192.168.1.50 (My Laptop)"


class TestResolveIpShort:
    def test_alias_short(self):
        aliases = {"192.168.1.1": "Router"}
        assert resolve_ip_short("192.168.1.1", aliases=aliases, local_ip="x") == "Router"

    def test_local_short(self):
        assert resolve_ip_short("192.168.1.50", aliases={}, local_ip="192.168.1.50") == "this pc"

    def test_unknown_short(self):
        assert resolve_ip_short("10.0.0.99", aliases={}, local_ip="x") == "10.0.0.99"
