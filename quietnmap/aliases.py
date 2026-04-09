"""Alias manager — map IPs to friendly names for readable output."""

from __future__ import annotations

import json
import logging
import socket
from pathlib import Path

logger = logging.getLogger("quietnmap.aliases")

# Default config directory
CONFIG_DIR = Path.home() / ".quietnmap"
ALIAS_FILE = CONFIG_DIR / "aliases.json"


def _ensure_config_dir() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def load_aliases() -> dict[str, str]:
    """Load aliases from disk. Returns {ip: name} mapping."""
    if not ALIAS_FILE.exists():
        return {}
    try:
        data = json.loads(ALIAS_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to load aliases: %s", e)
    return {}


def save_aliases(aliases: dict[str, str]) -> None:
    """Save aliases to disk."""
    _ensure_config_dir()
    ALIAS_FILE.write_text(
        json.dumps(aliases, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def add_alias(ip: str, name: str) -> None:
    """Add or update an alias for an IP."""
    aliases = load_aliases()
    aliases[ip] = name
    save_aliases(aliases)


def remove_alias(ip: str) -> bool:
    """Remove an alias. Returns True if it existed."""
    aliases = load_aliases()
    if ip in aliases:
        del aliases[ip]
        save_aliases(aliases)
        return True
    return False


def clear_aliases() -> int:
    """Remove all aliases. Returns count removed."""
    aliases = load_aliases()
    count = len(aliases)
    save_aliases({})
    return count


def list_aliases() -> dict[str, str]:
    """Return all aliases."""
    return load_aliases()


def get_local_ip() -> str:
    """Detect the local machine's IP address on the LAN."""
    try:
        # Connect to a public DNS to find our LAN IP (no data is sent)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def resolve_ip(ip: str, aliases: dict[str, str] | None = None,
               local_ip: str | None = None) -> str:
    """Resolve an IP to its display name.

    Priority:
        1. User-defined alias
        2. "(this pc)" if it matches the local IP
        3. Raw IP as-is

    Returns formatted string like "192.168.1.1 (Router)" or "192.168.1.50 (this pc)".
    """
    if aliases is None:
        aliases = load_aliases()
    if local_ip is None:
        local_ip = get_local_ip()

    name = aliases.get(ip)
    if name:
        return f"{ip} ({name})"
    if ip == local_ip:
        return f"{ip} (this pc)"
    return ip


def resolve_ip_short(ip: str, aliases: dict[str, str] | None = None,
                     local_ip: str | None = None) -> str:
    """Return just the alias/tag or IP if none exists.

    Returns "Router" or "this pc" or "192.168.1.50".
    """
    if aliases is None:
        aliases = load_aliases()
    if local_ip is None:
        local_ip = get_local_ip()

    name = aliases.get(ip)
    if name:
        return name
    if ip == local_ip:
        return "this pc"
    return ip
