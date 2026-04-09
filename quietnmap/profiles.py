"""Scan profiles — pre-configured scan settings for common use cases."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from quietnmap.models import ScanConfig, ScanType


@dataclass
class ScanProfile:
    """Named scan profile with description and preset config overrides."""
    name: str
    description: str
    overrides: dict[str, Any]


# Built-in profiles
PROFILES: dict[str, ScanProfile] = {
    "quiet": ScanProfile(
        name="quiet",
        description="Stealth scan — slow timing, randomized, minimal footprint",
        overrides={
            "scan_type": ScanType.TCP_SYN,
            "max_concurrency": 50,
            "timeout": 5.0,
            "delay_ms": 100.0,
            "randomize_ports": True,
            "randomize_hosts": True,
            "max_retries": 0,
            "detect_services": False,
            "detect_os": False,
        },
    ),
    "normal": ScanProfile(
        name="normal",
        description="Balanced scan — moderate speed with service detection",
        overrides={
            "scan_type": ScanType.TCP_SYN,
            "max_concurrency": 500,
            "timeout": 2.0,
            "delay_ms": 0,
            "randomize_ports": True,
            "randomize_hosts": False,
            "max_retries": 1,
            "detect_services": True,
            "detect_os": False,
        },
    ),
    "aggressive": ScanProfile(
        name="aggressive",
        description="Fast and thorough — high concurrency, all detection enabled",
        overrides={
            "scan_type": ScanType.TCP_SYN,
            "max_concurrency": 2000,
            "timeout": 1.5,
            "delay_ms": 0,
            "randomize_ports": False,
            "randomize_hosts": False,
            "max_retries": 2,
            "detect_services": True,
            "detect_os": True,
        },
    ),
    "paranoid": ScanProfile(
        name="paranoid",
        description="Maximum stealth — very slow, one port at a time",
        overrides={
            "scan_type": ScanType.TCP_SYN,
            "max_concurrency": 1,
            "timeout": 10.0,
            "delay_ms": 15000.0,  # 15 seconds between probes
            "randomize_ports": True,
            "randomize_hosts": True,
            "max_retries": 0,
            "detect_services": False,
            "detect_os": False,
        },
    ),
    "quick": ScanProfile(
        name="quick",
        description="Fast scan of top 100 ports only",
        overrides={
            "scan_type": ScanType.TCP_CONNECT,
            "max_concurrency": 1000,
            "timeout": 1.0,
            "delay_ms": 0,
            "randomize_ports": False,
            "max_retries": 0,
            "detect_services": True,
            "detect_os": False,
        },
    ),
}

# Quick scan uses fewer ports
QUICK_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5432, 5900, 8080, 8443,
]


def apply_profile(config: ScanConfig, profile_name: str) -> ScanConfig:
    """Apply a named profile's overrides to a scan config."""
    profile = PROFILES.get(profile_name)
    if profile is None:
        available = ", ".join(PROFILES.keys())
        raise ValueError(f"Unknown profile '{profile_name}'. Available: {available}")

    for key, value in profile.overrides.items():
        if hasattr(config, key):
            setattr(config, key, value)

    # Quick profile uses fewer ports
    if profile_name == "quick" and not config.ports:
        config.ports = QUICK_PORTS

    return config


def list_profiles() -> list[ScanProfile]:
    """Return all available scan profiles."""
    return list(PROFILES.values())
