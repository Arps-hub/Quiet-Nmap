"""OS fingerprinting — identify target operating system from network behavior."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from quietnmap.models import OSGuess

if TYPE_CHECKING:
    from quietnmap.models import PortResult

logger = logging.getLogger("quietnmap.os")

# TTL-based OS guessing (initial TTL values)
TTL_SIGNATURES: list[tuple[range, str, str]] = [
    (range(0, 33), "Linux 2.4-2.6", "Linux"),
    (range(33, 65), "Linux/Unix", "Linux"),
    (range(65, 129), "Windows", "Windows"),
    (range(129, 256), "Solaris/AIX/Cisco", "Unix"),
]

# TCP window size patterns
WINDOW_SIGNATURES: dict[int, tuple[str, str]] = {
    5840: ("Linux 2.4", "Linux"),
    5720: ("Linux 2.6+", "Linux"),
    14600: ("Linux 3.x", "Linux"),
    29200: ("Linux 4.x+", "Linux"),
    65535: ("Windows XP/2003", "Windows"),
    8192: ("Windows 7/2008", "Windows"),
    65392: ("Windows 10/11", "Windows"),
    64240: ("Windows 10/Server 2019", "Windows"),
    16384: ("macOS/iOS", "macOS"),
    32768: ("FreeBSD/macOS", "BSD"),
}


async def fingerprint_os(
    ip: str, open_ports: list[PortResult],
) -> list[OSGuess]:
    """Attempt to fingerprint the target OS using multiple techniques."""
    guesses: list[OSGuess] = []

    # Technique 1: TTL analysis via TCP connection
    ttl_guess = await _ttl_fingerprint(ip, open_ports)
    if ttl_guess:
        guesses.append(ttl_guess)

    # Technique 2: TCP window size analysis
    window_guess = await _window_fingerprint(ip, open_ports)
    if window_guess:
        guesses.append(window_guess)

    # Technique 3: Port-based heuristics
    port_guess = _port_heuristic(open_ports)
    if port_guess:
        guesses.append(port_guess)

    # Merge guesses — boost confidence when multiple techniques agree
    return _merge_guesses(guesses)


async def _ttl_fingerprint(
    ip: str, open_ports: list[PortResult],
) -> OSGuess | None:
    """Fingerprint OS based on TTL value in TCP response."""
    if not open_ports:
        return None

    port = open_ports[0].port
    try:
        from scapy.all import IP, TCP, sr1, conf
        conf.verb = 0

        loop = asyncio.get_running_loop()

        def _probe() -> OSGuess | None:
            pkt = IP(dst=ip) / TCP(dport=port, flags="S")
            reply = sr1(pkt, timeout=2, verbose=0)
            if reply is None:
                return None
            ttl = reply.ttl
            for ttl_range, name, family in TTL_SIGNATURES:
                if ttl in ttl_range:
                    # Higher TTL specificity = higher confidence
                    confidence = 0.4
                    return OSGuess(
                        name=name, confidence=confidence, family=family,
                        details={"ttl": ttl},
                    )
            return None

        return await loop.run_in_executor(None, _probe)
    except (ImportError, PermissionError, OSError):
        return None


async def _window_fingerprint(
    ip: str, open_ports: list[PortResult],
) -> OSGuess | None:
    """Fingerprint OS based on TCP window size."""
    if not open_ports:
        return None

    port = open_ports[0].port
    try:
        from scapy.all import IP, TCP, sr1, conf
        conf.verb = 0

        loop = asyncio.get_running_loop()

        def _probe() -> OSGuess | None:
            pkt = IP(dst=ip) / TCP(dport=port, flags="S")
            reply = sr1(pkt, timeout=2, verbose=0)
            if reply is None:
                return None
            tcp_layer = reply.getlayer(TCP)
            if tcp_layer is None:
                return None
            window = tcp_layer.window
            if window in WINDOW_SIGNATURES:
                name, family = WINDOW_SIGNATURES[window]
                return OSGuess(
                    name=name, confidence=0.5, family=family,
                    details={"window_size": window},
                )
            # Check closest match
            closest = min(WINDOW_SIGNATURES.keys(), key=lambda w: abs(w - window))
            if abs(closest - window) < 1000:
                name, family = WINDOW_SIGNATURES[closest]
                return OSGuess(
                    name=name, confidence=0.3, family=family,
                    details={"window_size": window, "matched_window": closest},
                )
            return None

        return await loop.run_in_executor(None, _probe)
    except (ImportError, PermissionError, OSError):
        return None


def _port_heuristic(open_ports: list[PortResult]) -> OSGuess | None:
    """Guess OS based on which ports are open — rough but useful."""
    port_numbers = {p.port for p in open_ports}

    # Windows indicators
    windows_ports = {135, 139, 445, 3389, 5985}
    windows_score = len(port_numbers & windows_ports) / max(len(windows_ports), 1)

    # Linux indicators
    linux_ports = {22, 111, 2049, 6379, 9090}
    linux_score = len(port_numbers & linux_ports) / max(len(linux_ports), 1)

    # macOS indicators
    mac_ports = {548, 5900, 3689, 5000, 7000}
    mac_score = len(port_numbers & mac_ports) / max(len(mac_ports), 1)

    scores = [
        ("Windows", "Windows", windows_score),
        ("Linux", "Linux", linux_score),
        ("macOS", "macOS", mac_score),
    ]
    best_name, best_family, best_score = max(scores, key=lambda s: s[2])

    if best_score >= 0.2:
        return OSGuess(
            name=best_name, confidence=min(best_score, 0.6), family=best_family,
            details={"method": "port-heuristic"},
        )
    return None


def _merge_guesses(guesses: list[OSGuess]) -> list[OSGuess]:
    """Merge multiple OS guesses, boosting confidence when they agree."""
    if not guesses:
        return []

    # Group by family
    family_scores: dict[str, list[OSGuess]] = {}
    for g in guesses:
        family_scores.setdefault(g.family, []).append(g)

    merged: list[OSGuess] = []
    for family, group in family_scores.items():
        # Pick the most specific name
        best = max(group, key=lambda g: g.confidence)
        # Boost confidence based on agreement
        agreement_bonus = min(0.3, 0.15 * (len(group) - 1))
        best.confidence = min(0.95, best.confidence + agreement_bonus)
        merged.append(best)

    merged.sort(key=lambda g: g.confidence, reverse=True)
    return merged
