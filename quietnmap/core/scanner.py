"""Main scanner engine — orchestrates host discovery, port scanning, and detection."""

from __future__ import annotations

import asyncio
import logging
import random
import time
from typing import AsyncIterator, Callable

from quietnmap.models import (
    HostResult,
    PortResult,
    ScanConfig,
    ScanSession,
    ScanType,
)
from quietnmap.core.host_discovery import ping_host
from quietnmap.core.tcp import get_scan_function, tcp_connect_scan
from quietnmap.core.udp import udp_scan

logger = logging.getLogger("quietnmap")


class ScanProgress:
    """Tracks scan progress for live dashboard updates."""

    def __init__(self, total_hosts: int, total_ports: int):
        self.total_hosts = total_hosts
        self.total_ports = total_ports
        self.hosts_completed = 0
        self.ports_scanned = 0
        self.open_ports_found = 0
        self.hosts_up = 0
        self.current_host = ""
        self.current_port = 0
        self._lock = asyncio.Lock()
        self.callbacks: list[Callable[[ScanProgress], None]] = []

    @property
    def total_tasks(self) -> int:
        return self.total_hosts * self.total_ports

    @property
    def percent(self) -> float:
        if self.total_tasks == 0:
            return 100.0
        return (self.ports_scanned / self.total_tasks) * 100

    async def update_port(self, host: str, port: int, is_open: bool) -> None:
        async with self._lock:
            self.ports_scanned += 1
            self.current_host = host
            self.current_port = port
            if is_open:
                self.open_ports_found += 1
        for cb in self.callbacks:
            cb(self)

    async def host_done(self, is_up: bool) -> None:
        async with self._lock:
            self.hosts_completed += 1
            if is_up:
                self.hosts_up += 1
        for cb in self.callbacks:
            cb(self)


class Scanner:
    """Async network scanner engine.

    Usage:
        config = ScanConfig(targets=["192.168.1.0/24"], ports=[22, 80, 443])
        scanner = Scanner(config)
        session = await scanner.run()
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.session = ScanSession(config=config)
        self.progress = ScanProgress(0, 0)
        self._semaphore: asyncio.Semaphore | None = None

    async def run(self) -> ScanSession:
        """Execute the full scan and return results."""
        self.session.start_time = time.time()
        self._semaphore = asyncio.Semaphore(self.config.max_concurrency)

        targets = self.config.resolve_targets()
        ports = self.config.resolve_ports()

        if self.config.randomize_hosts:
            random.shuffle(targets)
        if self.config.randomize_ports:
            random.shuffle(ports)

        self.progress = ScanProgress(len(targets), len(ports))

        logger.info(
            "Starting %s scan: %d host(s), %d port(s), concurrency=%d",
            self.config.scan_type.value, len(targets), len(ports),
            self.config.max_concurrency,
        )

        # Phase 1: Host discovery (skip if only scanning a few hosts)
        if len(targets) > 3:
            live_targets = await self._discover_hosts(targets)
        else:
            live_targets = targets

        if not live_targets:
            logger.warning("No live hosts found")
            self.session.end_time = time.time()
            return self.session

        logger.info("Scanning %d live host(s)", len(live_targets))

        # Phase 2: Port scanning
        host_tasks = [
            self._scan_host(ip, ports) for ip in live_targets
        ]
        host_results = await asyncio.gather(*host_tasks, return_exceptions=True)

        for result in host_results:
            if isinstance(result, HostResult):
                self.session.hosts.append(result)
            elif isinstance(result, Exception):
                logger.error("Host scan failed: %s", result)

        self.session.end_time = time.time()
        logger.info(
            "Scan complete: %d host(s) up, %d open port(s) in %.2fs",
            len(self.session.hosts_up),
            self.session.total_open_ports,
            self.session.duration,
        )
        return self.session

    async def run_stream(self) -> AsyncIterator[HostResult]:
        """Yield results as each host completes (for live output)."""
        self.session.start_time = time.time()
        self._semaphore = asyncio.Semaphore(self.config.max_concurrency)

        targets = self.config.resolve_targets()
        ports = self.config.resolve_ports()

        if self.config.randomize_hosts:
            random.shuffle(targets)
        if self.config.randomize_ports:
            random.shuffle(ports)

        self.progress = ScanProgress(len(targets), len(ports))

        # Discover hosts
        if len(targets) > 3:
            live_targets = await self._discover_hosts(targets)
        else:
            live_targets = targets

        # Scan and yield results
        tasks: dict[asyncio.Task, str] = {}
        for ip in live_targets:
            task = asyncio.create_task(self._scan_host(ip, ports))
            tasks[task] = ip

        for coro in asyncio.as_completed(list(tasks.keys())):
            try:
                result = await coro
                self.session.hosts.append(result)
                yield result
            except Exception as e:
                logger.error("Scan failed: %s", e)

        self.session.end_time = time.time()

    async def _discover_hosts(self, targets: list[str]) -> list[str]:
        """Ping sweep to find live hosts."""
        logger.info("Discovering live hosts among %d target(s)...", len(targets))
        live: list[str] = []

        async def _check(ip: str) -> tuple[str, bool]:
            assert self._semaphore is not None
            async with self._semaphore:
                is_up = await ping_host(ip, timeout=self.config.timeout)
                return ip, is_up

        tasks = [_check(ip) for ip in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, tuple):
                ip, is_up = r
                if is_up:
                    live.append(ip)
            elif isinstance(r, Exception):
                logger.debug("Discovery error: %s", r)

        logger.info("Found %d live host(s)", len(live))
        return live

    async def _scan_host(self, ip: str, ports: list[int]) -> HostResult:
        """Scan all ports on a single host."""
        host = HostResult(ip=ip, is_up=True, scan_start=time.time())

        # Select scan function
        if self.config.scan_type == ScanType.UDP:
            scan_fn = udp_scan
        else:
            scan_fn = get_scan_function(self.config.scan_type)

        # Scan all ports concurrently (bounded by semaphore)
        async def _scan_port(port: int) -> PortResult:
            assert self._semaphore is not None
            async with self._semaphore:
                # Stealth delay between packets
                if self.config.delay_ms > 0:
                    await asyncio.sleep(self.config.delay_ms / 1000.0)

                kwargs = {}
                if self.config.source_port is not None:
                    kwargs["source_port"] = self.config.source_port
                if self.config.ttl is not None:
                    kwargs["ttl"] = self.config.ttl

                for attempt in range(self.config.max_retries + 1):
                    result = await scan_fn(ip, port, self.config.timeout, **kwargs)
                    # Retry only if filtered (might be rate-limited)
                    if result.state.value != "filtered" or attempt == self.config.max_retries:
                        break

                await self.progress.update_port(ip, port, result.is_open)
                return result

        port_tasks = [_scan_port(p) for p in ports]
        port_results = await asyncio.gather(*port_tasks, return_exceptions=True)

        for r in port_results:
            if isinstance(r, PortResult):
                host.ports.append(r)
            elif isinstance(r, Exception):
                logger.debug("Port scan error on %s: %s", ip, r)

        # Sort ports by number
        host.ports.sort(key=lambda p: p.port)

        # Service detection on open ports
        if self.config.detect_services:
            await self._detect_services(host)

        # OS detection
        if self.config.detect_os:
            await self._detect_os(host)

        host.scan_end = time.time()
        await self.progress.host_done(is_up=True)
        return host

    async def _detect_services(self, host: HostResult) -> None:
        """Run service detection on open ports."""
        from quietnmap.core.service import detect_service

        async def _detect(port_result: PortResult) -> None:
            assert self._semaphore is not None
            async with self._semaphore:
                service = await detect_service(host.ip, port_result.port)
                port_result.service = service

        tasks = [_detect(p) for p in host.open_ports]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _detect_os(self, host: HostResult) -> None:
        """Run OS fingerprinting."""
        try:
            from quietnmap.fingerprint.os_detect import fingerprint_os
            guesses = await fingerprint_os(host.ip, host.open_ports)
            host.os_guesses = guesses
        except Exception as e:
            logger.debug("OS detection failed for %s: %s", host.ip, e)
