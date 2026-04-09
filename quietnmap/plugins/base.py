"""Plugin base class and loader for QuietNmap extensibility."""

from __future__ import annotations

import importlib
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from quietnmap.models import HostResult, ScanSession

logger = logging.getLogger("quietnmap.plugins")


@dataclass
class PluginInfo:
    """Metadata about a plugin."""
    name: str
    version: str = "0.0.0"
    author: str = ""
    description: str = ""


class ScanPlugin(ABC):
    """Base class for all QuietNmap plugins.

    Plugins can hook into the scan lifecycle:
    - on_scan_start: Called before scanning begins
    - on_host_complete: Called after each host is scanned
    - on_scan_complete: Called after all scanning is done
    - on_port_open: Called when an open port is found
    """

    @abstractmethod
    def info(self) -> PluginInfo:
        """Return plugin metadata."""
        ...

    async def on_scan_start(self, config: dict[str, Any]) -> None:
        """Called before scanning begins."""

    async def on_host_complete(self, host: HostResult) -> None:
        """Called after a host scan completes."""

    async def on_port_open(self, host_ip: str, port: int, service: str) -> None:
        """Called when an open port is discovered."""

    async def on_scan_complete(self, session: ScanSession) -> None:
        """Called after all scanning is complete."""


class PluginManager:
    """Discovers, loads, and manages plugins."""

    def __init__(self) -> None:
        self.plugins: list[ScanPlugin] = []

    def discover(self) -> list[PluginInfo]:
        """Discover available plugins from entry points."""
        discovered: list[PluginInfo] = []

        # Load from setuptools entry points
        try:
            eps = entry_points()
            plugin_eps = eps.get("quietnmap.plugins", [])
            for ep in plugin_eps:
                try:
                    plugin_cls = ep.load()
                    plugin = plugin_cls()
                    if isinstance(plugin, ScanPlugin):
                        self.plugins.append(plugin)
                        discovered.append(plugin.info())
                        logger.info("Loaded plugin: %s", plugin.info().name)
                except Exception as e:
                    logger.warning("Failed to load plugin %s: %s", ep.name, e)
        except Exception as e:
            logger.debug("Entry point discovery error: %s", e)

        return discovered

    def load_from_directory(self, directory: str | Path) -> list[PluginInfo]:
        """Load plugins from a directory of Python files."""
        directory = Path(directory).resolve()
        if not directory.is_dir():
            return []

        discovered: list[PluginInfo] = []
        for py_file in directory.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            # Ensure the file is actually inside the plugin directory (no symlink escapes)
            if not py_file.resolve().is_relative_to(directory):
                logger.warning("Skipping plugin outside directory: %s", py_file)
                continue
            try:
                spec = importlib.util.spec_from_file_location(
                    f"quietnmap_plugin_{py_file.stem}", py_file,
                )
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)  # type: ignore[union-attr]

                    # Find ScanPlugin subclasses in the module
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (
                            isinstance(attr, type)
                            and issubclass(attr, ScanPlugin)
                            and attr is not ScanPlugin
                        ):
                            plugin = attr()
                            self.plugins.append(plugin)
                            discovered.append(plugin.info())
                            logger.info("Loaded plugin from file: %s", py_file.name)
            except Exception as e:
                logger.warning("Failed to load plugin %s: %s", py_file.name, e)

        return discovered

    async def emit_scan_start(self, config: dict[str, Any]) -> None:
        for plugin in self.plugins:
            try:
                await plugin.on_scan_start(config)
            except Exception as e:
                logger.warning("Plugin %s error on scan_start: %s", plugin.info().name, e)

    async def emit_host_complete(self, host: HostResult) -> None:
        for plugin in self.plugins:
            try:
                await plugin.on_host_complete(host)
            except Exception as e:
                logger.warning("Plugin %s error on host_complete: %s", plugin.info().name, e)

    async def emit_port_open(self, host_ip: str, port: int, service: str) -> None:
        for plugin in self.plugins:
            try:
                await plugin.on_port_open(host_ip, port, service)
            except Exception as e:
                logger.warning("Plugin %s error on port_open: %s", plugin.info().name, e)

    async def emit_scan_complete(self, session: ScanSession) -> None:
        for plugin in self.plugins:
            try:
                await plugin.on_scan_complete(session)
            except Exception as e:
                logger.warning("Plugin %s error on scan_complete: %s", plugin.info().name, e)
