"""
Plugin system for custom attack modules.

Third-party modules placed in the ``plugins/`` directory are auto-
discovered at startup.  Each plugin must subclass ``BasePlugin`` and
implement ``generate_payloads()`` and ``analyze_response()``.
"""
from __future__ import annotations

import importlib.util
import os
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

__all__ = ["BasePlugin", "PluginLoader"]


class BasePlugin(ABC):
    """Interface that every PromptStrike plugin must implement."""

    name: str = "unnamed"
    version: str = "0.1"
    description: str = ""
    author: str = ""

    @abstractmethod
    def generate_payloads(self) -> List[str]:
        """Return a list of attack payloads."""
        ...

    @abstractmethod
    def analyze_response(self, response_text: str) -> Dict[str, Any]:
        """Return analysis dict for a response."""
        ...

    def on_load(self) -> None:
        """Called when plugin is loaded."""

    def on_unload(self) -> None:
        """Called when plugin is unloaded."""


class PluginLoader:
    """Discover and manage lifecycle of plugin modules."""

    def __init__(self, plugin_dir: Optional[str] = None) -> None:
        if plugin_dir is None:
            plugin_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "plugins")
        self.plugin_dir = plugin_dir
        self.plugins: Dict[str, BasePlugin] = {}

    def discover(self) -> List[str]:
        """Scan ``plugin_dir`` for Python files containing ``BasePlugin`` subclasses."""
        if not os.path.isdir(self.plugin_dir):
            return []
        found: List[str] = []
        for fname in os.listdir(self.plugin_dir):
            if not fname.endswith(".py") or fname.startswith("_"):
                continue
            path = os.path.join(self.plugin_dir, fname)
            try:
                spec = importlib.util.spec_from_file_location(fname[:-3], path)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)

                for attr_name in dir(mod):
                    attr = getattr(mod, attr_name)
                    if (isinstance(attr, type) and issubclass(attr, BasePlugin)
                            and attr is not BasePlugin):
                        plugin = attr()
                        plugin.on_load()
                        self.plugins[plugin.name] = plugin
                        found.append(plugin.name)
            except Exception as exc:
                print(f"  [!] Failed to load plugin {fname}: {exc}")
        return found

    def get(self, name: str) -> Optional[BasePlugin]:
        return self.plugins.get(name)

    def list(self) -> List[Dict[str, str]]:
        return [
            {"name": p.name, "version": p.version, "description": p.description, "author": p.author}
            for p in self.plugins.values()
        ]

    def unload(self, name: str) -> bool:
        p = self.plugins.pop(name, None)
        if p:
            p.on_unload()
        return p is not None

    def get_all_payloads(self) -> List[str]:
        """Aggregate payloads from every loaded plugin."""
        payloads: List[str] = []
        for p in self.plugins.values():
            try:
                payloads.extend(p.generate_payloads())
            except Exception:
                pass
        return payloads
