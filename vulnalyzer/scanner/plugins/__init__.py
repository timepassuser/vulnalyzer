"""
vulnalyzer.scanner.plugins
===========================
Plugin registry.

All ``ManifestPlugin`` subclasses defined in this package are auto-registered.
Adding a new ecosystem is as simple as:
  1. Create a new module in this folder.
  2. Subclass ``ManifestPlugin``.
  3. Import it here.
"""

from __future__ import annotations

from .base import ManifestPlugin, DependencyInfo
from .npm import PackageJsonPlugin, PackageLockPlugin, YarnLockPlugin
from .pypi import RequirementsTxtPlugin, PyprojectTomlPlugin, SetupCfgPlugin
from .maven import PomXmlPlugin

# Master registry: filename -> plugin instance
_REGISTRY: dict[str, ManifestPlugin] = {}


def _register(plugin: ManifestPlugin) -> None:
    for filename in plugin.manifest_files:
        _REGISTRY[filename] = plugin


_register(PackageJsonPlugin())
_register(PackageLockPlugin())
_register(YarnLockPlugin())
_register(RequirementsTxtPlugin())
_register(PyprojectTomlPlugin())
_register(SetupCfgPlugin())
_register(PomXmlPlugin())


def get_plugin_for_file(filename: str) -> ManifestPlugin | None:
    return _REGISTRY.get(filename)


def all_manifest_filenames() -> list[str]:
    """Return every filename that at least one plugin handles."""
    return list(_REGISTRY.keys())


__all__ = [
    "ManifestPlugin",
    "DependencyInfo",
    "get_plugin_for_file",
    "all_manifest_filenames",
]
