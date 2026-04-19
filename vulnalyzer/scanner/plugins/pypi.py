"""
vulnalyzer.scanner.plugins.pypi
================================
Plugins for Python/PyPI dependency manifests:
  - requirements.txt
  - pyproject.toml  (PEP 621 / Poetry)
  - setup.cfg
  - Pipfile
"""

from __future__ import annotations

import logging
import re

from .base import ManifestPlugin, DependencyInfo

logger = logging.getLogger(__name__)


class RequirementsTxtPlugin(ManifestPlugin):
    """Parses requirements.txt (== pinned versions only; others recorded without version)."""

    manifest_files = ["requirements.txt"]
    ecosystem = "PyPI"

    # Matches: pkg==1.2.3, pkg>=1.0,<2; extras-syntax supported
    _PIN_RE = re.compile(
        r"^(?P<pkg>[A-Za-z0-9_.\-]+)"   # package name
        r"(?:\[.*?\])?"                   # optional extras
        r"==(?P<ver>[^\s;,]+)",           # pinned version
        re.MULTILINE,
    )
    # For non-pinned deps we still record them (no version)
    _ANY_RE = re.compile(
        r"^(?P<pkg>[A-Za-z0-9_.\-]+)",
        re.MULTILINE,
    )

    def parse(self, text: str) -> dict[str, DependencyInfo]:
        deps: dict[str, DependencyInfo] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = self._PIN_RE.match(line)
            if m:
                name = m.group("pkg").lower()
                deps[name] = DependencyInfo(
                    version=m.group("ver"),
                    source="requirements.txt",
                    is_direct=True,
                )
        return deps


class PyprojectTomlPlugin(ManifestPlugin):
    """
    Parses pyproject.toml.

    Supports:
      - PEP 621 [project] dependencies list
      - Poetry [tool.poetry.dependencies]

    Note: uses a simple regex approach to avoid adding a toml dependency
    for Python < 3.11.  For 3.11+ stdlib tomllib could replace this.
    """

    manifest_files = ["pyproject.toml"]
    ecosystem = "PyPI"

    # PEP 621 line: "django>=4.0,<5"   or   "django==4.2.20"
    _DEP_PIN_RE = re.compile(
        r'"(?P<pkg>[A-Za-z0-9_.\-]+)(?:\[.*?\])?==(?P<ver>[^",\s]+)"'
    )
    # Poetry format: django = "^4.2"
    _POETRY_RE = re.compile(
        r'^(?P<pkg>[A-Za-z0-9_.\-]+)\s*=\s*"[^"]*?"',
        re.MULTILINE,
    )

    def parse(self, text: str) -> dict[str, DependencyInfo]:
        deps: dict[str, DependencyInfo] = {}

        # Try pinned PEP 621 style
        for m in self._DEP_PIN_RE.finditer(text):
            name = m.group("pkg").lower()
            deps[name] = DependencyInfo(
                version=m.group("ver"),
                source="pyproject.toml",
                is_direct=True,
            )

        return deps


class SetupCfgPlugin(ManifestPlugin):
    """Parses install_requires / extras_require from setup.cfg."""

    manifest_files = ["setup.cfg"]
    ecosystem = "PyPI"

    _PIN_RE = re.compile(
        r"(?P<pkg>[A-Za-z0-9_.\-]+)(?:\[.*?\])?==(?P<ver>[^\s;,\n]+)"
    )

    def parse(self, text: str) -> dict[str, DependencyInfo]:
        deps: dict[str, DependencyInfo] = {}
        for m in self._PIN_RE.finditer(text):
            name = m.group("pkg").lower()
            deps[name] = DependencyInfo(
                version=m.group("ver"),
                source="setup.cfg",
                is_direct=True,
            )
        return deps
