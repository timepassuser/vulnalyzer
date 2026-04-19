"""
vulnalyzer.scanner.plugins.maven
=================================
Plugin for Maven (pom.xml) dependency manifests.

Version extraction from pom.xml without a full XML parser is limited;
this implementation handles the most common patterns.  A future iteration
should use ``xml.etree.ElementTree`` for robust parsing.
"""

from __future__ import annotations

import logging
import re

from .base import ManifestPlugin, DependencyInfo

logger = logging.getLogger(__name__)


class PomXmlPlugin(ManifestPlugin):
    """Parses direct dependencies from pom.xml."""

    manifest_files = ["pom.xml"]
    ecosystem = "Maven"

    # Matches a <dependency> block
    _DEP_BLOCK_RE = re.compile(r"<dependency>(.*?)</dependency>", re.DOTALL)
    # Extracts groupId, artifactId, version from a block
    _GROUP_RE   = re.compile(r"<groupId>\s*([^<]+)\s*</groupId>")
    _ARTIFACT_RE = re.compile(r"<artifactId>\s*([^<]+)\s*</artifactId>")
    _VERSION_RE  = re.compile(r"<version>\s*([^<$\{]+)\s*</version>")

    def parse(self, text: str) -> dict[str, DependencyInfo]:
        deps: dict[str, DependencyInfo] = {}

        for block_m in self._DEP_BLOCK_RE.finditer(text):
            block = block_m.group(1)
            g_m = self._GROUP_RE.search(block)
            a_m = self._ARTIFACT_RE.search(block)
            v_m = self._VERSION_RE.search(block)

            if not (g_m and a_m):
                continue

            group    = g_m.group(1).strip()
            artifact = a_m.group(1).strip()
            version  = v_m.group(1).strip() if v_m else "UNKNOWN"

            # Maven coordinates: groupId:artifactId
            key = f"{group}:{artifact}"
            deps[key] = DependencyInfo(
                version=version,
                source="pom.xml",
                is_direct=True,
            )

        return deps
