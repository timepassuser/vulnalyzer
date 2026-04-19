from __future__ import annotations

import json
import logging
import re

from .base import ManifestPlugin, DependencyInfo

logger = logging.getLogger(__name__)


class PackageJsonPlugin(ManifestPlugin):
    manifest_files = ["package.json"]
    ecosystem = "npm"

    def parse(self, text: str):
        try:
            data = json.loads(text)
        except Exception:
            return {}

        out = {}

        for section in ("dependencies", "devDependencies", "peerDependencies"):
            is_dev = section == "devDependencies"
            for pkg, ver in data.get(section, {}).items():
                out[pkg] = DependencyInfo(
                    version=str(ver),
                    source="package.json",
                    is_direct=True,
                    is_dev=is_dev,
                    parent=None,
                    depth=1,
                    dependency_path=[pkg],
                )
        return out


class PackageLockPlugin(ManifestPlugin):
    manifest_files = ["package-lock.json"]
    ecosystem = "npm"

    def parse(self, text: str):
        try:
            data = json.loads(text)
        except Exception:
            return {}

        out = {}

        # npm v2/v3
        if "packages" in data:
            for pkg_path, meta in data["packages"].items():
                if not pkg_path.startswith("node_modules/"):
                    continue

                rel = pkg_path.split("node_modules/")
                chain = [x for x in rel if x]
                pkg_name = chain[-1]

                version = meta.get("version")
                if not version:
                    continue

                parent = chain[-2] if len(chain) > 1 else None
                depth = len(chain)

                out[pkg_name] = DependencyInfo(
                    version=version,
                    source="package-lock.json",
                    is_direct=(depth == 1),
                    parent=parent,
                    depth=depth,
                    dependency_path=chain,
                )

        elif "dependencies" in data:
            self._walk_legacy(data["dependencies"], out, None, 1, [])

        return out

    def _walk_legacy(self, deps, out, parent, depth, path):
        for pkg, meta in deps.items():
            ver = meta.get("version")
            if ver:
                out[pkg] = DependencyInfo(
                    version=ver,
                    source="package-lock.json",
                    is_direct=(depth == 1),
                    parent=parent,
                    depth=depth,
                    dependency_path=path + [pkg],
                )

            children = meta.get("dependencies", {})
            if children:
                self._walk_legacy(children, out, pkg, depth + 1, path + [pkg])


class YarnLockPlugin(ManifestPlugin):
    manifest_files = ["yarn.lock"]
    ecosystem = "npm"

    _ENTRY_RE = re.compile(r'^"?(?P<name>[^@"]+)@', re.MULTILINE)
    _VERSION_RE = re.compile(r'^\s+version\s+"?(?P<ver>[^"\n]+)"?', re.MULTILINE)

    def parse(self, text: str):
        out = {}
        blocks = re.split(r"\n{2,}", text.strip())

        for block in blocks:
            if not block:
                continue

            a = self._ENTRY_RE.search(block)
            b = self._VERSION_RE.search(block)

            if a and b:
                pkg = a.group("n")
                ver = b.group("ver")

                out[pkg] = DependencyInfo(
                    version=ver,
                    source="yarn.lock",
                    is_direct=False,
                    parent=None,
                    depth=2,
                    dependency_path=[pkg],
                )

        return out