"""
vulnalyzer.scanner.engine
==========================
Core scanning orchestrator (UPDATED with dependency depth support)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from vulnalyzer.core.db import (
    get_conn,
    get_all_vulnerabilities,
    upsert_repo,
    get_repo_last_sha,
    update_repo_last_scan,
    insert_scan,
    insert_finding,
    init_db,
)
from vulnalyzer.core.versions import version_in_range
from vulnalyzer.scanner.github import parse_github_url, get_revision, fetch_file
from vulnalyzer.scanner.plugins import get_plugin_for_file, all_manifest_filenames, DependencyInfo

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    package_name: str
    ecosystem: str
    version_found: str
    is_direct: bool
    manifest_source: str
    osv_id: str
    severity: str
    summary: str
    fixed_versions: list[str] = field(default_factory=list)
    is_dev: bool = False
    parent_package: str | None = None
    depth: int = 1
    dependency_path: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    repo_url: str
    platform: str
    owner: str
    repo_name: str
    revision_id: str
    branch_ref: str
    status: str
    manifests_found: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    skipped: bool = False

    @property
    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            sev = (f.severity or "UNKNOWN").upper()
            counts[sev] = counts.get(sev, 0) + 1
        return counts


# ---------------------------------------------------------------------------
# Matching logic
# ---------------------------------------------------------------------------

def _match_findings(
    deps: dict[str, DependencyInfo],
    ecosystem: str,
    vuln_rules: list[dict],
) -> list[Finding]:
    findings: list[Finding] = []

    for pkg_name, dep_info in deps.items():
        for rule in vuln_rules:
            if rule["ecosystem"] != ecosystem:
                continue

            if rule["package_name"].lower() != pkg_name.lower():
                continue

            if version_in_range(dep_info.version, rule["affected_ranges"]):
                        findings.append(Finding(
                            package_name=pkg_name,
                            ecosystem=ecosystem,
                            version_found=dep_info.version,
                            is_direct=dep_info.is_direct,
                            manifest_source=dep_info.source,
                            osv_id=rule["osv_id"],
                            severity=rule["severity"],
                            summary=rule["summary"],
                            fixed_versions=rule["fixed_versions"],
                            is_dev=dep_info.is_dev,
                            parent_package=dep_info.parent,
                            depth=dep_info.depth,
                            dependency_path=dep_info.dependency_path or [],
                        ))

    return findings


# ---------------------------------------------------------------------------
# Public scan API
# ---------------------------------------------------------------------------

def scan_repo(url: str, force: bool = False) -> ScanResult:
    init_db()

    owner, repo_name = parse_github_url(url)
    if not owner:
        return ScanResult(url, "github", "", "", "unknown", "unknown", "INVALID_URL")

    revision = get_revision(owner, repo_name)
    revision_id = revision["revision_id"]
    branch_ref = revision["branch_ref"]

    if revision_id == "unknown":
        return ScanResult(url, "github", owner, repo_name, revision_id, branch_ref, "FETCH_FAILED")

    with get_conn() as conn:
        repo_id = upsert_repo(conn, "github", owner, repo_name, url)
        last_sha = get_repo_last_sha(conn, repo_id)

    if not force and last_sha == revision_id:
        return ScanResult(url, "github", owner, repo_name, revision_id, branch_ref, "SKIPPED_UNCHANGED", skipped=True)

    with get_conn() as conn:
        vuln_rules = get_all_vulnerabilities(conn)

    all_findings: list[Finding] = []
    manifests_found: list[str] = []

    for filename in all_manifest_filenames():
        plugin = get_plugin_for_file(filename)
        if not plugin:
            continue

        text = fetch_file(owner, repo_name, revision_id, filename)
        if text is None:
            continue

        manifests_found.append(filename)

        try:
            deps = plugin.parse(text)
        except Exception:
            continue

        findings = _match_findings(deps, plugin.ecosystem, vuln_rules)
        all_findings.extend(findings)

    # Deduplicate: for the same (package, version, osv_id) triple, keep the
    # finding with the deepest / most informative dependency_path so that
    # DEPENDS_ON graph edges can be built from it later.
    seen: dict[tuple, Finding] = {}
    for f in all_findings:
        key = (f.package_name, f.version_found, f.osv_id)
        existing = seen.get(key)
        if existing is None or f.depth > existing.depth:
            seen[key] = f
    all_findings = list(seen.values())

    status = "SCANNED_OK" if manifests_found else "NO_MANIFEST"

    with get_conn() as conn:
        scan_id = insert_scan(conn, repo_id, revision_id, branch_ref, status, manifests_found)

        if scan_id:
            for f in all_findings:
                insert_finding(
                        conn,
                        scan_id,
                        f.package_name,
                        f.ecosystem,
                        f.version_found,
                        f.is_direct,
                        f.manifest_source,
                        f.osv_id,
                        f.severity,
                        is_dev=f.is_dev,
                        parent_package=f.parent_package,
                        depth=f.depth,
                        dependency_path=f.dependency_path,
                    )

        update_repo_last_scan(conn, repo_id, revision_id)

    return ScanResult(
        repo_url=url,
        platform="github",
        owner=owner,
        repo_name=repo_name,
        revision_id=revision_id,
        branch_ref=branch_ref,
        status=status,
        manifests_found=manifests_found,
        findings=all_findings,
    )


def load_repo_list(path: str) -> list[str]:
    """Read a text file of GitHub URLs, one per line. Skips blank lines and comments."""
    urls = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    # deduplicate while preserving order
    seen: set[str] = set()
    result = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            result.append(u)
    return result


def batch_scan(urls: list[str], force: bool = False) -> list[ScanResult]:
    """Scan multiple repos sequentially and return all results."""
    results = []
    for i, url in enumerate(urls, 1):
        logger.info("Scanning [%d/%d]: %s", i, len(urls), url)
        try:
            result = scan_repo(url, force=force)
        except Exception as exc:
            logger.error("Scan failed for %s: %s", url, exc)
            result = ScanResult(
                repo_url=url,
                platform="github",
                owner="",
                repo_name="",
                revision_id="unknown",
                branch_ref="unknown",
                status="ERROR",
            )
        results.append(result)
        logger.info(
            "  → %s  (%d finding(s))", result.status, len(result.findings)
        )
    return results