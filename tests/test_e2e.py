#!/usr/bin/env python3
"""
tests/test_e2e.py
=================
End-to-end integration test using mocked OSV + GitHub data.

Simulates the exact scenario from the test repo:
  https://github.com/timepassuser/vuln_test
  - package.json:    lodash==4.17.15
  - requirements.txt: django==4.2.20

Runs the full pipeline:
  ingest → scan → build_graph → query → patch_request
"""

import sys
import json
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Point DB at a temp file
_tmp = tempfile.mktemp(suffix=".db")
os.environ["VULNALYZER_DB"] = _tmp

from vulnalyzer.core.db import init_db, get_conn
from vulnalyzer.ingest.osv import normalise_osv_vuln
from vulnalyzer.core.db import upsert_vulnerability
from vulnalyzer.scanner.engine import scan_repo
from vulnalyzer.graph.builder import build_graph, blast_radius, cves_for_repo, repos_using_package, propagation_path
from vulnalyzer.graph.export import get_graph_json
from vulnalyzer.graph.patch_request import generate_issue_title, generate_issue_body


# ---------------------------------------------------------------------------
# Mock OSV data (representative of real advisories)
# ---------------------------------------------------------------------------

LODASH_RAW = {
    "id": "GHSA-35jh-r3h4-6jhm",
    "aliases": ["CVE-2020-8203"],
    "summary": "Prototype Pollution in lodash",
    "details": "The `merge`, `mergeWith` functions are vulnerable.",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"}],
    "affected": [
        {
            "package": {"name": "lodash", "ecosystem": "npm"},
            "ranges": [
                {
                    "type": "SEMVER",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "4.17.19"},
                    ],
                }
            ],
        }
    ],
}

DJANGO_RAW = {
    "id": "GHSA-xxxx-yyyy-zzzz",
    "aliases": ["CVE-2024-12345"],
    "summary": "SQL Injection in Django ORM",
    "details": "The `QuerySet.filter()` call is vulnerable.",
    "database_specific": {"severity": "HIGH"},
    "affected": [
        {
            "package": {"name": "Django", "ecosystem": "PyPI"},
            "ranges": [
                {
                    "type": "SEMVER",
                    "events": [
                        {"introduced": "4.2"},
                        {"fixed": "4.2.21"},
                    ],
                }
            ],
        }
    ],
}

# ---------------------------------------------------------------------------
# Mock GitHub responses
# ---------------------------------------------------------------------------

PACKAGE_JSON = json.dumps({
    "dependencies": {
        "lodash": "4.17.15"
    }
})

# Simulates: express → qs → lodash (transitive chain depth=3)
PACKAGE_LOCK_JSON = json.dumps({
    "lockfileVersion": 2,
    "packages": {
        "node_modules/express": {
            "version": "4.18.2",
        },
        "node_modules/express/node_modules/qs": {
            "version": "6.11.0",
        },
        "node_modules/express/node_modules/qs/node_modules/lodash": {
            "version": "4.17.15",
        },
    }
})

REQUIREMENTS_TXT = "django==4.2.20\n"


def mock_get_revision(owner, repo):
    return {
        "revision_id": "abc123def456abc123def456abc123def456abc1",
        "revision_type": "git_commit",
        "branch_ref": "main",
    }


def mock_fetch_file(owner, repo, revision_id, filename):
    files = {
        "package.json":      PACKAGE_JSON,
        "package-lock.json": PACKAGE_LOCK_JSON,
        "requirements.txt":  REQUIREMENTS_TXT,
    }
    return files.get(filename)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_ingest():
    print("\n[1] Testing CVE ingestion …")
    init_db()
    with get_conn() as conn:
        for raw in [LODASH_RAW, DJANGO_RAW]:
            for rec in normalise_osv_vuln(raw):
                upsert_vulnerability(conn, rec)

    with get_conn() as conn:
        rows = conn.execute("SELECT osv_id, package_name, ecosystem FROM vulnerabilities").fetchall()

    assert len(rows) == 2, f"Expected 2 vulns, got {len(rows)}"
    ids = {r["osv_id"] for r in rows}
    assert "GHSA-35jh-r3h4-6jhm" in ids
    assert "GHSA-xxxx-yyyy-zzzz" in ids
    print(f"   ✅ Ingested {len(rows)} vulnerability records")


def test_scan():
    print("\n[2] Testing repo scan …")
    with patch("vulnalyzer.scanner.engine.get_revision", side_effect=mock_get_revision), \
         patch("vulnalyzer.scanner.engine.fetch_file",   side_effect=mock_fetch_file):

        result = scan_repo("https://github.com/timepassuser/vuln_test")

    assert result.status == "SCANNED_OK", f"Unexpected status: {result.status}"
    assert "package.json" in result.manifests_found
    assert "requirements.txt" in result.manifests_found
    assert len(result.findings) == 2, f"Expected 2 findings, got {len(result.findings)}"

    osv_ids = {f.osv_id for f in result.findings}
    assert "GHSA-35jh-r3h4-6jhm" in osv_ids, "Missing lodash CVE"
    assert "GHSA-xxxx-yyyy-zzzz" in osv_ids, "Missing django CVE"

    print(f"   ✅ Scan status: {result.status}")
    print(f"   ✅ Manifests  : {result.manifests_found}")
    print(f"   ✅ Findings   : {len(result.findings)}")
    for f in result.findings:
        print(f"        [{f.severity}] {f.package_name}@{f.version_found} → {f.osv_id}")

    return result


def test_dedup_scan():
    print("\n[3] Testing deduplication (same SHA should be skipped) …")
    with patch("vulnalyzer.scanner.engine.get_revision", side_effect=mock_get_revision), \
         patch("vulnalyzer.scanner.engine.fetch_file",   side_effect=mock_fetch_file):

        result = scan_repo("https://github.com/timepassuser/vuln_test")

    assert result.status == "SKIPPED_UNCHANGED", f"Expected skip, got {result.status}"
    print(f"   ✅ Correctly skipped (status={result.status})")


def test_build_graph():
    print("\n[4] Testing graph build …")
    summary = build_graph()
    assert summary["nodes"] > 0
    assert summary["edges"] > 0
    print(f"   ✅ Graph: {summary['nodes']} nodes, {summary['edges']} edges")


def test_graph_queries():
    print("\n[5] Testing graph queries …")
    with get_conn() as conn:
        # blast radius
        repos = blast_radius(conn, "GHSA-35jh-r3h4-6jhm")
        assert len(repos) >= 1, "Expected at least 1 repo in blast radius"
        print(f"   ✅ Blast radius for lodash CVE: {len(repos)} repo(s)")

        # cves for repo
        cves = cves_for_repo(conn, "github", "timepassuser", "vuln_test")
        assert len(cves) == 2, f"Expected 2 CVEs for repo, got {len(cves)}"
        print(f"   ✅ CVEs for vuln_test: {len(cves)}")

        # repos using package
        lodash_repos = repos_using_package(conn, "lodash", "npm")
        assert len(lodash_repos) >= 1
        print(f"   ✅ Repos using lodash/npm: {len(lodash_repos)}")


def test_graph_export():
    print("\n[6] Testing graph JSON export …")
    graph = get_graph_json()
    assert "nodes" in graph
    assert "edges" in graph
    assert graph["meta"]["node_count"] > 0
    print(f"   ✅ Graph JSON: {graph['meta']}")

    # Ecosystem filter
    npm_graph = get_graph_json(ecosystem="npm")
    py_graph  = get_graph_json(ecosystem="PyPI")
    print(f"   ✅ npm-only graph: {npm_graph['meta']['node_count']} nodes")
    print(f"   ✅ PyPI-only graph: {py_graph['meta']['node_count']} nodes")


def test_patch_request(scan_result):
    print("\n[7] Testing patch request generation …")
    title = generate_issue_title(scan_result)
    body  = generate_issue_body(scan_result)

    assert "Vulnalyzer" in title
    assert "GHSA-35jh-r3h4-6jhm" in body
    assert "GHSA-xxxx-yyyy-zzzz" in body
    assert "lodash" in body
    assert "django" in body.lower()
    print(f"   ✅ Title: {title}")
    print(f"   ✅ Body length: {len(body)} chars")


def test_plugin_parsers():
    print("\n[8] Testing manifest plugins …")
    from vulnalyzer.scanner.plugins.npm import PackageJsonPlugin, PackageLockPlugin
    from vulnalyzer.scanner.plugins.pypi import RequirementsTxtPlugin, PyprojectTomlPlugin
    from vulnalyzer.scanner.plugins.maven import PomXmlPlugin

    # npm
    pkg = PackageJsonPlugin().parse(PACKAGE_JSON)
    assert "lodash" in pkg
    assert pkg["lodash"].version == "4.17.15"
    assert pkg["lodash"].is_direct is True
    print(f"   ✅ PackageJsonPlugin: {list(pkg.keys())}")

    # PyPI
    reqs = RequirementsTxtPlugin().parse(REQUIREMENTS_TXT)
    assert "django" in reqs
    assert reqs["django"].version == "4.2.20"
    print(f"   ✅ RequirementsTxtPlugin: {list(reqs.keys())}")

    # pyproject.toml
    toml_text = '[project]\ndependencies = ["django==4.2.20", "requests==2.31.0"]\n'
    pp = PyprojectTomlPlugin().parse(toml_text)
    assert "django" in pp
    print(f"   ✅ PyprojectTomlPlugin: {list(pp.keys())}")

    # Maven pom.xml
    pom = """
    <dependencies>
      <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-core</artifactId>
        <version>5.3.20</version>
      </dependency>
    </dependencies>
    """
    mvn = PomXmlPlugin().parse(pom)
    assert "org.springframework:spring-core" in mvn
    assert mvn["org.springframework:spring-core"].version == "5.3.20"
    print(f"   ✅ PomXmlPlugin: {list(mvn.keys())}")


def test_version_matching():
    print("\n[9] Testing version matching …")
    from vulnalyzer.core.versions import version_in_range

    ranges = [{"introduced": "0", "fixed": "4.17.19"}]
    assert version_in_range("4.17.15", ranges) is True
    assert version_in_range("4.17.19", ranges) is False
    assert version_in_range("4.17.20", ranges) is False
    assert version_in_range("^4.17.15", ranges) is True  # npm prefix
    assert version_in_range("~4.17.15", ranges) is True  # npm prefix

    ranges2 = [{"introduced": "4.2", "fixed": "4.2.21"}]
    assert version_in_range("4.2.20", ranges2) is True
    assert version_in_range("4.2.21", ranges2) is False
    assert version_in_range("4.1.0",  ranges2) is False
    print("   ✅ All version range checks passed")


def test_propagation_path():
    print("\n[10] Testing DEPENDS_ON propagation paths …")
    with get_conn() as conn:
        # lodash CVE — both direct (package.json) and transitive (package-lock express→qs→lodash)
        chains = propagation_path(conn, "GHSA-35jh-r3h4-6jhm")

    assert len(chains) >= 1, f"Expected at least 1 chain, got {len(chains)}"

    # Verify the transitive chain was captured (depth > 1 means DEPENDS_ON edges exist)
    transitive = [c for c in chains if c["depth"] > 1]
    direct     = [c for c in chains if c["depth"] == 1]

    print(f"   ✅ Total chains: {len(chains)} ({len(direct)} direct, {len(transitive)} transitive)")

    for c in chains:
        arrow = " → ".join(c["path"])
        print(f"      [{c['severity']:<8}] score={c['score']}  depth={c['depth']}  {arrow}")

    # Scores should be sorted descending
    scores = [c["score"] for c in chains]
    assert scores == sorted(scores, reverse=True), "Chains not sorted by score descending"
    print("   ✅ Chains sorted by score (highest first)")

    # Transitive chain score must be lower than direct for the same severity
    if direct and transitive:
        assert direct[0]["score"] >= transitive[0]["score"], (
            "Direct dep should score >= transitive dep of same severity"
        )
        print("   ✅ Direct exposure scores higher than transitive")

    # Verify DEPENDS_ON edges exist in the graph
    with get_conn() as conn:
        dep_edges = conn.execute(
            "SELECT COUNT(*) as n FROM graph_edges WHERE rel='DEPENDS_ON'"
        ).fetchone()["n"]
    assert dep_edges > 0, "No DEPENDS_ON edges found in graph"
    print(f"   ✅ DEPENDS_ON edges in graph: {dep_edges}")


if __name__ == "__main__":
    try:
        test_plugin_parsers()
        test_version_matching()
        test_ingest()
        scan_result = test_scan()
        test_dedup_scan()
        test_build_graph()
        test_graph_queries()
        test_graph_export()
        test_patch_request(scan_result)
        test_propagation_path()

        print("\n" + "=" * 50)
        print("✅ ALL TESTS PASSED")
        print("=" * 50 + "\n")

    finally:
        # Clean up temp DB
        try:
            os.unlink(_tmp)
        except Exception:
            pass
