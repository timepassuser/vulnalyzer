"""
vulnalyzer.graph.builder
=========================
Builds / refreshes the vulnerability propagation graph stored in SQLite.

Graph topology
--------------
Repository      ──USES──►        PackageVersion
PackageVersion  ──INSTANCE_OF──► Package
PackageVersion  ──AFFECTED_BY──► Vulnerability
Repository      ──EXPOSED_TO──►  Vulnerability
Package         ──DEPENDS_ON──►  Package   (transitive propagation, with depth)
"""

from __future__ import annotations

import json
import logging

from vulnalyzer.core.db import (
    get_conn,
    init_db,
    clear_graph,
    upsert_graph_node,
    upsert_graph_edge,
    get_all_vulnerabilities,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Node / Edge IDs
# ---------------------------------------------------------------------------

def repo_node_id(platform: str, owner: str, name: str) -> str:
    return f"repo:{platform}/{owner}/{name}"


def package_node_id(name: str, ecosystem: str) -> str:
    return f"pkg:{name.lower()}:{ecosystem}"


def pkgver_node_id(name: str, version: str, ecosystem: str) -> str:
    return f"pkgver:{name.lower()}@{version}:{ecosystem}"


def vuln_node_id(osv_id: str) -> str:
    return f"vuln:{osv_id}"


# ---------------------------------------------------------------------------
# Severity Scoring
# ---------------------------------------------------------------------------

SEVERITY_MAP = {
    "CRITICAL": 10,
    "HIGH": 8,
    "MODERATE": 5,
    "MEDIUM": 5,
    "LOW": 2,
    "UNKNOWN": 1,
}


def severity_points(sev: str) -> int:
    if not sev:
        return 1
    return SEVERITY_MAP.get(sev.upper(), 1)


def finding_score(
    severity: str,
    is_direct: bool,
    depth: int = 1,
    is_dev: bool = False,
) -> float:
    """
    Score a single vulnerable finding.

    Formula:
        base_severity
        + 2        if direct dependency
        + 0.5      if transitive
        - 0.5 * (depth - 1)   depth penalty (direct = depth 1, no penalty)
        - 1        if dev-only dependency
    """
    base = float(severity_points(severity))

    if is_direct:
        base += 2
    else:
        base += 0.5

    # Each extra hop reduces score by 0.5 (depth=1 means direct, no penalty)
    depth_penalty = 0.5 * max(0, depth - 1)
    base = max(0.0, base - depth_penalty)

    if is_dev:
        base = max(0.0, base - 1.0)

    return round(base, 2)


# ---------------------------------------------------------------------------
# Graph Build
# ---------------------------------------------------------------------------

def build_graph() -> dict:
    """
    Full rebuild of graph with exposure scoring.
    """
    init_db()

    with get_conn() as conn:
        clear_graph(conn)

        vulns = {v["osv_id"]: v for v in get_all_vulnerabilities(conn)}

        scans = conn.execute(
            """
            SELECT
                rs.id          AS scan_id,
                rs.commit_sha,
                rs.branch_ref,
                rs.scanned_at,
                r.platform,
                r.owner,
                r.name         AS repo_name,
                r.url          AS repo_url
            FROM repo_scans rs
            JOIN repos r ON r.id = rs.repo_id
            WHERE rs.status = 'SCANNED_OK'
            """
        ).fetchall()

        for scan in scans:
            platform = scan["platform"]
            owner = scan["owner"]
            repo_name = scan["repo_name"]
            repo_url = scan["repo_url"]
            commit_sha = scan["commit_sha"]

            r_id = repo_node_id(platform, owner, repo_name)

            findings = conn.execute(
                "SELECT * FROM scan_findings WHERE scan_id=?",
                (scan["scan_id"],)
            ).fetchall()

            # repo aggregate metrics
            total_score = 0.0
            max_score = 0.0
            vuln_count = 0
            critical_count = 0
            direct_count = 0

            for f in findings:
                sev = f["severity"]
                is_direct = bool(f["is_direct"])
                is_dev = bool(f["is_dev"]) if "is_dev" in f.keys() else False
                depth = f["depth"] or 1

                score = finding_score(sev, is_direct, depth=depth, is_dev=is_dev)
                total_score += score
                max_score = max(max_score, score)
                vuln_count += 1

                if sev.upper() == "CRITICAL":
                    critical_count += 1
                if is_direct:
                    direct_count += 1

            repo_data = {
                "platform": platform,
                "owner": owner,
                "name": repo_name,
                "url": repo_url,
                "commit_sha": commit_sha,
                "branch_ref": scan["branch_ref"],
                "scanned_at": scan["scanned_at"],

                # NEW fields
                "exposure_score": round(total_score, 2),
                "max_risk": round(max_score, 2),
                "vuln_count": vuln_count,
                "critical_count": critical_count,
                "direct_vuln_count": direct_count,
            }

            upsert_graph_node(conn, r_id, "Repository", None, repo_data)

            # ---------------------------------------------------------------
            # Findings: nodes, USES/INSTANCE_OF/AFFECTED_BY/EXPOSED_TO edges
            # ---------------------------------------------------------------
            for f in findings:
                pkg_name = f["package_name"]
                ecosystem = f["ecosystem"]
                version = f["version_found"]
                is_direct = bool(f["is_direct"])
                is_dev = bool(f["is_dev"]) if "is_dev" in f.keys() else False
                depth = f["depth"] or 1
                osv_id = f["osv_id"]
                manifest = f["manifest_source"]
                sev = f["severity"]
                dependency_path = json.loads(f["dependency_path"] or "[]")

                p_id = package_node_id(pkg_name, ecosystem)
                pv_id = pkgver_node_id(pkg_name, version, ecosystem)
                v_id = vuln_node_id(osv_id)

                vuln = vulns.get(osv_id, {})

                upsert_graph_node(conn, p_id, "Package", ecosystem, {
                    "name": pkg_name,
                    "ecosystem": ecosystem,
                })

                upsert_graph_node(conn, pv_id, "PackageVersion", ecosystem, {
                    "name": pkg_name,
                    "version": version,
                    "ecosystem": ecosystem,
                })

                upsert_graph_node(conn, v_id, "Vulnerability", ecosystem, {
                    "osv_id": osv_id,
                    "severity": vuln.get("severity", "UNKNOWN"),
                    "summary": vuln.get("summary", ""),
                    "type": vuln.get("vuln_type", "Unknown"),
                    "aliases": vuln.get("aliases", []),
                    "fixed_versions": vuln.get("fixed_versions", []),
                    "ecosystem": ecosystem,
                })

                score = finding_score(sev, is_direct, depth=depth, is_dev=is_dev)

                upsert_graph_edge(conn, r_id, pv_id, "USES", {
                    "direct": is_direct,
                    "is_dev": is_dev,
                    "depth": depth,
                    "manifest": manifest,
                    "commit_sha": commit_sha,
                })

                upsert_graph_edge(conn, pv_id, p_id, "INSTANCE_OF", {})

                upsert_graph_edge(conn, pv_id, v_id, "AFFECTED_BY", {
                    "severity": sev
                })

                upsert_graph_edge(conn, r_id, v_id, "EXPOSED_TO", {
                    "via_package": pkg_name,
                    "via_version": version,
                    "ecosystem":   ecosystem,
                    "direct":      is_direct,
                    "is_dev":      is_dev,
                    "depth":       depth,
                    "severity":    sev,
                    "score":       score,
                })

                # -----------------------------------------------------------
                # DEPENDS_ON edges: walk the dependency_path chain and create
                # Package → Package edges for every parent→child hop.
                #
                # dependency_path is stored as an ordered list of package names
                # from root to the vulnerable package, e.g.:
                #   ["express", "qs", "lodash"]   means
                #   express DEPENDS_ON qs DEPENDS_ON lodash
                # -----------------------------------------------------------
                if len(dependency_path) >= 2:
                    for hop_depth, (parent_name, child_name) in enumerate(
                        zip(dependency_path, dependency_path[1:]), start=1
                    ):
                        parent_pid = package_node_id(parent_name, ecosystem)
                        child_pid  = package_node_id(child_name, ecosystem)

                        # Ensure both package nodes exist (parent may not have
                        # its own finding row if it isn't itself vulnerable)
                        upsert_graph_node(conn, parent_pid, "Package", ecosystem, {
                            "name": parent_name,
                            "ecosystem": ecosystem,
                        })
                        upsert_graph_node(conn, child_pid, "Package", ecosystem, {
                            "name": child_name,
                            "ecosystem": ecosystem,
                        })

                        upsert_graph_edge(conn, parent_pid, child_pid, "DEPENDS_ON", {
                            "ecosystem": ecosystem,
                            "depth":     hop_depth,
                        })

    with get_conn() as conn:
        nodes = conn.execute("SELECT COUNT(*) FROM graph_nodes").fetchone()[0]
        edges = conn.execute("SELECT COUNT(*) FROM graph_edges").fetchone()[0]

    logger.info("Graph built: %d nodes, %d edges", nodes, edges)

    return {
        "nodes": nodes,
        "edges": edges,
    }


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------

def blast_radius(conn, osv_id: str) -> list[dict]:
    """
    Ranked repositories affected by a CVE / OSV ID.
    Highest score first.
    """
    v_id = vuln_node_id(osv_id)

    rows = conn.execute(
        """
        SELECT
            gn.data AS repo_data,
            ge.data AS edge_data
        FROM graph_edges ge
        JOIN graph_nodes gn ON gn.id = ge.src
        WHERE ge.rel='EXPOSED_TO'
          AND ge.dst=?
        """,
        (v_id,)
    ).fetchall()

    result = []

    for row in rows:
        repo = json.loads(row["repo_data"])
        edge = json.loads(row["edge_data"])

        item = {
            "repo": repo["name"],
            "owner": repo["owner"],
            "url": repo["url"],
            "severity": edge.get("severity"),
            "direct": edge.get("direct"),
            "score": edge.get("score", 0),
            "repo_exposure_score": repo.get("exposure_score", 0),
            "via_package": edge.get("via_package"),
            "via_version": edge.get("via_version"),
        }

        result.append(item)

    result.sort(
        key=lambda x: (
            x["score"],
            x["repo_exposure_score"]
        ),
        reverse=True
    )

    return result


def repos_using_package(conn, package_name: str, ecosystem: str) -> list[dict]:
    """
    Return repos using package.
    """
    p_id = package_node_id(package_name, ecosystem)

    rows = conn.execute(
        """
        SELECT DISTINCT gn.data
        FROM graph_edges ge1
        JOIN graph_edges ge2 ON ge1.src = ge2.dst
        JOIN graph_nodes gn ON gn.id = ge2.src
        WHERE ge1.rel='INSTANCE_OF'
          AND ge1.dst=?
          AND ge2.rel='USES'
        """,
        (p_id,)
    ).fetchall()

    return [json.loads(r["data"]) for r in rows]


def cves_for_repo(conn, platform: str, owner: str, repo_name: str) -> list[dict]:
    """
    Return all CVEs a specific repo is exposed to, with per-finding detail.
    """
    r_id = repo_node_id(platform, owner, repo_name)

    rows = conn.execute(
        """
        SELECT
            ge.data  AS edge_data,
            gn.data  AS vuln_data
        FROM graph_edges ge
        JOIN graph_nodes gn ON gn.id = ge.dst
        WHERE ge.rel = 'EXPOSED_TO'
          AND ge.src = ?
        """,
        (r_id,),
    ).fetchall()

    result = []
    for row in rows:
        edge = json.loads(row["edge_data"])
        vuln = json.loads(row["vuln_data"])
        result.append({
            "osv_id":      vuln.get("osv_id"),
            "severity":    edge.get("severity"),
            "via_package": edge.get("via_package"),
            "via_version": edge.get("via_version"),
            "direct":      edge.get("direct"),
            "score":       edge.get("score"),
            "summary":     vuln.get("summary", ""),
        })

    result.sort(key=lambda x: x.get("score", 0), reverse=True)
    return result


def top_toxic_packages(conn, limit: int = 20) -> list[dict]:
    """
    Packages ranked by number of downstream repos they expose to CVEs.
    """
    rows = conn.execute(
        """
        SELECT
            ge.data              AS edge_data,
            COUNT(DISTINCT ge.src) AS affected_repo_count,
            COUNT(DISTINCT ge.dst) AS cve_count
        FROM graph_edges ge
        WHERE ge.rel = 'EXPOSED_TO'
        GROUP BY json_extract(ge.data, '$.via_package'),
                 json_extract(ge.data, '$.ecosystem')
        ORDER BY affected_repo_count DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    result = []
    for row in rows:
        edge = json.loads(row["edge_data"])
        result.append({
            "package":             edge.get("via_package", "unknown"),
            "ecosystem":           edge.get("ecosystem", "unknown"),
            "affected_repo_count": row["affected_repo_count"],
            "cve_count":           row["cve_count"],
        })
    return result

def propagation_path(conn, osv_id: str) -> list[dict]:
    """
    For each repo exposed to *osv_id*, return the full dependency chain
    that leads to the vulnerable package, reconstructed from DEPENDS_ON edges.

    Returns a list of dicts, one per (repo, path) pair:
        {
            "repo_url":   str,
            "owner":      str,
            "repo_name":  str,
            "ecosystem":  str,
            "path":       ["root-pkg", ..., "vuln-pkg"],
            "depth":      int,
            "score":      float,
            "severity":   str,
            "direct":     bool,
        }

    Sorted by score descending (highest-risk exposure first).
    """
    v_id = vuln_node_id(osv_id)

    # 1. Every repo->vuln exposure edge
    exposure_rows = conn.execute(
        """
        SELECT
            gn.data  AS repo_data,
            ge.data  AS edge_data
        FROM graph_edges ge
        JOIN graph_nodes gn ON gn.id = ge.src
        WHERE ge.rel = 'EXPOSED_TO'
          AND ge.dst = ?
        """,
        (v_id,),
    ).fetchall()

    # 2. Build child→parents map for BFS path reconstruction
    dep_rows = conn.execute(
        "SELECT src, dst FROM graph_edges WHERE rel = 'DEPENDS_ON'"
    ).fetchall()

    child_to_parents: dict[str, list[str]] = {}
    for dr in dep_rows:
        child_to_parents.setdefault(dr["dst"], []).append(dr["src"])

    results = []

    for row in exposure_rows:
        repo = json.loads(row["repo_data"])
        edge = json.loads(row["edge_data"])

        ecosystem = edge.get("ecosystem", "")
        vuln_pkg  = edge.get("via_package", "")
        is_direct = edge.get("direct", True)
        depth     = edge.get("depth", 1)
        score     = edge.get("score", 0)
        severity  = edge.get("severity", "UNKNOWN")

        if is_direct or depth <= 1:
            path = [vuln_pkg]
        else:
            vuln_pid   = package_node_id(vuln_pkg, ecosystem)
            path_nodes = _bfs_path_to_root(vuln_pid, child_to_parents, max_depth=depth + 2)
            path = [_pid_to_name(pid) for pid in path_nodes] if path_nodes else [vuln_pkg]

        results.append({
            "repo_url":  repo.get("url", ""),
            "owner":     repo.get("owner", ""),
            "repo_name": repo.get("name", ""),
            "ecosystem": ecosystem,
            "path":      path,
            "depth":     depth,
            "score":     score,
            "severity":  severity,
            "direct":    is_direct,
        })

    results.sort(key=lambda x: x["score"], reverse=True)
    return results


def _bfs_path_to_root(
    start: str,
    child_to_parents: dict[str, list[str]],
    max_depth: int,
) -> list[str] | None:
    """
    Walk DEPENDS_ON backwards from *start* (a vulnerable package node ID) to
    find the shortest chain from a root package to *start*.
    Returns the path [root, ..., start] or None if no path found within max_depth.
    """
    from collections import deque

    queue: deque[tuple[str, list[str]]] = deque()
    queue.append((start, [start]))
    visited: set[str] = {start}
    best: list[str] | None = None

    while queue:
        node, path = queue.popleft()
        if len(path) > max_depth:
            continue

        parents = child_to_parents.get(node, [])

        if not parents:
            candidate = list(reversed(path))
            if best is None or len(candidate) < len(best):
                best = candidate
            continue

        for parent in parents:
            if parent not in visited:
                visited.add(parent)
                queue.append((parent, path + [parent]))

    return best


def _pid_to_name(pid: str) -> str:
    """Extract plain package name from a node ID like 'pkg:lodash:npm'."""
    parts = pid.split(":", 2)
    return parts[1] if len(parts) >= 2 else pid
