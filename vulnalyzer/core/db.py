from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(os.environ.get("VULNALYZER_DB", "data/vulnalyzer.db"))


# ----------------------------------------------------------------------
# Connection Helpers
# ----------------------------------------------------------------------

def _ensure_parent():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)


@contextmanager
def get_conn():
    _ensure_parent()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# ----------------------------------------------------------------------
# Schema
# ----------------------------------------------------------------------

def init_db():
    with get_conn() as conn:
        conn.executescript(
            """
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS repos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                platform TEXT NOT NULL,
                owner TEXT NOT NULL,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                last_scanned_sha TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(platform, owner, name)
            );

            CREATE TABLE IF NOT EXISTS repo_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_id INTEGER NOT NULL,
                commit_sha TEXT,
                branch_ref TEXT,
                status TEXT NOT NULL,
                scanned_at TEXT DEFAULT CURRENT_TIMESTAMP,
                error_message TEXT,
                FOREIGN KEY(repo_id) REFERENCES repos(id)
            );

            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                osv_id TEXT UNIQUE NOT NULL,
                aliases TEXT DEFAULT '[]',
                package_name TEXT,
                ecosystem TEXT,
                summary TEXT,
                details TEXT,
                severity TEXT DEFAULT 'UNKNOWN',
                fixed_versions TEXT DEFAULT '[]',
                published TEXT,
                modified TEXT,
                raw_json TEXT
            );

            CREATE TABLE IF NOT EXISTS scan_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,

                package_name TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                version_found TEXT NOT NULL,

                is_direct INTEGER DEFAULT 0,
                is_dev INTEGER DEFAULT 0,
                manifest_source TEXT,

                osv_id TEXT NOT NULL,
                severity TEXT DEFAULT 'UNKNOWN',

                -- NEW FIELDS
                parent_package TEXT,
                depth INTEGER DEFAULT 1,
                dependency_path TEXT DEFAULT '[]',

                created_at TEXT DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY(scan_id) REFERENCES repo_scans(id),
                FOREIGN KEY(osv_id) REFERENCES vulnerabilities(osv_id)
            );

            CREATE TABLE IF NOT EXISTS graph_nodes (
                id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                ecosystem TEXT,
                data TEXT DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS graph_edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src TEXT NOT NULL,
                dst TEXT NOT NULL,
                rel TEXT NOT NULL,
                data TEXT DEFAULT '{}',
                UNIQUE(src, dst, rel)
            );

            CREATE INDEX IF NOT EXISTS idx_findings_scan
                ON scan_findings(scan_id);

            CREATE INDEX IF NOT EXISTS idx_findings_osv
                ON scan_findings(osv_id);

            CREATE INDEX IF NOT EXISTS idx_findings_pkg
                ON scan_findings(package_name, ecosystem);

            CREATE INDEX IF NOT EXISTS idx_edges_src
                ON graph_edges(src);

            CREATE INDEX IF NOT EXISTS idx_edges_dst
                ON graph_edges(dst);
            """
        )


# ----------------------------------------------------------------------
# Repo Helpers
# ----------------------------------------------------------------------

def upsert_repo(conn, platform: str, owner: str, name: str, url: str) -> int:
    conn.execute(
        """
        INSERT OR IGNORE INTO repos(platform, owner, name, url)
        VALUES (?, ?, ?, ?)
        """,
        (platform, owner, name, url),
    )

    row = conn.execute(
        """
        SELECT id FROM repos
        WHERE platform=? AND owner=? AND name=?
        """,
        (platform, owner, name),
    ).fetchone()

    return row["id"]


def create_repo_scan(
    conn,
    repo_id: int,
    commit_sha: str | None,
    branch_ref: str | None,
    status: str,
    error_message: str | None = None,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO repo_scans(repo_id, commit_sha, branch_ref, status, error_message)
        VALUES (?, ?, ?, ?, ?)
        """,
        (repo_id, commit_sha, branch_ref, status, error_message),
    )
    return cur.lastrowid


def update_repo_scan_status(
    conn,
    scan_id: int,
    status: str,
    error_message: str | None = None,
):
    conn.execute(
        """
        UPDATE repo_scans
        SET status=?, error_message=?
        WHERE id=?
        """,
        (status, error_message, scan_id),
    )


def get_repo_last_sha(conn, repo_id: int) -> str | None:
    row = conn.execute(
        "SELECT last_scanned_sha FROM repos WHERE id=?",
        (repo_id,),
    ).fetchone()
    return row["last_scanned_sha"] if row else None


def update_repo_last_scan(conn, repo_id: int, sha: str):
    conn.execute(
        "UPDATE repos SET last_scanned_sha=? WHERE id=?",
        (sha, repo_id),
    )


def insert_scan(
    conn,
    repo_id: int,
    revision_id: str,
    branch_ref: str,
    status: str,
    manifests_found: list[str] | None = None,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO repo_scans(repo_id, commit_sha, branch_ref, status)
        VALUES (?, ?, ?, ?)
        """,
        (repo_id, revision_id, branch_ref, status),
    )
    return cur.lastrowid


# ----------------------------------------------------------------------
# Vulnerability Helpers
# ----------------------------------------------------------------------

def upsert_vulnerability(
    conn,
    rec_or_osv_id=None,
    *,
    osv_id: str | None = None,
    aliases=None,
    package_name=None,
    ecosystem=None,
    summary=None,
    details=None,
    severity="UNKNOWN",
    fixed_versions=None,
    published=None,
    modified=None,
    raw_json=None,
):
    """Accept either a dict (from normalise_osv_vuln) or explicit kwargs."""
    if isinstance(rec_or_osv_id, dict):
        rec = rec_or_osv_id
        osv_id        = rec["osv_id"]
        aliases       = rec.get("aliases")
        package_name  = rec.get("package_name")
        ecosystem     = rec.get("ecosystem")
        summary       = rec.get("summary")
        details       = rec.get("details")
        severity      = rec.get("severity", "UNKNOWN")
        fixed_versions = rec.get("fixed_versions")
        published     = rec.get("published")
        modified      = rec.get("modified")
        raw_json      = rec.get("raw_json")
    elif rec_or_osv_id is not None:
        osv_id = rec_or_osv_id

    conn.execute(
        """
        INSERT INTO vulnerabilities(
            osv_id, aliases, package_name, ecosystem,
            summary, details, severity, fixed_versions,
            published, modified, raw_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(osv_id) DO UPDATE SET
            aliases=excluded.aliases,
            package_name=excluded.package_name,
            ecosystem=excluded.ecosystem,
            summary=excluded.summary,
            details=excluded.details,
            severity=excluded.severity,
            fixed_versions=excluded.fixed_versions,
            published=excluded.published,
            modified=excluded.modified,
            raw_json=excluded.raw_json
        """,
        (
            osv_id,
            json.dumps(aliases or []),
            package_name,
            ecosystem,
            summary,
            details,
            severity,
            json.dumps(fixed_versions or []),
            published,
            modified,
            json.dumps(raw_json or {}) if not isinstance(raw_json, str) else raw_json,
        ),
    )


def get_all_vulnerabilities(conn) -> list[dict]:
    rows = conn.execute(
        """
        SELECT
            osv_id,
            aliases,
            package_name,
            ecosystem,
            summary,
            details,
            severity,
            fixed_versions,
            published,
            modified,
            raw_json
        FROM vulnerabilities
        """
    ).fetchall()

    result = []
    for r in rows:
        raw = json.loads(r["raw_json"]) if r["raw_json"] else {}
        fixed = json.loads(r["fixed_versions"]) if r["fixed_versions"] else []

        # Reconstruct affected_ranges from the raw OSV JSON so the engine
        # can do version-range matching without a separate table.
        affected_ranges: list[dict] = []
        for affected in raw.get("affected", []):
            pkg = affected.get("package", {})
            if pkg.get("name", "").lower() == (r["package_name"] or "").lower():
                for rng in affected.get("ranges", []):
                    events = rng.get("events", [])
                    current: dict = {}
                    for ev in events:
                        if "introduced" in ev:
                            if current:
                                affected_ranges.append(current)
                            current = {"introduced": ev["introduced"]}
                        elif "fixed" in ev:
                            current["fixed"] = ev["fixed"]
                            affected_ranges.append(current)
                            current = {}
                        elif "last_affected" in ev:
                            current["last_affected"] = ev["last_affected"]
                            affected_ranges.append(current)
                            current = {}
                    if current:
                        affected_ranges.append(current)

        result.append({
            "osv_id":          r["osv_id"],
            "aliases":         json.loads(r["aliases"]) if r["aliases"] else [],
            "package_name":    r["package_name"],
            "ecosystem":       r["ecosystem"],
            "summary":         r["summary"] or "",
            "details":         r["details"] or "",
            "severity":        r["severity"] or "UNKNOWN",
            "fixed_versions":  fixed,
            "affected_ranges": affected_ranges,
            "published":       r["published"],
            "modified":        r["modified"],
        })
    return result


# ----------------------------------------------------------------------
# Findings
# ----------------------------------------------------------------------

def insert_finding(
    conn,
    scan_id,
    package_name,
    ecosystem,
    version_found,
    is_direct,
    manifest_source,
    osv_id,
    severity,
    is_dev=False,
    parent_package=None,
    depth=1,
    dependency_path=None,
):
    conn.execute(
        """
        INSERT INTO scan_findings(
            scan_id,
            package_name,
            ecosystem,
            version_found,
            is_direct,
            is_dev,
            manifest_source,
            osv_id,
            severity,
            parent_package,
            depth,
            dependency_path
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            package_name,
            ecosystem,
            version_found,
            int(bool(is_direct)),
            int(bool(is_dev)),
            manifest_source,
            osv_id,
            severity,
            parent_package,
            depth,
            json.dumps(dependency_path or []),
        ),
    )


def findings_for_scan(conn, scan_id: int):
    return conn.execute(
        """
        SELECT * FROM scan_findings
        WHERE scan_id=?
        """,
        (scan_id,),
    ).fetchall()


# ----------------------------------------------------------------------
# Graph
# ----------------------------------------------------------------------

def clear_graph(conn):
    conn.execute("DELETE FROM graph_edges")
    conn.execute("DELETE FROM graph_nodes")


def upsert_graph_node(conn, node_id, label, ecosystem=None, data=None):
    conn.execute(
        """
        INSERT INTO graph_nodes(id, label, ecosystem, data)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            label=excluded.label,
            ecosystem=excluded.ecosystem,
            data=excluded.data
        """,
        (
            node_id,
            label,
            ecosystem,
            json.dumps(data or {}),
        ),
    )


def upsert_graph_edge(conn, src, dst, rel, data=None):
    conn.execute(
        """
        INSERT INTO graph_edges(src, dst, rel, data)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(src, dst, rel) DO UPDATE SET
            data=excluded.data
        """,
        (
            src,
            dst,
            rel,
            json.dumps(data or {}),
        ),
    )


def graph_nodes(conn):
    return conn.execute("SELECT * FROM graph_nodes").fetchall()


def graph_edges(conn):
    return conn.execute("SELECT * FROM graph_edges").fetchall()


def get_all_graph_nodes(conn, ecosystem: str | None = None) -> list[dict]:
    if ecosystem:
        rows = conn.execute(
            "SELECT * FROM graph_nodes WHERE ecosystem=? OR ecosystem IS NULL",
            (ecosystem,),
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM graph_nodes").fetchall()
    return [
        {
            "id": r["id"],
            "label": r["label"],
            "ecosystem": r["ecosystem"],
            "data": json.loads(r["data"]) if r["data"] else {},
        }
        for r in rows
    ]


def get_all_graph_edges(conn) -> list[dict]:
    rows = conn.execute("SELECT * FROM graph_edges").fetchall()
    return [
        {
            "id": r["id"],
            "src": r["src"],
            "dst": r["dst"],
            "rel": r["rel"],
            "data": json.loads(r["data"]) if r["data"] else {},
        }
        for r in rows
    ]