"""
vulnalyzer.ingest.osv
=====================
Fetches vulnerability advisories from the OSV API and stores them
(normalised) in the Vulnalyzer database.

OSV API: https://google.github.io/osv.dev/api/
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import requests

from vulnalyzer.core.db import get_conn, upsert_vulnerability, init_db

logger = logging.getLogger(__name__)

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL  = "https://api.osv.dev/v1/vulns/{id}"
TIMEOUT = 15


# ---------------------------------------------------------------------------
# OSV API wrappers
# ---------------------------------------------------------------------------

def query_osv(package: str, ecosystem: str, version: str | None = None) -> list[dict]:
    """
    Query OSV for all advisories affecting *package* in *ecosystem*.
    Optionally filters by *version*.

    Returns a list of raw OSV vulnerability dicts.
    """
    payload: dict[str, Any] = {
        "package": {"name": package, "ecosystem": ecosystem}
    }
    if version:
        payload["version"] = version

    try:
        resp = requests.post(OSV_QUERY_URL, json=payload, timeout=TIMEOUT)
        resp.raise_for_status()
        return resp.json().get("vulns", [])
    except requests.RequestException as exc:
        logger.error("OSV query failed for %s/%s: %s", ecosystem, package, exc)
        return []


def fetch_osv_vuln(osv_id: str) -> dict | None:
    """Fetch a single full advisory by its OSV id."""
    try:
        resp = requests.get(OSV_VULN_URL.format(id=osv_id), timeout=TIMEOUT)
        if resp.status_code == 200:
            return resp.json()
    except requests.RequestException as exc:
        logger.error("OSV fetch failed for %s: %s", osv_id, exc)
    return None


# ---------------------------------------------------------------------------
# Normalisation helpers (mirrors old simplify_vulns.py logic)
# ---------------------------------------------------------------------------

def _extract_severity(vuln: dict) -> str:
    sev_list = vuln.get("severity", [])
    if sev_list:
        score = sev_list[0].get("score", "").upper()
        for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if label in score:
                return label

    db = vuln.get("database_specific", {})
    if isinstance(db, dict):
        sev = str(db.get("severity", "")).upper()
        if sev:
            return sev

    return "UNKNOWN"


def _infer_vuln_type(vuln: dict) -> str:
    text = (vuln.get("summary", "") + " " + vuln.get("details", "")).lower()
    checks = [
        ("Prototype Pollution",             ["prototype pollution"]),
        ("Command Injection",               ["command injection"]),
        ("ReDoS",                           ["redos", "regular expression denial of service"]),
        ("Denial of Service",               ["denial of service"]),
        ("SQL Injection",                   ["sql injection"]),
        ("Path Traversal",                  ["path traversal", "directory traversal"]),
        ("Log Injection",                   ["log injection"]),
        ("XSS",                             ["xss", "cross-site scripting"]),
        ("SSRF",                            ["ssrf", "server-side request forgery"]),
        ("Remote Code Execution",           ["remote code execution", "rce"]),
        ("Arbitrary Code Execution",        ["arbitrary code execution"]),
        ("Deserialization",                 ["deserialization", "deserialisation"]),
        ("Open Redirect",                   ["open redirect"]),
        ("Information Disclosure",          ["information disclosure", "information exposure"]),
    ]
    for label, keywords in checks:
        if any(kw in text for kw in keywords):
            return label
    return "Unknown"


def _extract_risky_apis(vuln: dict) -> list[str]:
    text = vuln.get("details", "")
    found = re.findall(r"`([^`]+)`", text)
    seen: set[str] = set()
    out: list[str] = []
    for x in found:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out[:10]


def _simplify_ranges(affected: dict) -> list[dict]:
    out: list[dict] = []
    for rng in affected.get("ranges", []):
        events = rng.get("events", [])
        current: dict = {}
        for ev in events:
            if "introduced" in ev:
                if current:
                    out.append(current)
                current = {"introduced": ev["introduced"]}
            elif "fixed" in ev:
                current["fixed"] = ev["fixed"]
                out.append(current)
                current = {}
            elif "last_affected" in ev:
                current["last_affected"] = ev["last_affected"]
                out.append(current)
                current = {}
        if current:
            out.append(current)
    return out


def _best_fixed_versions(ranges: list[dict]) -> list[str]:
    return [r["fixed"] for r in ranges if "fixed" in r]


def normalise_osv_vuln(raw: dict) -> list[dict]:
    """
    Convert a raw OSV advisory (which may cover multiple packages) into a
    list of normalised vuln records — one per affected package/ecosystem pair.
    """
    records: list[dict] = []
    severity = _extract_severity(raw)
    vuln_type = _infer_vuln_type(raw)
    risky_apis = _extract_risky_apis(raw)

    for affected in raw.get("affected", []):
        pkg = affected.get("package", {})
        name = pkg.get("name")
        ecosystem = pkg.get("ecosystem")

        if not name or not ecosystem:
            continue

        ranges = _simplify_ranges(affected)
        fixed_versions = _best_fixed_versions(ranges)

        records.append({
            "osv_id":           raw["id"],
            "aliases":          raw.get("aliases", []),
            "package_name":     name,
            "ecosystem":        ecosystem,
            "summary":          raw.get("summary", ""),
            "severity":         severity,
            "vuln_type":        vuln_type,
            "affected_ranges":  ranges,
            "fixed_versions":   fixed_versions,
            "risky_apis":       risky_apis,
            "raw_json":         json.dumps(raw, ensure_ascii=False),
        })

    return records


# ---------------------------------------------------------------------------
# High-level ingest functions
# ---------------------------------------------------------------------------

def ingest_package(package: str, ecosystem: str, version: str | None = None) -> int:
    """
    Query OSV for *package*/*ecosystem*, normalise, and persist to DB.

    Returns number of new/updated records stored.
    """
    init_db()

    logger.info("Querying OSV: %s / %s%s", ecosystem, package,
                f" @ {version}" if version else "")

    raw_vulns = query_osv(package, ecosystem, version)
    if not raw_vulns:
        logger.info("No vulnerabilities found.")
        return 0

    logger.info("Found %d advisories from OSV.", len(raw_vulns))
    stored = 0

    with get_conn() as conn:
        for raw in raw_vulns:
            records = normalise_osv_vuln(raw)
            for rec in records:
                upsert_vulnerability(conn, rec)
                stored += 1

    logger.info("Stored/updated %d vulnerability records.", stored)
    return stored


def ingest_by_id(osv_id: str) -> bool:
    """Fetch a specific OSV advisory by id and store it."""
    init_db()
    raw = fetch_osv_vuln(osv_id)
    if not raw:
        logger.error("Could not fetch %s from OSV.", osv_id)
        return False

    with get_conn() as conn:
        for rec in normalise_osv_vuln(raw):
            upsert_vulnerability(conn, rec)
    logger.info("Stored advisory %s.", osv_id)
    return True


def list_ingested_packages() -> list[dict]:
    """Return distinct (package_name, ecosystem) pairs stored in the DB."""
    init_db()
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT DISTINCT package_name, ecosystem FROM vulnerabilities ORDER BY ecosystem, package_name"
        ).fetchall()
    return [dict(r) for r in rows]
