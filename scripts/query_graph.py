#!/usr/bin/env python3
"""
scripts/query_graph.py
======================
Query the graph for propagation insights.

Usage
-----
# All repos exposed to a specific CVE
python scripts/query_graph.py --cve GHSA-35jh-r3h4-6jhm

# All CVEs a specific repo is exposed to
python scripts/query_graph.py --repo https://github.com/timepassuser/vuln_test

# All repos using a specific package
python scripts/query_graph.py --package lodash --ecosystem npm

# Packages with most downstream impact (toxic package score)
python scripts/query_graph.py --toxic

# Generate a patch-request issue draft for a repo
python scripts/query_graph.py --repo https://github.com/owner/repo --patch-request
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnalyzer.core.logging_config import setup_logging
from vulnalyzer.core.db import get_conn, init_db
from vulnalyzer.graph.builder import (
    blast_radius,
    repos_using_package,
    cves_for_repo,
    top_toxic_packages,
    propagation_path,
)
from vulnalyzer.scanner.github import parse_github_url


def _print_repos(repos: list[dict]) -> None:
    if not repos:
        print("  (none)")
        return
    for r in repos:
        print(f"  {r.get('url', r.get('name', str(r)))}")


def _print_cves(cves: list[dict]) -> None:
    if not cves:
        print("  (none)")
        return
    for c in cves:
        sev = c.get("severity", "?")
        pkg = c.get("via_package", "?")
        print(f"  [{sev:<8}] {c.get('osv_id', '?')}  via {pkg}")
        if c.get("summary"):
            print(f"             {c['summary'][:80]}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Query the Vulnalyzer propagation graph.")
    parser.add_argument("--cve",           help="CVE/OSV id to find blast radius")
    parser.add_argument("--repo",          help="GitHub repo URL")
    parser.add_argument("--package",       help="Package name")
    parser.add_argument("--ecosystem",     help="Ecosystem (required with --package)")
    parser.add_argument("--toxic",         action="store_true",
                        help="Show top toxic packages by downstream impact")
    parser.add_argument("--propagation",   metavar="CVE_ID",
                        help="Show full dependency propagation chains for a CVE")
    parser.add_argument("--patch-request", action="store_true",
                        help="Print patch-request issue text (requires --repo)")
    parser.add_argument("--log-level",     default="WARNING")
    args = parser.parse_args()

    setup_logging(args.log_level)
    init_db()

    if args.cve:
        print(f"\nBlast radius for {args.cve}:")
        with get_conn() as conn:
            repos = blast_radius(conn, args.cve)
        print(f"  {len(repos)} repo(s) exposed\n")
        _print_repos(repos)

    elif args.package:
        if not args.ecosystem:
            print("--ecosystem is required with --package")
            sys.exit(1)
        print(f"\nRepos using {args.package} ({args.ecosystem}):")
        with get_conn() as conn:
            repos = repos_using_package(conn, args.package, args.ecosystem)
        print(f"  {len(repos)} repo(s)\n")
        _print_repos(repos)

    elif args.repo:
        owner, repo_name = parse_github_url(args.repo)
        if not owner:
            print(f"Invalid GitHub URL: {args.repo}")
            sys.exit(1)

        print(f"\nVulnerabilities for {owner}/{repo_name}:")
        with get_conn() as conn:
            cves = cves_for_repo(conn, "github", owner, repo_name)
        print(f"  {len(cves)} CVE(s) found\n")
        _print_cves(cves)

        if args.patch_request and cves:
            # Reconstruct a minimal ScanResult for patch request generation
            from vulnalyzer.scanner.engine import scan_repo
            from vulnalyzer.graph.patch_request import generate_issue_title, generate_issue_body
            print("\n" + "=" * 70)
            print("PATCH REQUEST ISSUE DRAFT")
            print("=" * 70)
            result = scan_repo(args.repo, force=False)
            if result.findings:
                print(f"\nTitle: {generate_issue_title(result)}\n")
                print(generate_issue_body(result))
            else:
                print("(no findings found in latest scan — run scan_repo.py first)")

    elif args.propagation:
        cve_id = args.propagation
        print(f"\nPropagation chains for {cve_id}:\n")
        with get_conn() as conn:
            chains = propagation_path(conn, cve_id)
        if not chains:
            print("  (no data — run batch_scan.py and build_graph.py first)")
        else:
            for c in chains:
                arrow_path = " → ".join(c["path"]) if c["path"] else c["repo_name"]
                print(
                    f"  [{c['severity']:<8}] score={c['score']:<5}  "
                    f"{c['owner']}/{c['repo_name']}"
                )
                print(f"             {arrow_path}")
                print()

    elif args.toxic:
        print("\nTop toxic packages by downstream repo impact:\n")
        with get_conn() as conn:
            packages = top_toxic_packages(conn)
        if not packages:
            print("  (no data — run batch_scan.py and build_graph.py first)")
        else:
            print(f"  {'Package':<25} {'Ecosystem':<8} {'Repos':>6} {'CVEs':>6}")
            print("  " + "-" * 55)
            for p in packages:
                print(
                    f"  {p['package']:<25} {p['ecosystem']:<8} "
                    f"{p['affected_repo_count']:>6} {p['cve_count']:>6}"
                )

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
