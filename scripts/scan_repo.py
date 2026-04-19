#!/usr/bin/env python3
"""
scripts/scan_repo.py
====================
Scan a single GitHub repository for vulnerable dependencies.

Usage
-----
python scripts/scan_repo.py --url https://github.com/timepassuser/vuln_test
python scripts/scan_repo.py --url https://github.com/timepassuser/vuln_test --force
python scripts/scan_repo.py --url https://github.com/timepassuser/vuln_test --patch-request
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnalyzer.core.logging_config import setup_logging
from vulnalyzer.scanner.engine import scan_repo
from vulnalyzer.graph.patch_request import generate_issue_title, generate_issue_body


def print_result(result) -> None:
    print()
    print(f"  Repo      : {result.repo_url}")
    print(f"  Revision  : {result.revision_id[:12]}  [{result.branch_ref}]")
    print(f"  Status    : {result.status}")
    print(f"  Manifests : {', '.join(result.manifests_found) or 'none'}")
    print()

    if result.skipped:
        print("  (skipped — same commit SHA already scanned)")
        return

    if not result.findings:
        print("  ✅ No vulnerabilities found.")
        return

    print(f"  ⚠️  {len(result.findings)} finding(s):\n")
    for f in result.findings:
        dep = "direct" if f.is_direct else "transitive"
        fix = f.fixed_versions[0] if f.fixed_versions else "no fix yet"
        print(f"    [{f.severity:<8}] {f.package_name} @ {f.version_found}  ({dep})")
        print(f"             {f.osv_id}  →  fix: {fix}")
        print(f"             {f.summary[:80]}")
        print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan a single GitHub repository.")
    parser.add_argument("--url",           "-u", required=True, help="GitHub repo URL")
    parser.add_argument("--force",         "-f", action="store_true",
                        help="Re-scan even if commit SHA is unchanged")
    parser.add_argument("--patch-request", "-P", action="store_true",
                        help="Print a GitHub issue patch-request draft")
    parser.add_argument("--log-level",           default="INFO")
    args = parser.parse_args()

    setup_logging(args.log_level)

    print(f"\nScanning: {args.url}")
    result = scan_repo(args.url, force=args.force)
    print_result(result)

    if args.patch_request and result.findings:
        print("\n" + "=" * 70)
        print("PATCH REQUEST ISSUE DRAFT")
        print("=" * 70)
        print(f"\nTitle: {generate_issue_title(result)}\n")
        print(generate_issue_body(result))


if __name__ == "__main__":
    main()
