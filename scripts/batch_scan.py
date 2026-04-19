#!/usr/bin/env python3
"""
scripts/batch_scan.py
=====================
Scan a list of GitHub repositories from a text file.

File format (repos_to_scan.txt):
  # Comments are ignored
  https://github.com/owner/repo1
  https://github.com/owner/repo2

Usage
-----
python scripts/batch_scan.py --file repos_to_scan.txt
python scripts/batch_scan.py --file repos_to_scan.txt --force
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnalyzer.core.logging_config import setup_logging
from vulnalyzer.scanner.engine import batch_scan, load_repo_list


def main() -> None:
    parser = argparse.ArgumentParser(description="Batch-scan GitHub repositories.")
    parser.add_argument("--file",  "-f", required=True, help="Path to repos list file")
    parser.add_argument("--force",       action="store_true",
                        help="Re-scan repos even if commit SHA is unchanged")
    parser.add_argument("--log-level",   default="INFO")
    args = parser.parse_args()

    setup_logging(args.log_level)

    repo_file = Path(args.file)
    if not repo_file.exists():
        print(f"File not found: {repo_file}")
        sys.exit(1)

    urls = load_repo_list(str(repo_file))
    if not urls:
        print("No URLs found in file.")
        sys.exit(0)

    print(f"\nLoaded {len(urls)} unique repos from {repo_file}\n")

    results = batch_scan(urls, force=args.force)

    # Summary
    print("\n" + "=" * 60)
    print("BATCH SCAN SUMMARY")
    print("=" * 60)
    statuses: dict[str, int] = {}
    total_findings = 0
    for r in results:
        statuses[r.status] = statuses.get(r.status, 0) + 1
        total_findings += len(r.findings)

    for status, count in sorted(statuses.items()):
        print(f"  {status:<25} {count}")

    print(f"\n  Total findings : {total_findings}")
    print(f"  Total repos    : {len(results)}")
    print()

    # List repos with findings
    vulnerable = [r for r in results if r.findings]
    if vulnerable:
        print("Repos with findings:")
        for r in vulnerable:
            print(f"  {r.repo_url}  —  {len(r.findings)} finding(s)")
    else:
        print("✅ No vulnerabilities found across all repos.")


if __name__ == "__main__":
    main()
