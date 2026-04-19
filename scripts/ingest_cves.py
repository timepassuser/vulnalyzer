#!/usr/bin/env python3
"""
scripts/ingest_cves.py
======================
Ingest vulnerability advisories from the OSV API into the Vulnalyzer database.

Usage
-----
# Query all known CVEs for a package
python scripts/ingest_cves.py --package lodash --ecosystem npm
python scripts/ingest_cves.py --package django  --ecosystem PyPI

# Query for a specific version
python scripts/ingest_cves.py --package lodash --ecosystem npm --version 4.17.15

# Fetch a single advisory by its OSV id
python scripts/ingest_cves.py --id GHSA-35jh-r3h4-6jhm

# List all packages already ingested
python scripts/ingest_cves.py --list
"""

import argparse
import sys
from pathlib import Path

# Allow running directly from project root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnalyzer.core.logging_config import setup_logging
from vulnalyzer.core.db import init_db
from vulnalyzer.ingest.osv import ingest_package, ingest_by_id, list_ingested_packages


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Ingest CVE/vulnerability data from the OSV API.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--package",   "-p", help="Package name")
    parser.add_argument("--ecosystem", "-e", help="Ecosystem (npm | PyPI | Maven | …)")
    parser.add_argument("--version",   "-v", help="Optional specific version")
    parser.add_argument("--id",              help="Fetch a single OSV advisory by id")
    parser.add_argument("--list",      "-l", action="store_true", help="List ingested packages")
    parser.add_argument("--log-level",       default="INFO", help="Logging level")
    args = parser.parse_args()

    setup_logging(args.log_level)
    init_db()

    if args.list:
        packages = list_ingested_packages()
        if not packages:
            print("No packages ingested yet.")
        else:
            print(f"{'Package':<30} {'Ecosystem'}")
            print("-" * 50)
            for p in packages:
                print(f"{p['package_name']:<30} {p['ecosystem']}")
        return

    if args.id:
        ok = ingest_by_id(args.id)
        sys.exit(0 if ok else 1)

    if not args.package or not args.ecosystem:
        parser.error("--package and --ecosystem are required (or use --id / --list)")

    count = ingest_package(args.package, args.ecosystem, args.version)
    sys.exit(0 if count >= 0 else 1)


if __name__ == "__main__":
    main()
