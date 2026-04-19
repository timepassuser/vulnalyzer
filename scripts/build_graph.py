#!/usr/bin/env python3
"""
scripts/build_graph.py
======================
Rebuild the vulnerability propagation graph from all scan data in the DB,
then export it to data/graph.json.

Usage
-----
python scripts/build_graph.py
python scripts/build_graph.py --output /path/to/graph.json
python scripts/build_graph.py --ecosystem npm
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnalyzer.core.logging_config import setup_logging
from vulnalyzer.graph.builder import build_graph
from vulnalyzer.graph.export import export_graph


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the vulnerability propagation graph.")
    parser.add_argument("--output",    "-o", help="Output JSON path (default: data/graph.json)")
    parser.add_argument("--ecosystem", "-e", help="Filter export to one ecosystem")
    parser.add_argument("--log-level",       default="INFO")
    args = parser.parse_args()

    setup_logging(args.log_level)

    print("\nBuilding graph …")
    summary = build_graph()
    print(f"  Graph complete: {summary['nodes']} nodes, {summary['edges']} edges")

    out_path = Path(args.output) if args.output else None
    print("\nExporting to JSON …")
    payload = export_graph(output_path=out_path, ecosystem=args.ecosystem)
    print(f"  Exported: {payload['meta']['node_count']} nodes, {payload['meta']['edge_count']} edges")
    print(f"  Ecosystems in graph: {payload['meta']['ecosystems']}")


if __name__ == "__main__":
    main()
