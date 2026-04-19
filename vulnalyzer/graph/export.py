"""
vulnalyzer.graph.export
========================
Exports the graph from SQLite to a JSON format suitable for
Obsidian-style force-directed graph frontends.

Output schema
-------------
{
  "nodes": [
    {
      "id":        "repo:github/owner/name",
      "label":     "Repository",
      "ecosystem": "npm" | "PyPI" | null,
      "data":      { ... display attributes }
    },
    ...
  ],
  "edges": [
    {
      "id":  42,
      "src": "repo:...",
      "dst": "vuln:...",
      "rel": "EXPOSED_TO",
      "data": { "severity": "HIGH", ... }
    },
    ...
  ],
  "meta": {
    "node_count": 123,
    "edge_count": 456,
    "ecosystems": ["npm", "PyPI"]
  }
}

The ``commit_sha`` field is present inside ``node.data`` for Repository
nodes so the frontend can access it when needed, but it does not appear
as a top-level visible field — keeping the graph display clean.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from vulnalyzer.core.db import get_conn, get_all_graph_nodes, get_all_graph_edges, init_db

logger = logging.getLogger(__name__)

DEFAULT_EXPORT_PATH = Path(__file__).resolve().parents[2] / "data" / "graph.json"


def export_graph(
    output_path: Path | None = None,
    ecosystem: str | None = None,
) -> dict:
    """
    Export the graph to a JSON file and also return it as a dict.

    Parameters
    ----------
    output_path:
        Where to write the JSON file.  Defaults to ``data/graph.json``.
    ecosystem:
        If provided, only nodes belonging to this ecosystem (and edges
        between them) are exported.  Pass None for the full graph.
    """
    init_db()
    path = output_path or DEFAULT_EXPORT_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    with get_conn() as conn:
        nodes = get_all_graph_nodes(conn, ecosystem=ecosystem)
        edges = get_all_graph_edges(conn)

    # If filtering by ecosystem, restrict edges to those between included nodes
    if ecosystem:
        node_ids = {n["id"] for n in nodes}
        edges = [e for e in edges if e["src"] in node_ids and e["dst"] in node_ids]

    ecosystems = sorted({n["ecosystem"] for n in nodes if n.get("ecosystem")})

    payload = {
        "nodes": nodes,
        "edges": edges,
        "meta": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "ecosystems": ecosystems,
        },
    }

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)

    logger.info(
        "Exported graph → %s  (%d nodes, %d edges)",
        path, len(nodes), len(edges),
    )
    return payload


def get_graph_json(ecosystem: str | None = None) -> dict:
    """
    Return the graph as a dict without writing to disk.
    Useful for API endpoints.
    """
    init_db()
    with get_conn() as conn:
        nodes = get_all_graph_nodes(conn, ecosystem=ecosystem)
        edges = get_all_graph_edges(conn)

    if ecosystem:
        node_ids = {n["id"] for n in nodes}
        edges = [e for e in edges if e["src"] in node_ids and e["dst"] in node_ids]

    ecosystems = sorted({n["ecosystem"] for n in nodes if n.get("ecosystem")})
    return {
        "nodes": nodes,
        "edges": edges,
        "meta": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "ecosystems": ecosystems,
        },
    }
