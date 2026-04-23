"""Convert a PrimitivesGraph into a Mermaid flowchart for dashboard rendering."""

from __future__ import annotations

import re

from cvehunter.schemas import PrimitivesGraph


def _sanitize_id(node_id: str) -> str:
    """Make a node ID safe for Mermaid (alphanumeric + underscores only)."""
    return re.sub(r"[^a-zA-Z0-9_]", "_", node_id)


def primitives_to_mermaid(graph: PrimitivesGraph) -> str:
    """Render a PrimitivesGraph as a Mermaid flowchart string.

    Nodes are labeled with name and confidence. Edges show dependency flow.
    Nodes that appear in any complete chain are highlighted with bold borders.
    """
    if not graph.nodes:
        return ""

    chain_node_ids: set[str] = set()
    for chain in graph.complete_chains:
        chain_node_ids.update(chain)

    lines = ["flowchart TD"]

    for node_id, prim in graph.nodes.items():
        safe_id = _sanitize_id(node_id)
        conf_pct = int(prim.confidence * 100)
        label = f"{prim.name} ({conf_pct}%)"
        escaped_label = label.replace('"', "'")

        if node_id in chain_node_ids:
            lines.append(f'    {safe_id}["{escaped_label}"]:::chain')
        else:
            lines.append(f'    {safe_id}["{escaped_label}"]')

    for src, dst in graph.edges:
        safe_src = _sanitize_id(src)
        safe_dst = _sanitize_id(dst)
        lines.append(f"    {safe_src} --> {safe_dst}")

    lines.append("    classDef chain stroke-width:3px")

    return "\n".join(lines)
