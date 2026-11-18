"""Exploration graph — JSON structure linking findings to attack chains.

Every finding node has edges to other findings it chains with.
Output: machine-readable JSON graph (not visual — but buildable from this data).

Usage:
    from hunter.engine.graph import build_graph, to_dot, to_json

    graph = build_graph(ledger, run_id)
    print(graph.to_json(indent=2))
    print(graph.to_dot())  # Graphviz DOT format
"""

import json
from typing import Any
from dataclasses import dataclass, field


@dataclass
class AttackGraph:
    """Directed graph: finding nodes + chain edges."""
    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, str]] = field(default_factory=list)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps({"nodes": self.nodes, "edges": self.edges}, indent=indent)

    def to_dot(self) -> str:
        """Graphviz DOT format for rendering."""
        lines = ["digraph G {", "  rankdir=LR;", '  node [shape=box,style=filled];']
        for n in self.nodes:
            color = {"critical": "red", "high": "orange", "medium": "yellow", "low": "green", "info": "blue"}.get(
                n.get("severity", "low"), "gray"
            )
            label = f"{n.get('id','?')}: {n.get('title','')[:30]}"
            lines.append(f'  "{n["id"]}" [label="{label}", fillcolor={color}];')
        for e in self.edges:
            lines.append(f'  "{e["from"]}" -> "{e["to"]}" [label="{e.get("label","")}"];')
        lines.append("}")
        return "\n".join(lines)


def build_graph(ledger: Any, run_id: str) -> AttackGraph:
    """Build exploration graph from ledger findings + chains."""
    graph = AttackGraph()

    # Add finding nodes
    try:
        findings = list(ledger.findings(run_id))
    except Exception:
        findings = []

    finding_ids = set()
    for f in findings:
        fid = getattr(f, "id", "")
        if not fid:
            continue
        finding_ids.add(fid)
        graph.nodes.append({
            "id": fid,
            "title": getattr(f, "title", "")[:100],
            "severity": str(getattr(f, "severity", "low")),
            "klass": getattr(f, "klass", ""),
            "status": str(getattr(f, "status", "candidate")),
        })

    # Add chain edges — from chain_spawner output
    try:
        from hunter.workflow.chain_spawner import find_chain_candidates
        chains = find_chain_candidates(findings)
    except Exception:
        chains = []

    for chain in chains:
        # Chain is typically (finding_a, finding_b, reason_dict)
        if len(chain) >= 2:
            fa, fb = chain[0], chain[1]
            fid_a = getattr(fa, "id", "") if hasattr(fa, "id") else str(fa)
            fid_b = getattr(fb, "id", "") if hasattr(fb, "id") else str(fb)
            reason = chain[2] if len(chain) >= 3 else {}
            label = str(reason.get("reason", ""))[:40] if isinstance(reason, dict) else str(reason)[:40]
            graph.edges.append({"from": fid_a, "to": fid_b, "label": label or "chain"})

    # Also scan for evidence-based connections (same contract = implicit edge)
    contracts = {}
    for n in graph.nodes:
        title = n.get("title", "")
        # Extract contract name from slither finding titles
        if "." in title:
            parts = title.split()
            for p in parts:
                if p.endswith(".sol") or (".sol" in p and "(" in p):
                    cname = p.split(".sol")[0].split("/")[-1]
                    contracts.setdefault(cname, []).append(n["id"])
                    break

    for cname, ids in contracts.items():
        if len(ids) >= 2:
            for i in range(len(ids)):
                for j in range(i + 1, len(ids)):
                    graph.edges.append({"from": ids[i], "to": ids[j], "label": f"same:{cname}"})

    return graph