"""
Trust graph — DAG tracking causal relationships between untrusted sources
and privileged actions.

Nodes: artifacts, agents, tools, prompts, memory entries
Edges: derived-from, influenced-by, executed-by, prompted-by

Use this to answer: "Which external URL caused this tool call?"
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterator


class NodeType(str, Enum):
    ARTIFACT = "artifact"
    AGENT    = "agent"
    TOOL     = "tool"
    PROMPT   = "prompt"
    MEMORY   = "memory"


class EdgeType(str, Enum):
    DERIVED_FROM  = "derived_from"
    INFLUENCED_BY = "influenced_by"
    EXECUTED_BY   = "executed_by"
    PROMPTED_BY   = "prompted_by"
    STORED_IN     = "stored_in"


@dataclass
class TrustNode:
    id: str
    node_type: NodeType
    label: str
    metadata: dict = field(default_factory=dict)


@dataclass
class TrustEdge:
    source_id: str
    target_id: str
    edge_type: EdgeType
    metadata: dict = field(default_factory=dict)


class TrustGraph:
    """
    Directed acyclic graph of trust relationships.

    Build it as your agent runs:
      graph.add_artifact(artifact)   — when content enters
      graph.add_tool_call(...)       — when a tool is invoked
      graph.link(artifact_id, tool_id, EdgeType.INFLUENCED_BY)
    """

    def __init__(self) -> None:
        self._nodes: dict[str, TrustNode] = {}
        self._edges: list[TrustEdge] = []

    # ------------------------------------------------------------------
    # Building
    # ------------------------------------------------------------------

    def add_node(self, node: TrustNode) -> None:
        self._nodes[node.id] = node

    def add_edge(self, edge: TrustEdge) -> None:
        self._edges.append(edge)

    def add_artifact(self, artifact_id: str, source: str, trust_level: str) -> TrustNode:
        node = TrustNode(
            id=artifact_id,
            node_type=NodeType.ARTIFACT,
            label=source,
            metadata={"trust_level": trust_level},
        )
        self.add_node(node)
        return node

    def add_tool_call(
        self,
        tool_id: str,
        tool_name: str,
        outcome: str,
        *,
        triggered_by: list[str] | None = None,
    ) -> TrustNode:
        node = TrustNode(
            id=tool_id,
            node_type=NodeType.TOOL,
            label=tool_name,
            metadata={"outcome": outcome},
        )
        self.add_node(node)
        for src_id in (triggered_by or []):
            self.add_edge(TrustEdge(
                source_id=src_id,
                target_id=tool_id,
                edge_type=EdgeType.INFLUENCED_BY,
            ))
        return node

    def link(self, source_id: str, target_id: str, edge_type: EdgeType) -> None:
        self.add_edge(TrustEdge(source_id=source_id, target_id=target_id, edge_type=edge_type))

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------

    def ancestors(self, node_id: str) -> set[str]:
        """Return all node IDs that have a path TO node_id."""
        result: set[str] = set()
        queue = [node_id]
        while queue:
            current = queue.pop()
            for edge in self._edges:
                if edge.target_id == current and edge.source_id not in result:
                    result.add(edge.source_id)
                    queue.append(edge.source_id)
        return result

    def descendants(self, node_id: str) -> set[str]:
        """Return all node IDs reachable FROM node_id."""
        result: set[str] = set()
        queue = [node_id]
        while queue:
            current = queue.pop()
            for edge in self._edges:
                if edge.source_id == current and edge.target_id not in result:
                    result.add(edge.target_id)
                    queue.append(edge.target_id)
        return result

    def untrusted_tool_calls(self) -> list[TrustNode]:
        """Return tool nodes whose ancestors include at least one UNTRUSTED artifact."""
        result = []
        for node in self._nodes.values():
            if node.node_type != NodeType.TOOL:
                continue
            for anc_id in self.ancestors(node.id):
                anc = self._nodes.get(anc_id)
                if anc and anc.metadata.get("trust_level") == "UNTRUSTED":
                    result.append(node)
                    break
        return result

    def nodes(self) -> Iterator[TrustNode]:
        return iter(self._nodes.values())

    def edges(self) -> Iterator[TrustEdge]:
        return iter(self._edges)

    def to_dict(self) -> dict:
        return {
            "nodes": [
                {"id": n.id, "type": n.node_type.value, "label": n.label, "metadata": n.metadata}
                for n in self._nodes.values()
            ],
            "edges": [
                {"source": e.source_id, "target": e.target_id, "type": e.edge_type.value}
                for e in self._edges
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


__all__ = ["NodeType", "EdgeType", "TrustNode", "TrustEdge", "TrustGraph"]
