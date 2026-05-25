from typing import Any

import networkx as nx

from awsentinel.graph.types import EdgeType, GraphEdge, Severity, deterministic_edge_id


def add_edge_dedup(graph: nx.DiGraph, edge: GraphEdge) -> None:
    if graph.has_edge(edge.source, edge.target):
        existing = graph.edges[edge.source, edge.target]
        if existing.get("edge_id") == edge.edge_id:
            return
    graph.add_edge(edge.source, edge.target, **edge.to_dict())


def build_edge(
    edge_type: EdgeType,
    source: str,
    target: str,
    matched_actions: tuple[str, ...] = (),
    source_policies: tuple[str, ...] = (),
    path_name: str | None = None,
    severity: Severity = Severity.LOW,
    confidence: float = 1.0,
    provenance: dict[str, Any] | None = None,
) -> GraphEdge:
    return GraphEdge(
        edge_id=deterministic_edge_id(edge_type, source, target, path_name or ""),
        edge_type=edge_type,
        source=source,
        target=target,
        matched_actions=tuple(sorted(matched_actions)),
        source_policies=tuple(sorted(source_policies)),
        path_name=path_name,
        severity=severity,
        confidence=confidence,
        provenance=provenance or {},
    )
