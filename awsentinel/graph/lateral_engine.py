import networkx as nx

from awsentinel.graph.edge_resolvers import add_edge_dedup, build_edge
from awsentinel.graph.types import EdgeType, GraphEdge, Severity

MAX_LATERAL_DEPTH = 5
LATERAL_EDGE_TYPES = {
    EdgeType.CAN_ASSUME.value,
    EdgeType.PASSROLE_TO.value,
    EdgeType.PRIVESC_TO.value,
}


class LateralMovementEngine:
    """DFS-based lateral movement mapper with cycle protection."""

    def generate_edges(
        self, graph: nx.DiGraph, max_depth: int = MAX_LATERAL_DEPTH
    ) -> tuple[GraphEdge, ...]:
        generated: dict[str, GraphEdge] = {}
        for source in sorted(graph.nodes):
            self._dfs(graph, source, source, set(), 0, max_depth, generated)
        for edge in generated.values():
            add_edge_dedup(graph, edge)
        return tuple(generated[key] for key in sorted(generated))

    def _dfs(
        self,
        graph: nx.DiGraph,
        root: str,
        current: str,
        visited: set[str],
        depth: int,
        max_depth: int,
        generated: dict[str, GraphEdge],
    ) -> None:
        if depth >= max_depth:
            return
        visited.add(current)
        for _, target, data in sorted(graph.out_edges(current, data=True)):
            if target in visited:
                continue
            if data.get("edge_type") not in LATERAL_EDGE_TYPES:
                continue
            edge = build_edge(
                EdgeType.LATERAL_TO,
                root,
                target,
                path_name="LateralMovement",
                severity=Severity.HIGH,
                confidence=0.8,
                provenance={"via_edge": data.get("edge_id"), "depth": depth + 1},
            )
            generated[edge.edge_id] = edge
            self._dfs(
                graph,
                root,
                target,
                set(visited),
                depth + 1,
                max_depth,
                generated,
            )
