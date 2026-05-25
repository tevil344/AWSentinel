import networkx as nx

from awsentinel.graph.types import AttackPath, EdgeType

MAX_ATTACK_DEPTH = 5


class AttackPathEngine:
    """BFS shortest-path and bounded all-path attack-chain traversal."""

    def shortest_paths_to_admin(
        self, graph: nx.DiGraph, max_depth: int = MAX_ATTACK_DEPTH
    ) -> tuple[AttackPath, ...]:
        paths: list[AttackPath] = []
        for source in self._non_admin_nodes(graph):
            for target in self._admin_nodes(graph):
                if source == target or not nx.has_path(graph, source, target):
                    continue
                node_path = tuple(nx.shortest_path(graph, source, target))
                if len(node_path) - 1 <= max_depth:
                    paths.append(self._to_attack_path(graph, source, target, node_path))
        return tuple(
            sorted(paths, key=lambda item: (item.source, item.target, item.nodes))
        )

    def all_paths_to_admin(
        self, graph: nx.DiGraph, max_depth: int = MAX_ATTACK_DEPTH
    ) -> tuple[AttackPath, ...]:
        paths: list[AttackPath] = []
        for source in self._non_admin_nodes(graph):
            for target in self._admin_nodes(graph):
                if source == target:
                    continue
                for node_path in nx.all_simple_paths(
                    graph, source, target, cutoff=max_depth
                ):
                    paths.append(
                        self._to_attack_path(graph, source, target, tuple(node_path))
                    )
        return tuple(
            sorted(paths, key=lambda item: (item.source, item.target, item.nodes))
        )

    def _admin_nodes(self, graph: nx.DiGraph) -> tuple[str, ...]:
        return tuple(
            sorted(
                node
                for node, data in graph.nodes(data=True)
                if data.get("is_admin")
                and data.get("node_type") in {"USER", "ROLE", "AWS_ACCOUNT"}
            )
        )

    def _non_admin_nodes(self, graph: nx.DiGraph) -> tuple[str, ...]:
        return tuple(
            sorted(
                node
                for node, data in graph.nodes(data=True)
                if not data.get("is_admin")
                and data.get("node_type") in {"USER", "ROLE", "GROUP"}
            )
        )

    def _to_attack_path(
        self, graph: nx.DiGraph, source: str, target: str, nodes: tuple[str, ...]
    ) -> AttackPath:
        edge_ids: list[str] = []
        escalation = 0
        lateral = 0
        privilege = 0
        for left, right in zip(nodes, nodes[1:]):
            data = graph.edges[left, right]
            edge_ids.append(data.get("edge_id", f"{left}->{right}"))
            edge_type = data.get("edge_type")
            if edge_type == EdgeType.PRIVESC_TO.value:
                escalation += 1
                privilege += 1
            if edge_type == EdgeType.LATERAL_TO.value:
                lateral += 1
            if edge_type in {EdgeType.CAN_ASSUME.value, EdgeType.PASSROLE_TO.value}:
                privilege += 1
        return AttackPath(
            source=source,
            target=target,
            nodes=nodes,
            edges=tuple(edge_ids),
            path_length=max(0, len(nodes) - 1),
            escalation_stages=escalation,
            lateral_movement_stages=lateral,
            privilege_transitions=privilege,
        )
