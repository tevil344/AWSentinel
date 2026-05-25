from typing import Iterable

import networkx as nx

from awsentinel.graph.edge_resolvers import add_edge_dedup, build_edge
from awsentinel.graph.privesc_paths import PrivEscPathDefinition, path_registry
from awsentinel.graph.types import EdgeType, GraphEdge, NodeType
from awsentinel.models.authz import EffectivePermissionSet


class PrivEscEngine:
    """Matches effective permissions against known privilege escalation paths."""

    def __init__(
        self, paths: Iterable[PrivEscPathDefinition] = path_registry()
    ) -> None:
        self._paths = tuple(paths)

    def generate_edges(
        self,
        graph: nx.DiGraph,
        effective_permissions: Iterable[EffectivePermissionSet],
    ) -> tuple[GraphEdge, ...]:
        admin_targets = sorted(
            node_id for node_id, data in graph.nodes(data=True) if data.get("is_admin")
        )
        if not admin_targets:
            admin_targets = sorted(
                node_id
                for node_id, data in graph.nodes(data=True)
                if data.get("node_type") == NodeType.AWS_ACCOUNT.value
            )

        edges: list[GraphEdge] = []
        for permission_set in sorted(
            effective_permissions, key=lambda item: item.principal_arn
        ):
            allowed = set(permission_set.allowed_actions)
            for path in self._paths:
                if not set(path.required_actions).issubset(allowed):
                    continue
                target = (
                    permission_set.principal_arn
                    if path.self_escalation
                    else (
                        admin_targets[0]
                        if admin_targets
                        else permission_set.principal_arn
                    )
                )
                edge = build_edge(
                    EdgeType.PRIVESC_TO,
                    source=permission_set.principal_arn,
                    target=target,
                    matched_actions=path.required_actions,
                    source_policies=tuple(
                        policy.policy_name for policy in permission_set.source_policies
                    ),
                    path_name=path.path_name,
                    severity=path.severity,
                    confidence=0.95,
                    provenance={
                        "category": path.category,
                        "attack_description": path.attack_description,
                        "mitigation_guidance": path.mitigation_guidance,
                        "references": path.references,
                        "mitre_attack_mapping": path.mitre_attack_mapping,
                        "kev_relevant": path.kev_relevant,
                    },
                )
                add_edge_dedup(graph, edge)
                edges.append(edge)
        return tuple(edges)
