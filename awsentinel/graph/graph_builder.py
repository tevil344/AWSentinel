from typing import Iterable, Optional

import networkx as nx

from awsentinel.graph.edge_resolvers import add_edge_dedup, build_edge
from awsentinel.graph.trust_resolver import resolve_trust_edges
from awsentinel.graph.types import EdgeType, GraphNode, NodeType, deterministic_node_id
from awsentinel.models.authz import (
    EffectivePermissionSet,
    GroupRecord,
    ManagedPolicyRecord,
    RoleRecord,
    UserRecord,
)


class AuthorizationGraphBuilder:
    """Builds deterministic metadata-rich NetworkX authorization graphs."""

    def build(
        self,
        users: Iterable[UserRecord],
        roles: Iterable[RoleRecord],
        groups: Iterable[GroupRecord],
        managed_policies: Iterable[ManagedPolicyRecord],
        effective_permissions: Iterable[EffectivePermissionSet],
        account_id: str,
        organization_root_ids: Iterable[str] = (),
        organization_ou_ids: Iterable[str] = (),
        instance_profiles: Iterable[dict] = (),
    ) -> nx.DiGraph:
        graph = nx.DiGraph()
        user_tuple = tuple(users)
        role_tuple = tuple(roles)
        group_tuple = tuple(groups)
        policy_tuple = tuple(managed_policies)
        permission_tuple = tuple(effective_permissions)

        self._add_account_nodes(
            graph, account_id, organization_root_ids, organization_ou_ids
        )
        self._add_principal_nodes(graph, user_tuple, role_tuple, permission_tuple)
        self._add_group_nodes(graph, group_tuple)
        self._add_policy_nodes(graph, policy_tuple)
        self._add_instance_profile_nodes(graph, account_id, instance_profiles)
        self._add_membership_edges(graph, user_tuple)
        self._add_policy_edges(graph, user_tuple, role_tuple, group_tuple)
        self._add_instance_profile_edges(graph, instance_profiles)

        for edge in resolve_trust_edges(
            role_tuple, (*user_tuple, *role_tuple), permission_tuple
        ):
            add_edge_dedup(graph, edge)

        return graph

    def _add_account_nodes(
        self,
        graph: nx.DiGraph,
        account_id: str,
        root_ids: Iterable[str],
        ou_ids: Iterable[str],
    ) -> None:
        account_node = GraphNode(
            node_id=deterministic_node_id(NodeType.AWS_ACCOUNT, account_id),
            arn=f"arn:aws:iam::{account_id}:root",
            node_type=NodeType.AWS_ACCOUNT,
            aws_account_id=account_id,
        )
        graph.add_node(account_node.node_id, **account_node.to_dict())
        for root_id in sorted(root_ids):
            node = GraphNode(
                node_id=deterministic_node_id(NodeType.ORGANIZATION_ROOT, root_id),
                arn=None,
                node_type=NodeType.ORGANIZATION_ROOT,
                aws_account_id=account_id,
                raw_metadata={"root_id": root_id},
            )
            graph.add_node(node.node_id, **node.to_dict())
        for ou_id in sorted(ou_ids):
            node = GraphNode(
                node_id=deterministic_node_id(NodeType.ORGANIZATION_OU, ou_id),
                arn=None,
                node_type=NodeType.ORGANIZATION_OU,
                aws_account_id=account_id,
                raw_metadata={"ou_id": ou_id},
            )
            graph.add_node(node.node_id, **node.to_dict())

    def _add_principal_nodes(
        self,
        graph: nx.DiGraph,
        users: tuple[UserRecord, ...],
        roles: tuple[RoleRecord, ...],
        effective_permissions: tuple[EffectivePermissionSet, ...],
    ) -> None:
        admin_arns = {
            permission.principal_arn
            for permission in effective_permissions
            if "*" in permission.allowed_actions
            or "iam:AttachUserPolicy" in permission.allowed_actions
        }
        for user in sorted(users, key=lambda item: item.arn):
            self._add_node(
                graph,
                user.arn,
                NodeType.USER,
                user.account_id,
                user.raw_json,
                user.arn in admin_arns,
            )
        for role in sorted(roles, key=lambda item: item.arn):
            self._add_node(
                graph,
                role.arn,
                NodeType.ROLE,
                role.account_id,
                role.raw_json,
                role.arn in admin_arns,
            )

    def _add_group_nodes(
        self, graph: nx.DiGraph, groups: tuple[GroupRecord, ...]
    ) -> None:
        for group in sorted(groups, key=lambda item: item.arn):
            self._add_node(
                graph, group.arn, NodeType.GROUP, group.account_id, group.raw_json
            )

    def _add_policy_nodes(
        self, graph: nx.DiGraph, policies: tuple[ManagedPolicyRecord, ...]
    ) -> None:
        for policy in sorted(policies, key=lambda item: item.arn):
            self._add_node(
                graph,
                policy.arn,
                NodeType.MANAGED_POLICY,
                policy.account_id,
                policy.raw_json,
            )

    def _add_node(
        self,
        graph: nx.DiGraph,
        arn: str,
        node_type: NodeType,
        account_id: str,
        raw_metadata: dict,
        is_admin: bool = False,
    ) -> None:
        node = GraphNode(
            node_id=arn,
            arn=arn,
            node_type=node_type,
            aws_account_id=account_id,
            raw_metadata=raw_metadata,
            is_admin=is_admin,
        )
        graph.add_node(node.node_id, **node.to_dict())

    def _add_instance_profile_nodes(
        self, graph: nx.DiGraph, account_id: str, profiles: Iterable[dict]
    ) -> None:
        for profile in sorted(
            profiles,
            key=lambda item: item.get("Arn", item.get("InstanceProfileName", "")),
        ):
            arn = profile.get("Arn") or deterministic_node_id(
                NodeType.INSTANCE_PROFILE, profile["InstanceProfileName"]
            )
            self._add_node(graph, arn, NodeType.INSTANCE_PROFILE, account_id, profile)

    def _add_membership_edges(
        self, graph: nx.DiGraph, users: tuple[UserRecord, ...]
    ) -> None:
        for user in users:
            for group_arn in sorted(user.group_arns):
                add_edge_dedup(
                    graph,
                    build_edge(
                        EdgeType.MEMBER_OF,
                        user.arn,
                        group_arn,
                        provenance={"source": "group_arns"},
                    ),
                )

    def _add_policy_edges(
        self,
        graph: nx.DiGraph,
        users: tuple[UserRecord, ...],
        roles: tuple[RoleRecord, ...],
        groups: tuple[GroupRecord, ...],
    ) -> None:
        for principal in (*users, *roles, *groups):
            for policy_arn in sorted(principal.attached_policy_arns):
                add_edge_dedup(
                    graph,
                    build_edge(
                        EdgeType.ATTACHED_POLICY,
                        principal.arn,
                        policy_arn,
                        source_policies=(policy_arn,),
                    ),
                )

    def _add_instance_profile_edges(
        self, graph: nx.DiGraph, profiles: Iterable[dict]
    ) -> None:
        for profile in profiles:
            profile_arn = profile.get("Arn")
            if not profile_arn:
                continue
            for role in profile.get("Roles", []):
                role_arn: Optional[str] = role.get("Arn")
                if role_arn:
                    add_edge_dedup(
                        graph,
                        build_edge(
                            EdgeType.INSTANCE_PROFILE,
                            profile_arn,
                            role_arn,
                            provenance={"instance_profile": profile},
                        ),
                    )
