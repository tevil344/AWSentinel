from typing import Any, Iterable

from awsentinel.graph.edge_resolvers import build_edge
from awsentinel.graph.types import EdgeType, GraphEdge, Severity
from awsentinel.models.authz import EffectivePermissionSet, RoleRecord, UserRecord


def resolve_trust_edges(
    roles: Iterable[RoleRecord],
    principals: Iterable[UserRecord | RoleRecord],
    effective_permissions: Iterable[EffectivePermissionSet],
) -> tuple[GraphEdge, ...]:
    """Generates CAN_ASSUME edges when trust and sts:AssumeRole permission both exist."""
    permissions_by_arn = {
        permission.principal_arn: set(permission.allowed_actions)
        for permission in effective_permissions
    }
    principal_by_arn = {principal.arn: principal for principal in principals}
    edges: list[GraphEdge] = []

    for role in sorted(roles, key=lambda item: item.arn):
        trust_doc = role.trust_policy.raw_json if role.trust_policy else {}
        trusted_principals = _trusted_principals_from_doc(trust_doc)
        for principal_arn, principal in sorted(principal_by_arn.items()):
            if not _can_assume_role(principal_arn, permissions_by_arn):
                continue
            if _trust_matches(principal_arn, principal.account_id, trusted_principals):
                edges.append(
                    build_edge(
                        EdgeType.CAN_ASSUME,
                        source=principal_arn,
                        target=role.arn,
                        matched_actions=("sts:AssumeRole",),
                        path_name="AssumeRoleTrust",
                        severity=Severity.MEDIUM,
                        provenance={
                            "trust_policy": trust_doc,
                            "conditions": _trust_conditions(trust_doc),
                        },
                    )
                )
    return tuple(edges)


def _can_assume_role(
    principal_arn: str, permissions_by_arn: dict[str, set[str]]
) -> bool:
    actions = permissions_by_arn.get(principal_arn, set())
    return "sts:AssumeRole" in actions or "*" in actions


def _trusted_principals_from_doc(document: dict[str, Any]) -> tuple[str, ...]:
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    principals: set[str] = set()
    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal", {})
        if principal == "*":
            principals.add("*")
        elif isinstance(principal, dict):
            for value in principal.values():
                if isinstance(value, list):
                    principals.update(str(item) for item in value)
                else:
                    principals.add(str(value))
    return tuple(sorted(principals))


def _trust_matches(
    principal_arn: str, account_id: str, trusted_principals: tuple[str, ...]
) -> bool:
    account_root = f"arn:aws:iam::{account_id}:root"
    for trusted in trusted_principals:
        if trusted in {"*", principal_arn, account_root}:
            return True
        if trusted.endswith(":root") and trusted.split(":")[4] == account_id:
            return True
        if trusted.endswith(".amazonaws.com"):
            return True
    return False


def _trust_conditions(document: dict[str, Any]) -> list[dict[str, Any]]:
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    return [
        statement["Condition"] for statement in statements if "Condition" in statement
    ]
