from typing import Any

from awsentinel.models.authz import PermissionStatement


def normalize_policy_document(
    policy_document: dict[str, Any],
) -> tuple[PermissionStatement, ...]:
    """Normalizes an IAM policy document into typed permission statements."""
    raw_statements = policy_document.get("Statement", [])
    if isinstance(raw_statements, dict):
        raw_statements = [raw_statements]

    return tuple(normalize_statement(statement) for statement in raw_statements)


def normalize_statement(statement: dict[str, Any]) -> PermissionStatement:
    """Normalizes singleton IAM fields into list-backed immutable contracts."""
    effect = statement.get("Effect", "Deny")
    if effect not in {"Allow", "Deny"}:
        effect = "Deny"

    return PermissionStatement(
        effect=effect,
        actions=tuple(_as_list(statement.get("Action"))),
        resources=tuple(_as_list(statement.get("Resource"))),
        conditions=dict(statement.get("Condition", {})),
        sid=statement.get("Sid"),
        not_actions=tuple(_as_list(statement.get("NotAction"))),
        not_resources=tuple(_as_list(statement.get("NotResource"))),
        principals=(
            dict(statement.get("Principal", {}))
            if isinstance(statement.get("Principal"), dict)
            else {}
        ),
        not_principals=(
            dict(statement.get("NotPrincipal", {}))
            if isinstance(statement.get("NotPrincipal"), dict)
            else {}
        ),
        raw_json=dict(statement),
    )


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]
