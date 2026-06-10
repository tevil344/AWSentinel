from collections import Counter
from typing import Any, Iterable

from awsentinel.intelligence.models import LeastPrivilegeFinding
from awsentinel.models.authz import EffectivePermissionSet


class LeastPrivilegeEngine:
    """Compares granted permissions with observed usage."""

    def analyze(
        self,
        effective_permissions: Iterable[EffectivePermissionSet],
        cloudtrail_events: Iterable[dict[str, Any]],
        service_last_accessed: dict[str, Iterable[dict[str, Any]]] | None = None,
    ) -> tuple[LeastPrivilegeFinding, ...]:
        service_last_accessed = service_last_accessed or {}
        usage_by_principal = _cloudtrail_usage_by_principal(cloudtrail_events)
        results: list[LeastPrivilegeFinding] = []

        for permission_set in sorted(
            effective_permissions, key=lambda item: item.principal_arn
        ):
            granted = set(permission_set.allowed_actions)
            used = usage_by_principal.get(permission_set.principal_arn, set())
            used.update(
                _actions_from_service_last_accessed(
                    service_last_accessed.get(permission_set.principal_arn, ())
                )
            )
            unused = {action for action in granted if not _action_used(action, used)}
            rarely_used = tuple(
                sorted(action for action, count in Counter(used).items() if count == 1)
            )
            score = int((len(unused) / max(len(granted), 1)) * 100)
            results.append(
                LeastPrivilegeFinding(
                    principal_arn=permission_set.principal_arn,
                    granted_actions=tuple(sorted(granted)),
                    used_actions=tuple(sorted(used)),
                    unused_actions=tuple(sorted(unused)),
                    rarely_used_actions=rarely_used,
                    overprivileged_score=score,
                    recommendation=(
                        "Remove unused permissions or replace wildcards "
                        "with observed actions."
                        if unused
                        else "No least-privilege reduction identified."
                    ),
                )
            )
        return tuple(results)


def _cloudtrail_usage_by_principal(
    cloudtrail_events: Iterable[dict[str, Any]],
) -> dict[str, Counter[str]]:
    usage: dict[str, Counter[str]] = {}
    for event in cloudtrail_events:
        principal = event.get("Username") or event.get("userIdentity", {}).get("arn")
        action = _action_from_event(event)
        if principal and action:
            usage.setdefault(str(principal), Counter()).update((action,))
    return usage


def _action_from_event(event: dict[str, Any]) -> str:
    event_name = event.get("EventName") or event.get("eventName")
    source = event.get("EventSource") or event.get("eventSource")
    if not event_name or not source:
        return ""
    service = str(source).split(".")[0]
    return f"{service}:{event_name}"


def _actions_from_service_last_accessed(events: Iterable[dict[str, Any]]) -> set[str]:
    actions: set[str] = set()
    for event in events:
        service_namespace = event.get("ServiceNamespace")
        if service_namespace:
            actions.add(f"{service_namespace}:*")
    return actions


def _action_used(granted_action: str, used_actions: set[str]) -> bool:
    service = granted_action.split(":", 1)[0]
    if granted_action in used_actions or f"{service}:*" in used_actions:
        return True
    if granted_action.endswith(":*"):
        return any(action.startswith(f"{service}:") for action in used_actions)
    return False
