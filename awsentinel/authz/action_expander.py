from functools import lru_cache
from typing import Protocol


class ActionExpander(Protocol):
    """Expands IAM action wildcards into concrete IAM actions."""

    def expand_actions(self, actions: tuple[str, ...]) -> tuple[str, ...]:
        """Expands all action patterns in a statement."""


class PolicySentryActionExpander:
    """Policy Sentry-backed wildcard expander with per-action caching."""

    def expand_actions(self, actions: tuple[str, ...]) -> tuple[str, ...]:
        expanded: set[str] = set()
        for action in actions:
            expanded.update(_expand_single_action(action))
        return tuple(sorted(expanded))


@lru_cache(maxsize=4096)
def _expand_single_action(action: str) -> tuple[str, ...]:
    if "*" not in action and "?" not in action:
        return (action,)

    try:
        from policy_sentry.analysis.expand import expand
    except ImportError:
        return (action,)

    return tuple(sorted(str(expanded_action) for expanded_action in expand(action)))
