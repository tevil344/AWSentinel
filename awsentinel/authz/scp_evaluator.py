from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Iterable, Optional

from awsentinel.authz.action_expander import ActionExpander, PolicySentryActionExpander
from awsentinel.models.authz import PermissionStatement


@dataclass(frozen=True)
class ServiceControlPolicy:
    policy_id: str
    name: str
    target_accounts: tuple[str, ...]
    target_ous: tuple[str, ...]
    statements: tuple[PermissionStatement, ...]
    raw_json: dict = field(default_factory=dict)


@dataclass(frozen=True)
class AccountOrgPlacement:
    account_id: str
    ou_ids: tuple[str, ...] = field(default_factory=tuple)


class SCPEvaluator:
    """Models SCP explicit deny restrictions for accounts and OUs."""

    def __init__(
        self,
        policies: Iterable[ServiceControlPolicy],
        account_placements: Iterable[AccountOrgPlacement] = (),
    ) -> None:
        self._policies = tuple(policies)
        self._placements = {
            placement.account_id: placement for placement in account_placements
        }
        self._action_expander = PolicySentryActionExpander()

    def applicable_policies(self, account_id: str) -> tuple[ServiceControlPolicy, ...]:
        placement = self._placements.get(account_id)
        account_ous = set(placement.ou_ids if placement else ())

        return tuple(
            policy
            for policy in self._policies
            if account_id in policy.target_accounts
            or bool(account_ous.intersection(policy.target_ous))
        )

    def denied_actions_for_account(self, account_id: str) -> tuple[str, ...]:
        return self.expanded_denied_actions_for_account(account_id)

    def expanded_denied_actions_for_account(
        self, account_id: str, action_expander: Optional[ActionExpander] = None
    ) -> tuple[str, ...]:
        expander = action_expander or self._action_expander
        denied_actions: set[str] = set()
        for policy in self.applicable_policies(account_id):
            for statement in policy.statements:
                if statement.effect == "Deny":
                    denied_actions.update(expander.expand_actions(statement.actions))
        return tuple(sorted(denied_actions))

    def policy_name_for_action(self, account_id: str, action: str) -> Optional[str]:
        for policy in self.applicable_policies(account_id):
            for statement in policy.statements:
                if statement.effect == "Deny" and any(
                    _action_matches(pattern, action) for pattern in statement.actions
                ):
                    return policy.name
        return None


def _action_matches(pattern: str, action: str) -> bool:
    return fnmatchcase(action.lower(), pattern.lower())
