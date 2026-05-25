from dataclasses import dataclass
from typing import Iterable, Optional

from awsentinel.authz.action_expander import ActionExpander, PolicySentryActionExpander
from awsentinel.authz.scp_evaluator import SCPEvaluator
from awsentinel.models.authz import (
    EffectivePermissionSet,
    GroupRecord,
    ManagedPolicyRecord,
    PermissionStatement,
    RoleRecord,
    SourcePolicy,
    UserRecord,
)


@dataclass(frozen=True)
class _PolicyBinding:
    statements: tuple[PermissionStatement, ...]
    source_policy: SourcePolicy


@dataclass(frozen=True)
class _ExpandedPolicy:
    allow_actions: frozenset[str]
    deny_actions: frozenset[str]


class PermissionComputationEngine:
    """Computes IAM effective permissions with cached wildcard expansion."""

    def __init__(
        self,
        managed_policies: Iterable[ManagedPolicyRecord],
        groups: Iterable[GroupRecord] = (),
        action_expander: Optional[ActionExpander] = None,
        scp_evaluator: Optional[SCPEvaluator] = None,
    ) -> None:
        self._managed_by_arn = {policy.arn: policy for policy in managed_policies}
        self._groups_by_arn = {group.arn: group for group in groups}
        self._action_expander = action_expander or PolicySentryActionExpander()
        self._scp_evaluator = scp_evaluator
        self._expanded_policy_cache: dict[str, _ExpandedPolicy] = {}

    def compute_effective_permissions(
        self, principal: UserRecord | RoleRecord
    ) -> EffectivePermissionSet:
        """Computes permissions in the required nine authorization steps.

        1. Resolve direct inline policy statements.
        2. Resolve direct managed policy statements.
        3. Resolve inherited group inline policy statements.
        4. Resolve inherited group managed policy statements.
        5. Expand all wildcard actions through Policy Sentry with caching.
        6. Split expanded statements into allow and explicit-deny sets.
        7. Apply permission boundary cap: allow_set intersect boundary_set.
        8. Apply SCP deny subtraction: allow_set minus scp_deny_set.
        9. Apply explicit-deny precedence: effective = (allow - deny) - scp_deny.
        """
        direct_inline = self._direct_inline_bindings(principal)
        direct_managed = self._direct_managed_bindings(principal)
        inherited_inline = self._inherited_inline_bindings(principal)
        inherited_managed = self._inherited_managed_bindings(principal)
        policy_bindings = (
            direct_inline + direct_managed + inherited_inline + inherited_managed
        )

        allow_set, explicit_deny_set = self._expand_and_split(policy_bindings)
        boundary_set = self._permission_boundary_allow_set(principal)
        if boundary_set is not None:
            allow_set = allow_set.intersection(boundary_set)

        scp_deny_set = self._scp_deny_set(principal)
        effective_allow_set = (allow_set - explicit_deny_set) - scp_deny_set
        denied_actions = explicit_deny_set.union(scp_deny_set)

        source_policies = [binding.source_policy for binding in policy_bindings]
        source_policies.extend(self._scp_source_policies(principal, scp_deny_set))
        inherited_from = {
            source.inherited_from for source in source_policies if source.inherited_from
        }

        return EffectivePermissionSet(
            principal_arn=principal.arn,
            allowed_actions=tuple(sorted(effective_allow_set)),
            denied_actions=tuple(sorted(denied_actions)),
            inherited_from=tuple(sorted(inherited_from)),
            source_policies=tuple(source_policies),
            raw_json={
                "principal_type": (
                    "role" if isinstance(principal, RoleRecord) else "user"
                ),
                "permission_boundary_policy_arn": (
                    principal.permission_boundary_policy_arn
                ),
            },
        )

    @property
    def expanded_policy_cache_size(self) -> int:
        return len(self._expanded_policy_cache)

    def _direct_inline_bindings(
        self, principal: UserRecord | RoleRecord
    ) -> list[_PolicyBinding]:
        return [
            _PolicyBinding(
                statements=policy.statements,
                source_policy=SourcePolicy(
                    policy_name=policy.name,
                    policy_type="inline",
                ),
            )
            for policy in principal.inline_policies
        ]

    def _direct_managed_bindings(
        self, principal: UserRecord | RoleRecord
    ) -> list[_PolicyBinding]:
        bindings: list[_PolicyBinding] = []
        for policy_arn in principal.attached_policy_arns:
            policy = self._managed_by_arn.get(policy_arn)
            if policy:
                bindings.append(self._managed_binding(policy))
        return bindings

    def _inherited_inline_bindings(
        self, principal: UserRecord | RoleRecord
    ) -> list[_PolicyBinding]:
        if not isinstance(principal, UserRecord):
            return []

        bindings: list[_PolicyBinding] = []
        for group in self._principal_groups(principal):
            for policy in group.inline_policies:
                bindings.append(
                    _PolicyBinding(
                        statements=policy.statements,
                        source_policy=SourcePolicy(
                            policy_name=policy.name,
                            policy_type="inline",
                            inherited_from=group.arn,
                        ),
                    )
                )
        return bindings

    def _inherited_managed_bindings(
        self, principal: UserRecord | RoleRecord
    ) -> list[_PolicyBinding]:
        if not isinstance(principal, UserRecord):
            return []

        bindings: list[_PolicyBinding] = []
        for group in self._principal_groups(principal):
            for policy_arn in group.attached_policy_arns:
                policy = self._managed_by_arn.get(policy_arn)
                if policy:
                    bindings.append(
                        self._managed_binding(policy, inherited_from=group.arn)
                    )
        return bindings

    def _principal_groups(self, principal: UserRecord) -> tuple[GroupRecord, ...]:
        return tuple(
            group
            for group_arn in principal.group_arns
            if (group := self._groups_by_arn.get(group_arn))
        )

    def _managed_binding(
        self, policy: ManagedPolicyRecord, inherited_from: Optional[str] = None
    ) -> _PolicyBinding:
        return _PolicyBinding(
            statements=policy.statements,
            source_policy=SourcePolicy(
                policy_name=policy.name,
                policy_type="managed",
                policy_arn=policy.arn,
                inherited_from=inherited_from,
            ),
        )

    def _expand_and_split(
        self, policy_bindings: Iterable[_PolicyBinding]
    ) -> tuple[set[str], set[str]]:
        allow_set: set[str] = set()
        deny_set: set[str] = set()

        for binding in policy_bindings:
            policy_key = self._policy_cache_key(binding.source_policy)
            if policy_key not in self._expanded_policy_cache:
                self._expanded_policy_cache[policy_key] = self._expand_statements(
                    binding.statements
                )
            expanded = self._expanded_policy_cache[policy_key]
            allow_set.update(expanded.allow_actions)
            deny_set.update(expanded.deny_actions)

        return allow_set, deny_set

    def _policy_cache_key(self, source_policy: SourcePolicy) -> str:
        return (
            source_policy.policy_arn
            or f"{source_policy.policy_type}:{source_policy.policy_name}:"
            f"{source_policy.inherited_from or 'direct'}"
        )

    def _expand_statements(
        self, statements: Iterable[PermissionStatement]
    ) -> _ExpandedPolicy:
        allow_actions: set[str] = set()
        deny_actions: set[str] = set()
        for statement in statements:
            expanded_actions = self._action_expander.expand_actions(statement.actions)
            if statement.effect == "Allow":
                allow_actions.update(expanded_actions)
            elif statement.effect == "Deny":
                deny_actions.update(expanded_actions)
        return _ExpandedPolicy(
            allow_actions=frozenset(allow_actions),
            deny_actions=frozenset(deny_actions),
        )

    def _permission_boundary_allow_set(
        self, principal: UserRecord | RoleRecord
    ) -> Optional[set[str]]:
        boundary_arn = principal.permission_boundary_policy_arn
        if not boundary_arn:
            return None
        boundary_policy = self._managed_by_arn.get(boundary_arn)
        if not boundary_policy:
            return set()

        cache_key = f"permission-boundary:{boundary_policy.arn}"
        if cache_key not in self._expanded_policy_cache:
            self._expanded_policy_cache[cache_key] = self._expand_statements(
                boundary_policy.statements
            )
        return set(self._expanded_policy_cache[cache_key].allow_actions)

    def _scp_deny_set(self, principal: UserRecord | RoleRecord) -> set[str]:
        if not self._scp_evaluator:
            return set()
        return set(
            self._scp_evaluator.expanded_denied_actions_for_account(
                principal.account_id,
                action_expander=self._action_expander,
            )
        )

    def _scp_source_policies(
        self, principal: UserRecord | RoleRecord, scp_deny_set: set[str]
    ) -> list[SourcePolicy]:
        if not self._scp_evaluator:
            return []
        policies: list[SourcePolicy] = []
        for action in scp_deny_set:
            policies.append(
                SourcePolicy(
                    policy_name=(
                        self._scp_evaluator.policy_name_for_action(
                            principal.account_id, action
                        )
                        or "SCP"
                    ),
                    policy_type="scp",
                )
            )
        return policies


def compute_effective_permissions(
    principal: UserRecord | RoleRecord,
    managed_policies: Iterable[ManagedPolicyRecord],
    groups: Iterable[GroupRecord] = (),
    scp_evaluator: Optional[SCPEvaluator] = None,
    action_expander: Optional[ActionExpander] = None,
) -> EffectivePermissionSet:
    """Computes effective permissions for one IAM user or role."""
    engine = PermissionComputationEngine(
        managed_policies=managed_policies,
        groups=groups,
        action_expander=action_expander,
        scp_evaluator=scp_evaluator,
    )
    return engine.compute_effective_permissions(principal)


def compute_all_effective_permissions(
    users: Iterable[UserRecord],
    roles: Iterable[RoleRecord],
    groups: Iterable[GroupRecord],
    managed_policies: Iterable[ManagedPolicyRecord],
    scp_evaluator: Optional[SCPEvaluator] = None,
    action_expander: Optional[ActionExpander] = None,
) -> tuple[EffectivePermissionSet, ...]:
    """Computes effective permissions for every supported principal."""
    engine = PermissionComputationEngine(
        managed_policies=managed_policies,
        groups=groups,
        action_expander=action_expander,
        scp_evaluator=scp_evaluator,
    )
    outputs = [engine.compute_effective_permissions(user) for user in users]
    outputs.extend(engine.compute_effective_permissions(role) for role in roles)
    return tuple(outputs)
