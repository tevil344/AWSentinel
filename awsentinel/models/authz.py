from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal, Optional

Effect = Literal["Allow", "Deny"]
PrincipalType = Literal["user", "role", "group"]
PolicyType = Literal["managed", "inline", "scp", "trust"]


@dataclass(frozen=True)
class PermissionStatement:
    effect: Effect
    actions: tuple[str, ...] = field(default_factory=tuple)
    resources: tuple[str, ...] = field(default_factory=tuple)
    conditions: dict[str, Any] = field(default_factory=dict)
    sid: Optional[str] = None
    not_actions: tuple[str, ...] = field(default_factory=tuple)
    not_resources: tuple[str, ...] = field(default_factory=tuple)
    principals: dict[str, Any] = field(default_factory=dict)
    not_principals: dict[str, Any] = field(default_factory=dict)
    raw_json: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ManagedPolicyRecord:
    arn: str
    account_id: str
    name: str
    statements: tuple[PermissionStatement, ...]
    raw_json: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class InlinePolicyRecord:
    name: str
    owner_arn: str
    owner_type: PrincipalType
    statements: tuple[PermissionStatement, ...]
    raw_json: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TrustPolicyRecord:
    role_arn: str
    statements: tuple[PermissionStatement, ...]
    raw_json: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GroupRecord:
    arn: str
    account_id: str
    name: str
    inline_policies: tuple[InlinePolicyRecord, ...] = field(default_factory=tuple)
    attached_policy_arns: tuple[str, ...] = field(default_factory=tuple)
    raw_json: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class UserRecord:
    arn: str
    account_id: str
    name: str
    group_arns: tuple[str, ...] = field(default_factory=tuple)
    inline_policies: tuple[InlinePolicyRecord, ...] = field(default_factory=tuple)
    attached_policy_arns: tuple[str, ...] = field(default_factory=tuple)
    permission_boundary_policy_arn: Optional[str] = None
    raw_json: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RoleRecord:
    arn: str
    account_id: str
    name: str
    trust_policy: Optional[TrustPolicyRecord] = None
    inline_policies: tuple[InlinePolicyRecord, ...] = field(default_factory=tuple)
    attached_policy_arns: tuple[str, ...] = field(default_factory=tuple)
    permission_boundary_policy_arn: Optional[str] = None
    raw_json: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SourcePolicy:
    policy_name: str
    policy_type: PolicyType
    policy_arn: Optional[str] = None
    inherited_from: Optional[str] = None


@dataclass(frozen=True)
class EffectivePermissionSet:
    principal_arn: str
    allowed_actions: tuple[str, ...]
    denied_actions: tuple[str, ...]
    inherited_from: tuple[str, ...] = field(default_factory=tuple)
    source_policies: tuple[SourcePolicy, ...] = field(default_factory=tuple)
    computed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    raw_json: dict[str, Any] = field(default_factory=dict)
