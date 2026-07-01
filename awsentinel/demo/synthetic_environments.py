from dataclasses import dataclass

from awsentinel.models.authz import (
    EffectivePermissionSet,
    GroupRecord,
    ManagedPolicyRecord,
    PermissionStatement,
    RoleRecord,
    TrustPolicyRecord,
    UserRecord,
)


@dataclass(frozen=True)
class SyntheticEnvironment:
    name: str
    account_id: str
    users: tuple[UserRecord, ...]
    roles: tuple[RoleRecord, ...]
    groups: tuple[GroupRecord, ...]
    policies: tuple[ManagedPolicyRecord, ...]
    effective_permissions: tuple[EffectivePermissionSet, ...]
    instance_profiles: tuple[dict, ...] = ()
    cloudtrail_events: tuple[dict, ...] = ()


def small_startup() -> SyntheticEnvironment:
    return _environment(
        "small-startup", user_count=5, role_count=4, group_count=2, policy_count=10
    )


def enterprise() -> SyntheticEnvironment:
    return _environment(
        "enterprise", user_count=300, role_count=150, group_count=50, policy_count=700
    )


def multi_account_organization() -> tuple[SyntheticEnvironment, ...]:
    return tuple(
        _environment(
            f"org-account-{index}",
            account_id=f"12345678901{index}",
            user_count=5,
            role_count=5,
            group_count=2,
            policy_count=12,
        )
        for index in range(3)
    )


def misconfigured_sandbox() -> SyntheticEnvironment:
    return _environment(
        "misconfigured-sandbox",
        user_count=8,
        role_count=8,
        group_count=3,
        policy_count=20,
        include_lambda=True,
        include_cloudformation=True,
        include_glue=True,
        include_self_escalation=True,
    )


def _environment(
    name: str,
    user_count: int,
    role_count: int,
    group_count: int,
    policy_count: int,
    account_id: str = "123456789012",
    include_lambda: bool = False,
    include_cloudformation: bool = False,
    include_glue: bool = False,
    include_self_escalation: bool = False,
) -> SyntheticEnvironment:
    admin_role_arn = f"arn:aws:iam::{account_id}:role/AdminRole"
    deployer_role_arn = f"arn:aws:iam::{account_id}:role/dev-deployer"
    users = tuple(
        UserRecord(
            arn=f"arn:aws:iam::{account_id}:user/user-{index:04d}",
            account_id=account_id,
            name=f"user-{index:04d}",
            group_arns=(
                f"arn:aws:iam::{account_id}:group/group-{index % max(group_count, 1):03d}",
            ),
        )
        for index in range(user_count)
    )
    roles = [
        RoleRecord(arn=deployer_role_arn, account_id=account_id, name="dev-deployer")
    ]
    roles.append(
        RoleRecord(
            arn=admin_role_arn,
            account_id=account_id,
            name="AdminRole",
            trust_policy=TrustPolicyRecord(
                role_arn=admin_role_arn,
                statements=(_statement("Allow", ("sts:AssumeRole",)),),
                raw_json={
                    "Statement": {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                        "Action": "sts:AssumeRole",
                    }
                },
            ),
        )
    )
    roles.extend(
        RoleRecord(
            arn=f"arn:aws:iam::{account_id}:role/role-{index:04d}",
            account_id=account_id,
            name=f"role-{index:04d}",
        )
        for index in range(max(0, role_count - 2))
    )
    groups = tuple(
        GroupRecord(
            arn=f"arn:aws:iam::{account_id}:group/group-{index:03d}",
            account_id=account_id,
            name=f"group-{index:03d}",
        )
        for index in range(group_count)
    )
    policies = tuple(
        ManagedPolicyRecord(
            arn=f"arn:aws:iam::{account_id}:policy/policy-{index:04d}",
            account_id=account_id,
            name=f"policy-{index:04d}",
            statements=(_statement("Allow", ("s3:ListBucket",)),),
        )
        for index in range(policy_count)
    )
    deployer_actions = {"iam:PassRole", "ec2:RunInstances"}
    if include_lambda:
        deployer_actions.update({"lambda:CreateFunction", "lambda:InvokeFunction"})
    if include_cloudformation:
        deployer_actions.add("cloudformation:CreateStack")
    if include_glue:
        deployer_actions.update({"glue:CreateJob", "glue:StartJobRun"})
    if include_self_escalation:
        deployer_actions.update(
            {"iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:AddUserToGroup"}
        )
    permissions = [
        EffectivePermissionSet(
            principal_arn=deployer_role_arn,
            allowed_actions=tuple(sorted(deployer_actions)),
            denied_actions=(),
        ),
        EffectivePermissionSet(
            principal_arn=admin_role_arn,
            allowed_actions=("*",),
            denied_actions=(),
        ),
    ]
    permissions.extend(
        EffectivePermissionSet(
            principal_arn=role.arn,
            allowed_actions=("s3:ListBucket",),
            denied_actions=(),
        )
        for role in roles[2:]
    )
    instance_profiles = (
        {
            "Arn": f"arn:aws:iam::{account_id}:instance-profile/AdminProfile",
            "InstanceProfileName": "AdminProfile",
            "Roles": [{"Arn": admin_role_arn}],
        },
    )
    return SyntheticEnvironment(
        name=name,
        account_id=account_id,
        users=users,
        roles=tuple(roles),
        groups=groups,
        policies=policies,
        effective_permissions=tuple(permissions),
        instance_profiles=instance_profiles,
    )


def _statement(effect: str, actions: tuple[str, ...]) -> PermissionStatement:
    return PermissionStatement(effect=effect, actions=actions, resources=("*",))
