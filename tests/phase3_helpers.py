from awsentinel.graph.graph_builder import AuthorizationGraphBuilder
from awsentinel.models.authz import (
    EffectivePermissionSet,
    ManagedPolicyRecord,
    PermissionStatement,
    RoleRecord,
    TrustPolicyRecord,
    UserRecord,
)

ACCOUNT_ID = "123456789012"
DEV_ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/dev-deployer"
ADMIN_ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/AdminRole"
USER_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/Alice"


def statement(effect: str, actions: tuple[str, ...]) -> PermissionStatement:
    return PermissionStatement(effect=effect, actions=actions, resources=("*",))


def user_with_assume_role() -> UserRecord:
    return UserRecord(arn=USER_ARN, account_id=ACCOUNT_ID, name="Alice")


def dev_role() -> RoleRecord:
    return RoleRecord(arn=DEV_ROLE_ARN, account_id=ACCOUNT_ID, name="dev-deployer")


def admin_role() -> RoleRecord:
    return RoleRecord(
        arn=ADMIN_ROLE_ARN,
        account_id=ACCOUNT_ID,
        name="AdminRole",
        trust_policy=TrustPolicyRecord(
            role_arn=ADMIN_ROLE_ARN,
            statements=(statement("Allow", ("sts:AssumeRole",)),),
            raw_json={
                "Statement": {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"},
                    "Action": "sts:AssumeRole",
                }
            },
        ),
    )


def admin_policy() -> ManagedPolicyRecord:
    return ManagedPolicyRecord(
        arn=f"arn:aws:iam::{ACCOUNT_ID}:policy/Admin",
        account_id=ACCOUNT_ID,
        name="Admin",
        statements=(statement("Allow", ("*",)),),
    )


def dev_permissions(actions: tuple[str, ...]) -> EffectivePermissionSet:
    return EffectivePermissionSet(
        principal_arn=DEV_ROLE_ARN,
        allowed_actions=actions,
        denied_actions=(),
    )


def admin_permissions() -> EffectivePermissionSet:
    return EffectivePermissionSet(
        principal_arn=ADMIN_ROLE_ARN,
        allowed_actions=("*",),
        denied_actions=(),
    )


def user_permissions(actions: tuple[str, ...]) -> EffectivePermissionSet:
    return EffectivePermissionSet(
        principal_arn=USER_ARN,
        allowed_actions=actions,
        denied_actions=(),
    )


def base_graph(effective_permissions):
    return AuthorizationGraphBuilder().build(
        users=(user_with_assume_role(),),
        roles=(dev_role(), admin_role()),
        groups=(),
        managed_policies=(admin_policy(),),
        effective_permissions=tuple(effective_permissions),
        account_id=ACCOUNT_ID,
        instance_profiles=(
            {
                "Arn": f"arn:aws:iam::{ACCOUNT_ID}:instance-profile/AppProfile",
                "InstanceProfileName": "AppProfile",
                "Roles": [{"Arn": ADMIN_ROLE_ARN}],
            },
        ),
    )
