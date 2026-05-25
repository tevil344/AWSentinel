from dataclasses import dataclass

from awsentinel.graph.types import Severity


@dataclass(frozen=True)
class PrivEscPathDefinition:
    path_name: str
    required_actions: tuple[str, ...]
    severity: Severity
    category: str
    attack_description: str
    mitigation_guidance: str
    references: tuple[str, ...]
    mitre_attack_mapping: tuple[str, ...]
    kev_relevant: bool = False
    self_escalation: bool = False


PRIVESC_PATHS: tuple[PrivEscPathDefinition, ...] = (
    PrivEscPathDefinition(
        path_name="PassRole+RunInstances",
        required_actions=("iam:PassRole", "ec2:RunInstances"),
        severity=Severity.CRITICAL,
        category="Compute privilege escalation",
        attack_description="Launch EC2 with a privileged role and retrieve credentials.",
        mitigation_guidance="Restrict iam:PassRole and ec2:RunInstances to approved roles.",
        references=(
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html",
        ),
        mitre_attack_mapping=("T1098", "T1578"),
        kev_relevant=True,
    ),
    PrivEscPathDefinition(
        path_name="PassRole+CreateFunction",
        required_actions=(
            "iam:PassRole",
            "lambda:CreateFunction",
            "lambda:InvokeFunction",
        ),
        severity=Severity.CRITICAL,
        category="Serverless privilege escalation",
        attack_description="Create and invoke Lambda with a privileged execution role.",
        mitigation_guidance="Restrict Lambda creation and iam:PassRole targets.",
        references=(
            "https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html",
        ),
        mitre_attack_mapping=("T1098", "T1578"),
        kev_relevant=True,
    ),
    PrivEscPathDefinition(
        path_name="CreatePolicyVersion",
        required_actions=("iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"),
        severity=Severity.CRITICAL,
        category="IAM policy privilege escalation",
        attack_description="Create an administrator policy version and set it as default.",
        mitigation_guidance="Deny policy version mutation except to controlled break-glass roles.",
        references=(
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-versioning.html",
        ),
        mitre_attack_mapping=("T1098",),
        kev_relevant=True,
    ),
    PrivEscPathDefinition(
        path_name="AttachUserPolicySelf",
        required_actions=("iam:AttachUserPolicy",),
        severity=Severity.CRITICAL,
        category="Self privilege escalation",
        attack_description="Attach a privileged managed policy to the current user.",
        mitigation_guidance="Deny self-service IAM attachment APIs.",
        references=(
            "https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachUserPolicy.html",
        ),
        mitre_attack_mapping=("T1098",),
        kev_relevant=True,
        self_escalation=True,
    ),
    PrivEscPathDefinition(
        path_name="PutUserPolicySelf",
        required_actions=("iam:PutUserPolicy",),
        severity=Severity.CRITICAL,
        category="Self privilege escalation",
        attack_description="Put an inline administrator policy on the current user.",
        mitigation_guidance="Deny inline policy mutation on principals.",
        references=(
            "https://docs.aws.amazon.com/IAM/latest/APIReference/API_PutUserPolicy.html",
        ),
        mitre_attack_mapping=("T1098",),
        kev_relevant=True,
        self_escalation=True,
    ),
    PrivEscPathDefinition(
        path_name="AddUserToGroup",
        required_actions=("iam:AddUserToGroup",),
        severity=Severity.CRITICAL,
        category="Self privilege escalation",
        attack_description="Add the current user to a privileged group.",
        mitigation_guidance="Restrict group membership mutation.",
        references=(
            "https://docs.aws.amazon.com/IAM/latest/APIReference/API_AddUserToGroup.html",
        ),
        mitre_attack_mapping=("T1098",),
        kev_relevant=True,
        self_escalation=True,
    ),
    PrivEscPathDefinition(
        path_name="PassRole+CreateStack",
        required_actions=("iam:PassRole", "cloudformation:CreateStack"),
        severity=Severity.CRITICAL,
        category="CloudFormation privilege escalation",
        attack_description="Create a stack that uses a privileged service role.",
        mitigation_guidance="Restrict CloudFormation service roles and iam:PassRole.",
        references=(
            "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-servicerole.html",
        ),
        mitre_attack_mapping=("T1098", "T1578"),
        kev_relevant=True,
    ),
    PrivEscPathDefinition(
        path_name="UpdateLoginProfile",
        required_actions=("iam:UpdateLoginProfile",),
        severity=Severity.HIGH,
        category="Credential takeover",
        attack_description="Reset a console password for another IAM user.",
        mitigation_guidance="Restrict login profile mutation.",
        references=(
            "https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateLoginProfile.html",
        ),
        mitre_attack_mapping=("T1098",),
    ),
    PrivEscPathDefinition(
        path_name="PassRole+CreateJob",
        required_actions=("iam:PassRole", "glue:CreateJob", "glue:StartJobRun"),
        severity=Severity.HIGH,
        category="Glue privilege escalation",
        attack_description="Create and run a Glue job with a privileged role.",
        mitigation_guidance="Restrict Glue job creation and iam:PassRole targets.",
        references=(
            "https://docs.aws.amazon.com/glue/latest/dg/create-an-iam-role.html",
        ),
        mitre_attack_mapping=("T1098", "T1578"),
    ),
)


def path_registry() -> tuple[PrivEscPathDefinition, ...]:
    return PRIVESC_PATHS
