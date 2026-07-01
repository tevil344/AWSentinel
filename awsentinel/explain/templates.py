from dataclasses import dataclass


@dataclass(frozen=True)
class AttackTemplate:
    path_name: str
    title: str
    summary: str
    attack_steps: tuple[str, ...]
    remediation_summary: str
    remediation_actions: tuple[str, ...]
    breakage_risk: str


DEFAULT_TEMPLATE = AttackTemplate(
    path_name="Unknown",
    title="AWSentinel finding requires review",
    summary=(
        "AWSentinel found a reachable authorization path. Review the attack path, "
        "matched permissions, and graph evidence before changing IAM access."
    ),
    attack_steps=("Review the serialized attack chain for the exact transition.",),
    remediation_summary="Reduce the permissions that make the path reachable.",
    remediation_actions=("Review the principal policy scope.",),
    breakage_risk="Unknown until dependencies and runtime usage are reviewed.",
)


ATTACK_TEMPLATES: dict[str, AttackTemplate] = {
    "PassRole+RunInstances": AttackTemplate(
        path_name="PassRole+RunInstances",
        title="EC2 launch path can reach administrator privileges",
        summary=(
            "This attack works because the source principal can pass a privileged "
            "IAM role to EC2 and launch an instance that receives that role's "
            "temporary credentials."
        ),
        attack_steps=(
            "The attacker starts from the source principal in the finding.",
            "iam:PassRole lets the attacker delegate a more privileged role to EC2.",
            "ec2:RunInstances lets the attacker launch a new instance with that role.",
            "The instance receives role credentials from the metadata service.",
            "Those credentials can be used as the target administrator role.",
        ),
        remediation_summary=(
            "Restrict iam:PassRole and EC2 launch permissions to approved roles "
            "and approved provisioning paths."
        ),
        remediation_actions=(
            "Scope iam:PassRole to specific execution roles instead of broad role ARNs.",
            "Restrict ec2:RunInstances to approved launch templates or deployment roles.",
            "Add monitoring for RunInstances calls that include privileged instance profiles.",
        ),
        breakage_risk=(
            "Medium: EC2 deployment workflows can break if legitimate builders rely "
            "on broad PassRole access."
        ),
    ),
    "PassRole+CreateFunction": AttackTemplate(
        path_name="PassRole+CreateFunction",
        title="Lambda creation path can execute privileged code",
        summary=(
            "The principal can create and invoke Lambda functions while passing a "
            "role that may have stronger privileges."
        ),
        attack_steps=(
            "Pass a privileged execution role to Lambda.",
            "Create a Lambda function that runs attacker-controlled code.",
            "Invoke the function to execute with the delegated role.",
        ),
        remediation_summary="Restrict Lambda creation and iam:PassRole targets.",
        remediation_actions=(
            "Limit iam:PassRole to approved Lambda execution roles.",
            "Restrict lambda:CreateFunction for non-deployment identities.",
        ),
        breakage_risk="Medium: serverless deployment pipelines may need explicit allowlists.",
    ),
}


def template_for(path_name: str | None) -> AttackTemplate:
    if not path_name:
        return DEFAULT_TEMPLATE
    return ATTACK_TEMPLATES.get(path_name, DEFAULT_TEMPLATE)
