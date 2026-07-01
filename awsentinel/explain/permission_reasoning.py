from awsentinel.explain.models import PermissionExplanation

PERMISSION_SUMMARIES: dict[str, tuple[str, str]] = {
    "iam:PassRole": (
        "PassRole allows a principal to delegate an IAM role to an AWS service.",
        "Dangerous when the passed role has more privilege than the caller.",
    ),
    "ec2:RunInstances": (
        "RunInstances allows launching EC2 instances.",
        "Dangerous with PassRole because the new instance can receive privileged credentials.",
    ),
    "lambda:CreateFunction": (
        "CreateFunction allows creating Lambda code execution entry points.",
        "Dangerous when paired with PassRole to a privileged execution role.",
    ),
    "lambda:InvokeFunction": (
        "InvokeFunction allows triggering Lambda code execution.",
        "Dangerous when the function runs with delegated privileged credentials.",
    ),
    "iam:CreatePolicyVersion": (
        "CreatePolicyVersion allows adding a new version to a managed policy.",
        "Dangerous when combined with setting that version as the default.",
    ),
    "iam:SetDefaultPolicyVersion": (
        "SetDefaultPolicyVersion activates an existing managed policy version.",
        "Dangerous because a malicious policy version can become effective immediately.",
    ),
}


def explain_permissions(actions: tuple[str, ...]) -> tuple[PermissionExplanation, ...]:
    explanations: list[PermissionExplanation] = []
    for action in sorted(actions):
        summary, risk = PERMISSION_SUMMARIES.get(
            action,
            (
                f"{action} grants access to an AWS API action.",
                "Review whether this action is required for the principal's job function.",
            ),
        )
        service = action.split(":", 1)[0] if ":" in action else "unknown"
        explanations.append(
            PermissionExplanation(
                action=action,
                service=service,
                summary=summary,
                risk=risk,
            )
        )
    return tuple(explanations)
