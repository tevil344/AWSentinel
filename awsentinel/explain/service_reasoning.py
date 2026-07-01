from awsentinel.explain.models import ServiceExplanation

SERVICE_SUMMARIES: dict[str, tuple[str, str]] = {
    "iam": (
        "IAM controls identities, roles, policies, and delegation.",
        "IAM actions are central to privilege escalation because they can change who has access.",
    ),
    "ec2": (
        "EC2 runs virtual machines that can receive credentials through instance profiles.",
        "EC2 is relevant when an attacker can launch compute with a privileged role.",
    ),
    "lambda": (
        "Lambda runs code with an execution role.",
        "Lambda is relevant when an attacker can create or invoke code under a privileged role.",
    ),
    "glue": (
        "Glue runs managed ETL jobs with an execution role.",
        "Glue is relevant when jobs can be created with privileged roles.",
    ),
    "cloudformation": (
        "CloudFormation provisions AWS resources through templates and service roles.",
        "CloudFormation is relevant when stacks can create privileged resources.",
    ),
    "sts": (
        "STS issues temporary credentials for roles and federation.",
        "STS is relevant when trust policies and AssumeRole permissions create pivots.",
    ),
}


def explain_services(actions: tuple[str, ...]) -> tuple[ServiceExplanation, ...]:
    services = tuple(
        sorted({action.split(":", 1)[0] for action in actions if ":" in action})
    )
    explanations: list[ServiceExplanation] = []
    for service in services:
        summary, relevance = SERVICE_SUMMARIES.get(
            service,
            (
                f"{service} is an AWS service involved in this finding.",
                "Review service-specific permissions and runtime evidence.",
            ),
        )
        explanations.append(
            ServiceExplanation(service=service, summary=summary, relevance=relevance)
        )
    return tuple(explanations)
