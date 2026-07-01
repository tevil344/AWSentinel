from awsentinel.explain.models import FindingExplanation


def build_prompt_context(explanation: FindingExplanation) -> str:
    permission_lines = "\n".join(
        f"- {item.action}: {item.summary}" for item in explanation.permissions
    )
    service_lines = "\n".join(
        f"- {item.service}: {item.relevance}" for item in explanation.services
    )
    steps = "\n".join(f"- {step}" for step in explanation.attack.steps)
    evidence_lines = "\n".join(
        (
            f"- {item.get('evidence_type')}: {item.get('value')}"
            for item in explanation.evidence.get("items", [])
        )
    )
    return (
        "Explain this AWSentinel finding for a cloud security engineer.\n"
        f"Finding: {explanation.title}\n"
        f"Severity: {explanation.severity.value}\n"
        f"Summary: {explanation.executive_summary}\n"
        f"Attack steps:\n{steps}\n"
        f"Permissions:\n{permission_lines}\n"
        f"Services:\n{service_lines}\n"
        f"Evidence:\n{evidence_lines}\n"
        f"Uncertainty: {explanation.uncertainty}\n"
        f"Remediation: {explanation.remediation.summary}\n"
    )
