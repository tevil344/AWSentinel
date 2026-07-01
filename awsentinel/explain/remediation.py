from awsentinel.explain.models import RemediationExplanation
from awsentinel.explain.templates import template_for


def explain_remediation(
    path_name: str | None, existing_mitigation: str = ""
) -> RemediationExplanation:
    template = template_for(path_name)
    summary = existing_mitigation or template.remediation_summary
    return RemediationExplanation(
        summary=summary,
        rationale=(
            "The safest fix is to reduce the specific permission combination that "
            "makes the attack path possible while preserving known deployment workflows."
        ),
        recommended_actions=template.remediation_actions,
        breakage_risk=template.breakage_risk,
    )
