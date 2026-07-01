from awsentinel.explain.attack_reasoning import explain_attack
from awsentinel.explain.evidence import build_evidence, evidence_to_dict
from awsentinel.explain.models import FindingExplanation
from awsentinel.explain.permission_reasoning import explain_permissions
from awsentinel.explain.prompt_builder import build_prompt_context
from awsentinel.explain.remediation import explain_remediation
from awsentinel.explain.service_reasoning import explain_services
from awsentinel.explain.templates import template_for
from awsentinel.findings.models import RiskFinding
from awsentinel.graph.attack_replay import AttackChain


class ExplanationEngine:
    """Generates deterministic, rule-based explanations for findings."""

    def generate_explanation(
        self, finding: RiskFinding, attack_chain: AttackChain | None = None
    ) -> FindingExplanation:
        path_name = finding.matched_privesc_path
        template = template_for(path_name)
        actions = _actions_from_finding(finding, attack_chain)
        attack = explain_attack(path_name, attack_chain)
        permissions = explain_permissions(actions)
        services = explain_services(actions)
        remediation = explain_remediation(path_name, finding.mitigation)
        evidence = build_evidence(finding, attack_chain)
        evidence_payload = evidence_to_dict(evidence)
        uncertainty = _uncertainty_note(finding.confidence, evidence_payload)

        explanation = FindingExplanation(
            finding_id=finding.finding_id,
            severity=finding.severity,
            title=template.title,
            executive_summary=template.summary,
            attack=attack,
            permissions=permissions,
            services=services,
            remediation=remediation,
            evidence={
                **evidence_payload,
                "risk_score": finding.risk_score,
                "confidence": finding.confidence,
            },
            prompt_context="",
            uncertainty=uncertainty,
        )
        return FindingExplanation(
            **{
                **explanation.__dict__,
                "prompt_context": build_prompt_context(explanation),
            }
        )


def _actions_from_finding(
    finding: RiskFinding, attack_chain: AttackChain | None
) -> tuple[str, ...]:
    if attack_chain:
        actions = {
            action
            for step in attack_chain.steps
            for action in step.required_permissions
        }
        if actions:
            return tuple(sorted(actions))
    if finding.attack_path.edges:
        action_candidates = {
            part
            for edge_id in finding.attack_path.edges
            for part in edge_id.replace(":", "|").replace("+", "|").split("|")
            if part in {"PassRole", "RunInstances", "CreateFunction"}
        }
        mapped = {
            "PassRole": "iam:PassRole",
            "RunInstances": "ec2:RunInstances",
            "CreateFunction": "lambda:CreateFunction",
        }
        return tuple(
            sorted(mapped[item] for item in action_candidates if item in mapped)
        )
    return ()


def _uncertainty_note(confidence: float, evidence: dict) -> str:
    if not evidence.get("complete"):
        return (
            "This explanation has incomplete evidence and should be treated as "
            "a hypothesis until the missing evidence is attached."
        )
    if confidence < 0.7:
        return (
            "AWSentinel has lower confidence in this finding; validate the graph "
            "path and runtime evidence before remediation."
        )
    return "Evidence is sufficient for deterministic rule-based explanation."
