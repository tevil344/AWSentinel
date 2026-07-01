from awsentinel.explain.engine import ExplanationEngine
from awsentinel.explain.permission_reasoning import explain_permissions
from awsentinel.explain.service_reasoning import explain_services
from tests.phase4_helpers import attack_fixture


def test_explanation_engine_generates_rule_based_finding_explanation():
    _, _, _, finding, chain = attack_fixture()

    explanation = ExplanationEngine().generate_explanation(finding, chain)

    assert explanation.finding_id == finding.finding_id
    assert explanation.title == "EC2 launch path can reach administrator privileges"
    assert explanation.attack.path_name == "PassRole+RunInstances"
    assert explanation.permissions[0].action == "ec2:RunInstances"
    assert explanation.permissions[1].action == "iam:PassRole"
    assert {service.service for service in explanation.services} == {"ec2", "iam"}
    assert "Restrict iam:PassRole" in explanation.remediation.summary
    assert "Attack steps:" in explanation.prompt_context
    assert explanation.evidence["complete"] is True
    assert not explanation.evidence["missing"]
    assert any(
        item["evidence_type"] == "matched_permission"
        for item in explanation.evidence["items"]
    )
    assert "Evidence:" in explanation.prompt_context
    assert explanation.to_dict()["severity"] == "CRITICAL"


def test_permission_reasoning_explains_known_and_unknown_actions():
    known, unknown = explain_permissions(("iam:PassRole", "s3:ListBucket"))

    assert known.action == "iam:PassRole"
    assert "delegate an IAM role" in known.summary
    assert unknown.action == "s3:ListBucket"
    assert "Review whether this action is required" in unknown.risk


def test_service_reasoning_deduplicates_services():
    services = explain_services(("iam:PassRole", "iam:GetRole", "ec2:RunInstances"))

    assert tuple(service.service for service in services) == ("ec2", "iam")
    assert "instance" in services[0].summary.lower()


def test_explanation_engine_states_uncertainty_when_confidence_is_low():
    _, _, _, finding, chain = attack_fixture()
    low_confidence = finding.__class__(
        **{
            **finding.__dict__,
            "confidence": 0.4,
        }
    )

    explanation = ExplanationEngine().generate_explanation(low_confidence, chain)

    assert "lower confidence" in explanation.uncertainty
