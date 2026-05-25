from awsentinel.intelligence.constants import RemediationDecision
from awsentinel.intelligence.dependency_analysis import DependencyAnalysisEngine
from awsentinel.intelligence.remediation_safety import RemediationSafetyEngine
from tests.phase4_helpers import DEV_ROLE


def test_remediation_safety_blocks_running_workload_and_reviews_production():
    dependency = DependencyAnalysisEngine().analyze(
        (
            {
                "service": "lambda",
                "arn": "arn:aws:lambda:::function:prod",
                "Role": DEV_ROLE,
                "tags": {"Environment": "production"},
            },
        )
    )

    blocked = RemediationSafetyEngine().evaluate(
        "finding-1", DEV_ROLE, dependency, runtime_active=True
    )
    review = RemediationSafetyEngine().evaluate(
        "finding-1", DEV_ROLE, dependency, runtime_active=False
    )

    assert blocked.decision == RemediationDecision.BLOCKED
    assert 'BLOCKED("live workload")' in blocked.reasons
    assert review.decision == RemediationDecision.HUMAN_REVIEW
