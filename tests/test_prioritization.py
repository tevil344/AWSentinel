from datetime import datetime, timedelta, timezone

from awsentinel.graph.types import BlastRadius
from awsentinel.intelligence.constants import RemediationDecision
from awsentinel.intelligence.dependency_analysis import DependencyAnalysisEngine
from awsentinel.intelligence.models import OperationalFindingContext
from awsentinel.intelligence.prioritization import PrioritizationEngine
from awsentinel.intelligence.remediation_safety import RemediationSafetyEngine
from awsentinel.intelligence.runtime_correlation import RuntimeCorrelationEngine
from awsentinel.intelligence.scoring import OperationalScoringEngine
from awsentinel.intelligence.stale_access import StaleAccessAnalyzer
from tests.phase4_helpers import DEV_ROLE, attack_fixture, cloudtrail_event


def test_prioritization_orders_runtime_active_above_stale_paths():
    _, permissions, path, finding, _ = attack_fixture()
    runtime_active = RuntimeCorrelationEngine().correlate(
        (finding,), (cloudtrail_event(1),), permissions
    )[0]
    stale = StaleAccessAnalyzer().analyze(
        (DEV_ROLE,), {DEV_ROLE: datetime.now(timezone.utc) - timedelta(days=400)}
    )[0]

    active_context = OperationalFindingContext(
        finding_id="active",
        attack_path=path,
        runtime=runtime_active,
        blast_radius=BlastRadius.ACCOUNT_WIDE,
        kev_relevant=True,
    )
    stale_context = OperationalFindingContext(
        finding_id="stale",
        attack_path=path,
        stale=stale,
        blast_radius=BlastRadius.SMALL,
    )

    scores = PrioritizationEngine().prioritize((stale_context, active_context))

    assert scores[0].finding_id == "active"
    assert scores[0].score > scores[1].score


def test_confidence_scoring_and_runtime_activity_weighting():
    _, permissions, path, finding, _ = attack_fixture()
    runtime = RuntimeCorrelationEngine().correlate(
        (finding,), (cloudtrail_event(1),), permissions
    )[0]
    score = OperationalScoringEngine().score(
        OperationalFindingContext(
            finding_id=finding.finding_id,
            attack_path=path,
            runtime=runtime,
            blast_radius=BlastRadius.ACCOUNT_WIDE,
            false_positive_probability=0.9,
        )
    )

    assert score.score == 45
    assert score.confidence < 1.0


def test_phase4_critical_integration_stale_sandbox_is_downgraded_and_safe_auto():
    _, permissions, path, finding, _ = attack_fixture()
    runtime = RuntimeCorrelationEngine().correlate((finding,), (), permissions)[0]
    stale = StaleAccessAnalyzer().analyze(
        (DEV_ROLE,), {DEV_ROLE: datetime.now(timezone.utc) - timedelta(days=400)}
    )[0]
    context = OperationalFindingContext(
        finding_id=finding.finding_id,
        attack_path=path,
        runtime=runtime,
        stale=stale,
        blast_radius=BlastRadius.SMALL,
    )

    priority = PrioritizationEngine().prioritize((context,))[0]
    safety = RemediationSafetyEngine().evaluate(finding.finding_id, DEV_ROLE)

    assert priority.score < 35
    assert safety.decision == RemediationDecision.SAFE_AUTO


def test_phase4_critical_integration_active_production_lambda_is_critical_and_blocked():
    _, permissions, path, finding, _ = attack_fixture()
    runtime = RuntimeCorrelationEngine().correlate(
        (finding,), (cloudtrail_event(1),), permissions
    )[0]
    dependencies = DependencyAnalysisEngine().analyze(
        (
            {
                "service": "lambda",
                "arn": "arn:aws:lambda:::function:prod",
                "Role": DEV_ROLE,
                "tags": {"Environment": "production"},
            },
        )
    )
    context = OperationalFindingContext(
        finding_id=finding.finding_id,
        attack_path=path,
        runtime=runtime,
        dependency=dependencies[0],
        blast_radius=BlastRadius.ACCOUNT_WIDE,
        kev_relevant=True,
    )

    priority = PrioritizationEngine().prioritize((context,))[0]
    safety = RemediationSafetyEngine().evaluate(
        finding.finding_id, DEV_ROLE, dependencies, runtime_active=True
    )

    assert priority.severity == "CRITICAL"
    assert safety.decision == RemediationDecision.BLOCKED
