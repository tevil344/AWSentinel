from awsentinel.graph.types import BlastRadius
from awsentinel.intelligence.constants import IntelligenceSeverity
from awsentinel.intelligence.models import (
    OperationalFindingContext,
    OperationalRiskScore,
)


class OperationalScoringEngine:
    """Weighted operational risk scoring with confidence and FP penalties."""

    def score(self, context: OperationalFindingContext) -> OperationalRiskScore:
        value = 0
        value += 30
        value += _runtime_weight(context)
        value += _blast_radius_weight(context.blast_radius)
        value += 10 if context.kev_relevant else 0
        value += min(15, context.attack_path.privilege_transitions * 5)
        value += min(10, context.attack_path.lateral_movement_stages * 5)
        if context.dependency:
            value += min(15, context.dependency.dependency_fanout * 3)
        if context.stale:
            value -= 30
        if context.false_positive_probability > 0.5:
            value -= 20
        if context.false_positive_probability > 0.8:
            value -= 15

        bounded = max(0, min(100, value))
        confidence = max(
            0.0,
            min(
                1.0,
                0.75
                + (context.runtime.confidence_adjustment if context.runtime else 0.0)
                - (context.false_positive_probability * 0.25),
            ),
        )
        return OperationalRiskScore(
            finding_id=context.finding_id,
            score=bounded,
            severity=_severity(bounded),
            confidence=round(confidence, 2),
            factors={
                "runtime_active": bool(
                    context.runtime and context.runtime.runtime_active
                ),
                "blast_radius": context.blast_radius.value,
                "stale": context.stale is not None,
                "dependency_fanout": (
                    context.dependency.dependency_fanout if context.dependency else 0
                ),
            },
        )


def _runtime_weight(context: OperationalFindingContext) -> int:
    if not context.runtime:
        return 0
    if context.runtime.runtime_active:
        return 25
    return -20


def _blast_radius_weight(blast_radius: BlastRadius) -> int:
    return {
        BlastRadius.SMALL: 0,
        BlastRadius.MEDIUM: 5,
        BlastRadius.LARGE: 10,
        BlastRadius.ACCOUNT_WIDE: 20,
    }[blast_radius]


def _severity(score: int) -> IntelligenceSeverity:
    if score >= 85:
        return IntelligenceSeverity.CRITICAL
    if score >= 65:
        return IntelligenceSeverity.HIGH
    if score >= 35:
        return IntelligenceSeverity.MEDIUM
    if score >= 10:
        return IntelligenceSeverity.LOW
    return IntelligenceSeverity.INFO
