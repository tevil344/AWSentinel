from awsentinel.graph.risk_classifier import RiskClassifier, RiskSignals
from awsentinel.graph.types import BlastRadius, Severity


def test_risk_classifier_scores_false_positive_penalties_and_blast_radius():
    classifier = RiskClassifier()

    high_confidence_score = classifier.score(
        RiskSignals(
            admin_reachability=True,
            privilege_escalation_capability=True,
            kev_active_techniques=True,
            blast_radius=BlastRadius.ACCOUNT_WIDE,
            false_positive_probability=0.1,
        )
    )
    penalized_score = classifier.score(
        RiskSignals(
            admin_reachability=True,
            privilege_escalation_capability=True,
            kev_active_techniques=True,
            blast_radius=BlastRadius.ACCOUNT_WIDE,
            false_positive_probability=0.9,
        )
    )

    assert high_confidence_score == 90
    assert penalized_score == 55
    assert classifier.severity(high_confidence_score) == Severity.CRITICAL
    assert classifier.blast_radius(101) == BlastRadius.LARGE
