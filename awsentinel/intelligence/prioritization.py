from typing import Iterable

from awsentinel.intelligence.models import OperationalFindingContext, PriorityScore
from awsentinel.intelligence.scoring import OperationalScoringEngine


class PrioritizationEngine:
    """Ranks findings by operational relevance, not only graph reachability."""

    def __init__(self, scoring: OperationalScoringEngine | None = None) -> None:
        self._scoring = scoring or OperationalScoringEngine()

    def prioritize(
        self, contexts: Iterable[OperationalFindingContext]
    ) -> tuple[PriorityScore, ...]:
        scores = []
        for context in contexts:
            scored = self._scoring.score(context)
            reason = (
                "runtime-active exploit chain"
                if context.runtime and context.runtime.runtime_active
                else (
                    "stale or theoretical path"
                    if context.stale
                    else "graph-reachable path"
                )
            )
            scores.append(
                PriorityScore(
                    finding_id=context.finding_id,
                    score=scored.score,
                    severity=scored.severity,
                    rank_reason=reason,
                )
            )
        return tuple(sorted(scores, key=lambda item: (-item.score, item.finding_id)))
