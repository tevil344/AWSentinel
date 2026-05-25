from datetime import datetime, time
from typing import Iterable, Optional

from awsentinel.intelligence.constants import RemediationDecision
from awsentinel.intelligence.models import DependencyProfile, RemediationSafetyResult


class RemediationSafetyEngine:
    """Classifies whether a proposed remediation is operationally safe."""

    def evaluate(
        self,
        finding_id: str,
        principal_arn: str,
        dependencies: Iterable[DependencyProfile] = (),
        active_sessions: Iterable[str] = (),
        runtime_active: bool = False,
        iac_managed: bool = False,
        maintenance_window: Optional[tuple[time, time]] = None,
        rollback_feasible: bool = True,
    ) -> RemediationSafetyResult:
        reasons: list[str] = []
        profile = next(
            (item for item in dependencies if item.principal_arn == principal_arn), None
        )

        if profile and profile.dependency_fanout > 0 and runtime_active:
            reasons.append('BLOCKED("live workload")')
            return RemediationSafetyResult(
                finding_id=finding_id,
                decision=RemediationDecision.BLOCKED,
                reasons=tuple(reasons),
                rollback_feasible=rollback_feasible,
            )
        if principal_arn in set(active_sessions):
            reasons.append('BLOCKED("active session")')
            return RemediationSafetyResult(
                finding_id=finding_id,
                decision=RemediationDecision.BLOCKED,
                reasons=tuple(reasons),
                rollback_feasible=rollback_feasible,
            )
        if maintenance_window and not _in_window(datetime.now().time(), maintenance_window):
            reasons.append('DEFERRED("maintenance window")')
            return RemediationSafetyResult(
                finding_id=finding_id,
                decision=RemediationDecision.DEFERRED,
                reasons=tuple(reasons),
                rollback_feasible=rollback_feasible,
            )
        if profile and profile.production_critical:
            reasons.append('HUMAN_REVIEW("production-critical")')
            return RemediationSafetyResult(
                finding_id=finding_id,
                decision=RemediationDecision.HUMAN_REVIEW,
                reasons=tuple(reasons),
                rollback_feasible=rollback_feasible,
            )
        if iac_managed:
            reasons.append('HUMAN_REVIEW("IaC-managed")')
            return RemediationSafetyResult(
                finding_id=finding_id,
                decision=RemediationDecision.HUMAN_REVIEW,
                reasons=tuple(reasons),
                rollback_feasible=rollback_feasible,
            )
        if not rollback_feasible:
            reasons.append('HUMAN_REVIEW("rollback not verified")')
            return RemediationSafetyResult(
                finding_id=finding_id,
                decision=RemediationDecision.HUMAN_REVIEW,
                reasons=tuple(reasons),
                rollback_feasible=rollback_feasible,
            )

        return RemediationSafetyResult(
            finding_id=finding_id,
            decision=RemediationDecision.SAFE_AUTO,
            reasons=('SAFE_AUTO("no live dependencies")',),
            rollback_feasible=rollback_feasible,
        )


def _in_window(value: time, window: tuple[time, time]) -> bool:
    start, end = window
    if start <= end:
        return start <= value <= end
    return value >= start or value <= end
