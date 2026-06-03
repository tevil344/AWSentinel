from datetime import datetime, time
from typing import Iterable, Optional

from awsentinel.intelligence.constants import RemediationDecision
from awsentinel.intelligence.models import DependencyProfile, RemediationSafetyResult

SAFE_THRESHOLD = 40


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
        exception_tag: bool = False,
        terraform_managed: bool = False,
        lockout_risk: bool = False,
        running_compute: bool = False,
        used_in_last_24h: bool = False,
    ) -> RemediationSafetyResult:
        reasons: list[str] = []
        profile = next(
            (item for item in dependencies if item.principal_arn == principal_arn), None
        )

        if exception_tag:
            return _decision(
                finding_id,
                RemediationDecision.BLOCKED,
                'BLOCKED("exception tag set")',
                rollback_feasible,
            )
        if terraform_managed or iac_managed:
            return _decision(
                finding_id,
                RemediationDecision.HUMAN_REVIEW,
                'SUGGEST_PR("IaC-managed")',
                rollback_feasible,
            )
        if not rollback_feasible:
            return _decision(
                finding_id,
                RemediationDecision.BLOCKED,
                'BLOCKED("no rollback path")',
                rollback_feasible,
            )
        if lockout_risk:
            return _decision(
                finding_id,
                RemediationDecision.BLOCKED,
                'BLOCKED("lockout risk")',
                rollback_feasible,
            )
        if profile and profile.dependency_fanout > 0 and runtime_active:
            return _decision(
                finding_id,
                RemediationDecision.BLOCKED,
                'BLOCKED("live workload")',
                rollback_feasible,
            )
        if running_compute:
            return _decision(
                finding_id,
                RemediationDecision.HUMAN_REVIEW,
                'HUMAN_ONLY("live workload")',
                rollback_feasible,
            )
        if principal_arn in set(active_sessions):
            return _decision(
                finding_id,
                RemediationDecision.BLOCKED,
                'BLOCKED("active session")',
                rollback_feasible,
            )
        if maintenance_window and not _in_window(
            datetime.now().time(), maintenance_window
        ):
            return _decision(
                finding_id,
                RemediationDecision.DEFERRED,
                'DEFERRED("outside window")',
                rollback_feasible,
            )

        risk = 0
        if profile and profile.production_critical:
            risk += 40
            reasons.append('RISK("production-critical")')
        if principal_arn in set(active_sessions):
            risk += 30
        if profile and profile.downstream_services_count > 3:
            risk += 20
            reasons.append('RISK("downstream services > 3")')
        if used_in_last_24h or runtime_active:
            risk += 20
            reasons.append('RISK("used in last 24h")')

        if risk < SAFE_THRESHOLD:
            return RemediationSafetyResult(
                finding_id=finding_id,
                decision=RemediationDecision.SAFE_AUTO,
                reasons=('SAFE_AUTO("low operational risk")',),
                rollback_feasible=rollback_feasible,
            )
        return RemediationSafetyResult(
            finding_id=finding_id,
            decision=RemediationDecision.HUMAN_REVIEW,
            reasons=tuple(reasons) or ('APPROVAL_REQUIRED("operational risk")',),
            rollback_feasible=rollback_feasible,
        )


def validate_remediation_safety(*args, **kwargs) -> RemediationSafetyResult:
    return RemediationSafetyEngine().evaluate(*args, **kwargs)


def _decision(
    finding_id: str,
    decision: RemediationDecision,
    reason: str,
    rollback_feasible: bool,
) -> RemediationSafetyResult:
    return RemediationSafetyResult(
        finding_id=finding_id,
        decision=decision,
        reasons=(reason,),
        rollback_feasible=rollback_feasible,
    )


def _in_window(value: time, window: tuple[time, time]) -> bool:
    start, end = window
    if start <= end:
        return start <= value <= end
    return value >= start or value <= end
