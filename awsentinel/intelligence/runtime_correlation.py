from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from awsentinel.findings.models import RiskFinding
from awsentinel.intelligence.models import RuntimeCorrelatedFinding
from awsentinel.models.authz import EffectivePermissionSet

CORRELATED_EVENT_NAMES = {
    "AssumeRole",
    "PassRole",
    "RunInstances",
    "CreateFunction",
    "InvokeFunction",
    "CreateJob",
    "StartJobRun",
}


class RuntimeCorrelationEngine:
    """Correlates graph findings with CloudTrail runtime activity."""

    def correlate(
        self,
        findings: Iterable[RiskFinding],
        cloudtrail_events: Iterable[dict[str, Any]],
        effective_permissions: Iterable[EffectivePermissionSet] = (),
    ) -> tuple[RuntimeCorrelatedFinding, ...]:
        events = tuple(cloudtrail_events)
        permission_arns = {item.principal_arn for item in effective_permissions}
        results: list[RuntimeCorrelatedFinding] = []

        for finding in sorted(findings, key=lambda item: item.finding_id):
            related = [
                event
                for event in events
                if _event_related_to_finding(event, finding, permission_arns)
            ]
            last_seen = _latest_event_time(related)
            services = tuple(
                sorted(
                    {
                        _service_from_event(event)
                        for event in related
                        if _service_from_event(event)
                    }
                )
            )
            active_usage_score = min(100, len(related) * 20)
            dormant_path_score = _dormant_score(last_seen)
            runtime_active = bool(related and dormant_path_score < 80)
            runtime_confidence = min(1.0, 0.35 + (len(related) * 0.15))

            results.append(
                RuntimeCorrelatedFinding(
                    finding_id=finding.finding_id,
                    last_seen=last_seen,
                    times_used=len(related),
                    services_used=services,
                    runtime_active=runtime_active,
                    active_usage_score=active_usage_score,
                    dormant_path_score=dormant_path_score,
                    runtime_confidence=runtime_confidence,
                    confidence_adjustment=0.2 if runtime_active else -0.25,
                )
            )
        return tuple(results)


def _event_related_to_finding(
    event: dict[str, Any], finding: RiskFinding, permission_arns: set[str]
) -> bool:
    event_name = event.get("EventName") or event.get("eventName")
    if event_name not in CORRELATED_EVENT_NAMES:
        return False
    principal = event.get("Username") or event.get("userIdentity", {}).get("arn")
    if principal in {finding.principal, finding.target}:
        return True
    return bool(principal and principal in permission_arns)


def _latest_event_time(events: Iterable[dict[str, Any]]) -> Optional[datetime]:
    times = [_event_time(event) for event in events]
    times = [time for time in times if time]
    return max(times) if times else None


def _event_time(event: dict[str, Any]) -> Optional[datetime]:
    value = event.get("EventTime") or event.get("eventTime")
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _service_from_event(event: dict[str, Any]) -> str:
    source = event.get("EventSource") or event.get("eventSource") or ""
    if source:
        return str(source).split(".")[0]
    name = str(event.get("EventName") or event.get("eventName") or "")
    service_hints = {
        "AssumeRole": "sts",
        "PassRole": "iam",
        "RunInstances": "ec2",
        "CreateFunction": "lambda",
        "InvokeFunction": "lambda",
        "CreateJob": "glue",
        "StartJobRun": "glue",
    }
    return service_hints.get(name, "")


def _dormant_score(last_seen: Optional[datetime]) -> int:
    if not last_seen:
        return 100
    days = (datetime.now(timezone.utc) - last_seen).days
    return max(0, min(100, days // 4))
