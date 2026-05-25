from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from awsentinel.graph.types import AttackPath, BlastRadius
from awsentinel.intelligence.constants import IntelligenceSeverity, RemediationDecision


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class RuntimeCorrelatedFinding:
    finding_id: str
    last_seen: Optional[datetime]
    times_used: int
    services_used: tuple[str, ...]
    runtime_active: bool
    active_usage_score: int
    dormant_path_score: int
    runtime_confidence: float
    confidence_adjustment: float

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["last_seen"] = self.last_seen.isoformat() if self.last_seen else None
        return data


@dataclass(frozen=True)
class LeastPrivilegeFinding:
    principal_arn: str
    granted_actions: tuple[str, ...]
    used_actions: tuple[str, ...]
    unused_actions: tuple[str, ...]
    rarely_used_actions: tuple[str, ...]
    overprivileged_score: int
    recommendation: str


@dataclass(frozen=True)
class DependencyProfile:
    principal_arn: str
    downstream_services_count: int
    dependency_risk_score: int
    production_critical: bool
    shared_execution_role: bool
    dependency_fanout: int
    dependencies: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class RemediationSafetyResult:
    finding_id: str
    decision: RemediationDecision
    reasons: tuple[str, ...]
    rollback_feasible: bool


@dataclass(frozen=True)
class SuppressionRecord:
    suppression_id: str
    finding_hash: str
    reason: str
    created_by: str
    expires_at: Optional[datetime]
    created_at: datetime = field(default_factory=utc_now)

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        if not self.expires_at:
            return False
        return self.expires_at <= (now or utc_now())


@dataclass(frozen=True)
class GraphDiffResult:
    new_paths: tuple[str, ...]
    removed_paths: tuple[str, ...]
    risk_delta: int
    newly_reachable_admins: tuple[str, ...]
    removed_admin_paths: tuple[str, ...]


@dataclass(frozen=True)
class StaleAccessFinding:
    principal_arn: str
    stale_type: str
    last_seen: Optional[datetime]
    inactive_days: int
    recommendation: str


@dataclass(frozen=True)
class OperationalRiskScore:
    finding_id: str
    score: int
    severity: IntelligenceSeverity
    confidence: float
    factors: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PriorityScore:
    finding_id: str
    score: int
    severity: IntelligenceSeverity
    rank_reason: str


@dataclass(frozen=True)
class OperationalFindingContext:
    finding_id: str
    attack_path: AttackPath
    runtime: Optional[RuntimeCorrelatedFinding] = None
    dependency: Optional[DependencyProfile] = None
    stale: Optional[StaleAccessFinding] = None
    blast_radius: BlastRadius = BlastRadius.SMALL
    kev_relevant: bool = False
    internet_exposed: bool = False
    false_positive_probability: float = 0.0
