from dataclasses import asdict, dataclass, field
from typing import Any

from awsentinel.graph.types import Severity, utc_now_iso


@dataclass(frozen=True)
class Explanation:
    title: str
    summary: str
    details: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PermissionExplanation:
    action: str
    service: str
    summary: str
    risk: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ServiceExplanation:
    service: str
    summary: str
    relevance: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AttackExplanation:
    path_name: str
    summary: str
    steps: tuple[str, ...]
    services_involved: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RemediationExplanation:
    summary: str
    rationale: str
    recommended_actions: tuple[str, ...]
    breakage_risk: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class FindingExplanation:
    finding_id: str
    severity: Severity
    title: str
    executive_summary: str
    attack: AttackExplanation
    permissions: tuple[PermissionExplanation, ...]
    services: tuple[ServiceExplanation, ...]
    remediation: RemediationExplanation
    evidence: dict[str, Any]
    prompt_context: str
    uncertainty: str = ""
    created_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "severity": self.severity.value,
            "title": self.title,
            "executive_summary": self.executive_summary,
            "attack": self.attack.to_dict(),
            "permissions": [item.to_dict() for item in self.permissions],
            "services": [item.to_dict() for item in self.services],
            "remediation": self.remediation.to_dict(),
            "evidence": self.evidence,
            "prompt_context": self.prompt_context,
            "uncertainty": self.uncertainty,
            "created_at": self.created_at,
        }
