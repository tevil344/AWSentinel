from dataclasses import asdict, dataclass, field
from enum import StrEnum

from awsentinel.graph.types import AttackPath, BlastRadius, Severity, utc_now_iso


class AutoRemediationMode(StrEnum):
    AUTO_SAFE = "AUTO_SAFE"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    SUGGEST_ONLY = "SUGGEST_ONLY"


@dataclass(frozen=True)
class RiskFinding:
    finding_id: str
    finding_type: str
    principal: str
    target: str
    severity: Severity
    confidence: float
    blast_radius: BlastRadius
    attack_path: AttackPath
    matched_privesc_path: str | None
    mitigation: str
    risk_score: int = 0
    auto_remediation: AutoRemediationMode = AutoRemediationMode.SUGGEST_ONLY
    created_at: str = field(default_factory=utc_now_iso)

    @property
    def id(self) -> str:
        return self.finding_id

    @property
    def type(self) -> str:
        return self.finding_type

    def to_dict(self) -> dict:
        data = asdict(self)
        data["id"] = self.finding_id
        data["type"] = self.finding_type
        data["severity"] = self.severity.value
        data["blast_radius"] = self.blast_radius.value
        data["auto_remediation"] = self.auto_remediation.value
        data["attack_path"] = self.attack_path.to_dict()
        return data
