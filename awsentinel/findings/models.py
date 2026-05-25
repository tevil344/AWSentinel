from dataclasses import asdict, dataclass, field

from awsentinel.graph.types import AttackPath, BlastRadius, Severity, utc_now_iso


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
    created_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["blast_radius"] = self.blast_radius.value
        data["attack_path"] = self.attack_path.to_dict()
        return data
