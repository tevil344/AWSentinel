from dataclasses import asdict, dataclass
from typing import Any

from awsentinel.findings.models import RiskFinding
from awsentinel.graph.attack_replay import AttackChain


@dataclass(frozen=True)
class EvidenceReference:
    evidence_type: str
    source: str
    value: str
    confidence: float = 1.0
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["metadata"] = self.metadata or {}
        return data


def build_evidence(
    finding: RiskFinding, attack_chain: AttackChain | None = None
) -> tuple[EvidenceReference, ...]:
    evidence: list[EvidenceReference] = [
        EvidenceReference("principal", "finding", finding.principal),
        EvidenceReference("target", "finding", finding.target),
        EvidenceReference(
            "attack_path",
            "graph",
            " -> ".join(finding.attack_path.nodes),
            metadata=finding.attack_path.to_dict(),
        ),
    ]
    if finding.matched_privesc_path:
        evidence.append(
            EvidenceReference(
                "matched_privesc_path",
                "path_registry",
                finding.matched_privesc_path,
            )
        )
    for edge_id in finding.attack_path.edges:
        evidence.append(EvidenceReference("graph_edge", "attack_path", edge_id))
    if attack_chain:
        for step in attack_chain.steps:
            evidence.append(
                EvidenceReference(
                    "attack_step",
                    "attack_chain",
                    f"{step.source_node} --{step.action_taken}--> {step.target_node}",
                    metadata=step.to_dict(),
                )
            )
            for action in step.required_permissions:
                evidence.append(
                    EvidenceReference("matched_permission", "attack_chain", action)
                )
    return tuple(sorted(evidence, key=lambda item: (item.evidence_type, item.value)))


def evidence_to_dict(evidence: tuple[EvidenceReference, ...]) -> dict[str, Any]:
    return {
        "items": [item.to_dict() for item in evidence],
        "complete": has_minimum_evidence(evidence),
        "missing": missing_evidence(evidence),
    }


def has_minimum_evidence(evidence: tuple[EvidenceReference, ...]) -> bool:
    evidence_types = {item.evidence_type for item in evidence}
    return {"principal", "target", "attack_path"}.issubset(evidence_types)


def missing_evidence(evidence: tuple[EvidenceReference, ...]) -> tuple[str, ...]:
    evidence_types = {item.evidence_type for item in evidence}
    required = ("principal", "target", "attack_path")
    return tuple(item for item in required if item not in evidence_types)
