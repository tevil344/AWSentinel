from dataclasses import dataclass

from awsentinel.findings.models import RiskFinding
from awsentinel.graph.privesc_paths import path_registry
from awsentinel.graph.types import AttackPath, BlastRadius, Severity


@dataclass(frozen=True)
class RiskSignals:
    admin_reachability: bool = False
    internet_exposure: bool = False
    privilege_escalation_capability: bool = False
    lateral_movement_capability: bool = False
    production_criticality: bool = False
    stale_credentials: bool = False
    kev_active_techniques: bool = False
    blast_radius: BlastRadius = BlastRadius.SMALL
    false_positive_probability: float = 0.0


class RiskClassifier:
    """Scores graph findings using bounded deterministic security signals."""

    def score(self, signals: RiskSignals) -> int:
        score = 0
        score += 35 if signals.admin_reachability else 0
        score += 10 if signals.internet_exposure else 0
        score += 25 if signals.privilege_escalation_capability else 0
        score += 15 if signals.lateral_movement_capability else 0
        score += 10 if signals.production_criticality else 0
        score += 5 if signals.stale_credentials else 0
        score += 10 if signals.kev_active_techniques else 0
        score += {
            BlastRadius.SMALL: 0,
            BlastRadius.MEDIUM: 5,
            BlastRadius.LARGE: 10,
            BlastRadius.ACCOUNT_WIDE: 20,
        }[signals.blast_radius]
        if signals.false_positive_probability > 0.5:
            score -= 20
        if signals.false_positive_probability > 0.8:
            score -= 15
        return max(0, min(100, score))

    def severity(self, score: int) -> Severity:
        if score >= 85:
            return Severity.CRITICAL
        if score >= 65:
            return Severity.HIGH
        if score >= 35:
            return Severity.MEDIUM
        return Severity.LOW

    def blast_radius(self, node_count: int, account_wide: bool = False) -> BlastRadius:
        if account_wide:
            return BlastRadius.ACCOUNT_WIDE
        if node_count >= 100:
            return BlastRadius.LARGE
        if node_count >= 10:
            return BlastRadius.MEDIUM
        return BlastRadius.SMALL

    def finding_for_path(self, attack_path: AttackPath, graph) -> RiskFinding:
        privesc_name = self._matched_privesc_path(attack_path, graph)
        definition = next(
            (path for path in path_registry() if path.path_name == privesc_name),
            None,
        )
        blast_radius = self.blast_radius(len(attack_path.nodes), account_wide=True)
        signals = RiskSignals(
            admin_reachability=True,
            privilege_escalation_capability=privesc_name is not None,
            lateral_movement_capability=attack_path.lateral_movement_stages > 0,
            kev_active_techniques=bool(definition and definition.kev_relevant),
            blast_radius=blast_radius,
            false_positive_probability=0.05,
        )
        score = self.score(signals)
        return RiskFinding(
            finding_id=f"finding:{attack_path.source}->{attack_path.target}",
            finding_type="ADMIN_REACHABILITY",
            principal=attack_path.source,
            target=attack_path.target,
            severity=self.severity(score),
            confidence=0.95,
            blast_radius=blast_radius,
            attack_path=attack_path,
            matched_privesc_path=privesc_name,
            mitigation=(
                definition.mitigation_guidance
                if definition
                else "Reduce reachable privilege paths."
            ),
        )

    def _matched_privesc_path(self, attack_path: AttackPath, graph) -> str | None:
        for source, target in zip(attack_path.nodes, attack_path.nodes[1:]):
            edge = graph.edges[source, target]
            if edge.get("path_name"):
                return edge["path_name"]
        return None
