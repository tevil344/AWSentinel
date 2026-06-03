from dataclasses import dataclass
from typing import Any

from awsentinel.findings.models import AutoRemediationMode, RiskFinding
from awsentinel.graph.privesc_paths import path_registry
from awsentinel.graph.types import AttackPath, BlastRadius, Severity

SAFE_AUTOFIX_TYPES = {"STALE_ACCESS", "UNUSED_PERMISSION", "INACTIVE_ACCESS_KEY"}


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


@dataclass(frozen=True)
class RiskClassification:
    risk_score: int
    severity: Severity
    blast_radius: BlastRadius
    confidence: float
    auto_remediation: AutoRemediationMode


def classify_risk(finding: Any) -> RiskClassification:
    score = 0
    if _truthy(finding, "privesc_to_admin", "admin_reachability"):
        score += 40
    if _truthy(finding, "internet_exposed", "internet_exposure"):
        score += 30
    if getattr(finding, "environment", "") == "prod":
        score += 20
    if _truthy(finding, "contains_sensitive_data"):
        score += 20
    if _truthy(finding, "lateral_movement_risk", "lateral_movement_capability"):
        score += 15
    if _truthy(finding, "no_mfa_on_principal"):
        score += 10
    if _truthy(finding, "active_in_kev", "kev_active_techniques"):
        score += 15
    if _truthy(finding, "cross_account_trust"):
        score += 10

    false_positive_prob = float(getattr(finding, "false_positive_prob", 0.0))
    false_positive_prob = float(
        getattr(finding, "false_positive_probability", false_positive_prob)
    )
    if false_positive_prob > 0.5:
        score -= 20
    if false_positive_prob > 0.8:
        score -= 15

    score = max(0, min(100, score))
    severity = map_score(score)
    blast = estimate_blast_radius(finding)
    confidence = compute_confidence(finding)
    finding_type = str(getattr(finding, "type", getattr(finding, "finding_type", "")))
    if severity == Severity.CRITICAL:
        mode = AutoRemediationMode.APPROVAL_REQUIRED
    elif finding_type in SAFE_AUTOFIX_TYPES:
        mode = AutoRemediationMode.AUTO_SAFE
    else:
        mode = AutoRemediationMode.SUGGEST_ONLY
    return RiskClassification(score, severity, blast, confidence, mode)


def map_score(score: int) -> Severity:
    if score >= 80:
        return Severity.CRITICAL
    if score >= 60:
        return Severity.HIGH
    if score >= 40:
        return Severity.MEDIUM
    return Severity.LOW


def estimate_blast_radius(finding: Any) -> BlastRadius:
    current = getattr(finding, "blast_radius", None)
    if current:
        return current if isinstance(current, BlastRadius) else BlastRadius(str(current))
    if _truthy(finding, "account_wide", "privesc_to_admin"):
        return BlastRadius.ACCOUNT_WIDE
    downstream = int(getattr(finding, "downstream_services", 0))
    affected = int(getattr(finding, "affected_resources", downstream))
    if affected >= 100 or downstream > 10:
        return BlastRadius.LARGE
    if affected >= 10 or downstream > 3:
        return BlastRadius.MEDIUM
    return BlastRadius.SMALL


def compute_confidence(finding: Any) -> float:
    confidence = float(getattr(finding, "confidence", 0.75))
    evidence_count = int(getattr(finding, "evidence_count", 0))
    if evidence_count:
        confidence += min(0.2, evidence_count * 0.05)
    confidence -= float(getattr(finding, "false_positive_prob", 0.0)) * 0.25
    return round(max(0.0, min(1.0, confidence)), 2)


def _truthy(finding: Any, *names: str) -> bool:
    return any(bool(getattr(finding, name, False)) for name in names)


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
        return map_score(score)

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
        severity = self.severity(score)
        auto_remediation = (
            AutoRemediationMode.APPROVAL_REQUIRED
            if severity == Severity.CRITICAL
            else AutoRemediationMode.SUGGEST_ONLY
        )
        return RiskFinding(
            finding_id=f"finding:{attack_path.source}->{attack_path.target}",
            finding_type="ADMIN_REACHABILITY",
            principal=attack_path.source,
            target=attack_path.target,
            severity=severity,
            confidence=0.95,
            blast_radius=blast_radius,
            attack_path=attack_path,
            matched_privesc_path=privesc_name,
            mitigation=(
                definition.mitigation_guidance
                if definition
                else "Reduce reachable privilege paths."
            ),
            risk_score=score,
            auto_remediation=auto_remediation,
        )

    def _matched_privesc_path(self, attack_path: AttackPath, graph) -> str | None:
        for source, target in zip(attack_path.nodes, attack_path.nodes[1:]):
            edge = graph.edges[source, target]
            if edge.get("path_name"):
                return edge["path_name"]
        return None
