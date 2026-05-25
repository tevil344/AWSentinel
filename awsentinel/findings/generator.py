from awsentinel.findings.models import RiskFinding
from awsentinel.graph.risk_classifier import RiskClassifier
from awsentinel.graph.types import AttackPath


class FindingGenerator:
    def __init__(self, classifier: RiskClassifier | None = None) -> None:
        self._classifier = classifier or RiskClassifier()

    def from_attack_paths(
        self, graph, paths: tuple[AttackPath, ...]
    ) -> tuple[RiskFinding, ...]:
        return tuple(self._classifier.finding_for_path(path, graph) for path in paths)
