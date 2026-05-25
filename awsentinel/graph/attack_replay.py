from dataclasses import asdict, dataclass, field

from awsentinel.graph.types import AttackPath, Severity, utc_now_iso


@dataclass(frozen=True)
class AttackStep:
    source_node: str
    target_node: str
    action_taken: str
    required_permissions: tuple[str, ...]
    path_type: str
    severity: Severity
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass(frozen=True)
class AttackChain:
    chain_id: str
    steps: tuple[AttackStep, ...]
    source: str
    target: str

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "source": self.source,
            "target": self.target,
            "steps": [step.to_dict() for step in self.steps],
        }


def build_attack_chain(graph, attack_path: AttackPath) -> AttackChain:
    steps: list[AttackStep] = []
    for source, target in zip(attack_path.nodes, attack_path.nodes[1:]):
        edge = graph.edges[source, target]
        steps.append(
            AttackStep(
                source_node=source,
                target_node=target,
                action_taken=edge.get("path_name") or edge.get("edge_type"),
                required_permissions=tuple(edge.get("matched_actions", ())),
                path_type=edge.get("edge_type", ""),
                severity=Severity(edge.get("severity", Severity.LOW.value)),
            )
        )
    chain_id = f"chain:{attack_path.source}->{attack_path.target}:{len(steps)}"
    return AttackChain(
        chain_id=chain_id,
        steps=tuple(steps),
        source=attack_path.source,
        target=attack_path.target,
    )
