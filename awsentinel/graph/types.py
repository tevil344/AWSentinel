from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Optional


class NodeType(StrEnum):
    USER = "USER"
    ROLE = "ROLE"
    GROUP = "GROUP"
    MANAGED_POLICY = "MANAGED_POLICY"
    INLINE_POLICY = "INLINE_POLICY"
    INSTANCE_PROFILE = "INSTANCE_PROFILE"
    AWS_ACCOUNT = "AWS_ACCOUNT"
    ORGANIZATION_ROOT = "ORGANIZATION_ROOT"
    ORGANIZATION_OU = "ORGANIZATION_OU"


class EdgeType(StrEnum):
    MEMBER_OF = "MEMBER_OF"
    ATTACHED_POLICY = "ATTACHED_POLICY"
    CAN_ASSUME = "CAN_ASSUME"
    INSTANCE_PROFILE = "INSTANCE_PROFILE"
    PRIVESC_TO = "PRIVESC_TO"
    PASSROLE_TO = "PASSROLE_TO"
    LATERAL_TO = "LATERAL_TO"
    SCP_RESTRICTS = "SCP_RESTRICTS"


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class BlastRadius(StrEnum):
    SMALL = "SMALL"
    MEDIUM = "MEDIUM"
    LARGE = "LARGE"
    ACCOUNT_WIDE = "ACCOUNT_WIDE"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class GraphNode:
    node_id: str
    arn: Optional[str]
    node_type: NodeType
    aws_account_id: str
    raw_metadata: dict[str, Any] = field(default_factory=dict)
    is_admin: bool = False
    reachable_admin: bool = False
    blast_radius: BlastRadius = BlastRadius.SMALL
    risk_score: int = 0
    severity: Severity = Severity.LOW
    tags: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    created_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["node_type"] = self.node_type.value
        data["blast_radius"] = self.blast_radius.value
        data["severity"] = self.severity.value
        return data


@dataclass(frozen=True)
class GraphEdge:
    edge_id: str
    edge_type: EdgeType
    source: str
    target: str
    matched_actions: tuple[str, ...] = field(default_factory=tuple)
    source_policies: tuple[str, ...] = field(default_factory=tuple)
    path_name: Optional[str] = None
    severity: Severity = Severity.LOW
    confidence: float = 1.0
    provenance: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["edge_type"] = self.edge_type.value
        data["severity"] = self.severity.value
        return data


@dataclass(frozen=True)
class AttackPath:
    source: str
    target: str
    nodes: tuple[str, ...]
    edges: tuple[str, ...]
    path_length: int
    escalation_stages: int
    lateral_movement_stages: int
    privilege_transitions: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def deterministic_node_id(node_type: NodeType, stable_value: str) -> str:
    return f"{node_type.value}:{stable_value}"


def deterministic_edge_id(
    edge_type: EdgeType, source: str, target: str, path: str = ""
) -> str:
    return f"{edge_type.value}:{source}->{target}:{path}"
