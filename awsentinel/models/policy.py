from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional


@dataclass
class PolicyStatement:
    """Represents a single statement in an IAM Policy Document."""

    effect: str
    action: List[str]
    resource: List[str]
    sid: Optional[str] = None
    condition: Optional[Dict[str, Any]] = None
    principal: Optional[Dict[str, Any]] = None
    not_action: Optional[List[str]] = None
    not_resource: Optional[List[str]] = None
    not_principal: Optional[Dict[str, Any]] = None


@dataclass
class PolicyRecord:
    """Represents a crawled AWS IAM Policy with its associated versions and attachments."""

    arn: str
    account_id: str
    policy_name: str
    policy_id: str
    path: str
    create_date: str
    default_version_id: str
    document: Dict[str, Any] = field(default_factory=dict)
    versions: List[Dict[str, Any]] = field(default_factory=list)
    entities: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw_response: Dict[str, Any] = field(default_factory=dict)
