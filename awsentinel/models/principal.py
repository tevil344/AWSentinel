from dataclasses import dataclass, field
from typing import Dict, List, Any


@dataclass
class UserRecord:
    """Represents a crawled AWS IAM User with its associated attributes."""

    arn: str
    account_id: str
    username: str
    path: str
    user_id: str
    create_date: str
    groups: List[Dict[str, Any]] = field(default_factory=list)
    inline_policies: List[Dict[str, Any]] = field(default_factory=list)
    attached_policies: List[Dict[str, Any]] = field(default_factory=list)
    access_keys: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw_response: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RoleRecord:
    """Represents a crawled AWS IAM Role with its associated attributes."""

    arn: str
    account_id: str
    role_name: str
    role_id: str
    path: str
    create_date: str
    assume_role_policy_document: Dict[str, Any] = field(default_factory=dict)
    inline_policies: List[Dict[str, Any]] = field(default_factory=list)
    attached_policies: List[Dict[str, Any]] = field(default_factory=list)
    instance_profiles: List[Dict[str, Any]] = field(default_factory=list)
    tags: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw_response: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GroupRecord:
    """Represents a crawled AWS IAM Group with its associated attributes."""

    arn: str
    account_id: str
    group_name: str
    group_id: str
    path: str
    create_date: str
    users: List[Dict[str, Any]] = field(default_factory=list)
    inline_policies: List[Dict[str, Any]] = field(default_factory=list)
    attached_policies: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw_response: Dict[str, Any] = field(default_factory=dict)
