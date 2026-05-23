import datetime
import os
from typing import Any, List
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from awsentinel.db.models import Base, UserRaw, RoleRaw, GroupRaw, PolicyRaw
from awsentinel.models.principal import UserRecord, RoleRecord, GroupRecord
from awsentinel.models.policy import PolicyRecord


def serialize_datetime(obj: Any) -> Any:
    """Recursively converts datetime/date objects to ISO format strings to ensure JSON compatibility."""
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    if isinstance(obj, datetime.date):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: serialize_datetime(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [serialize_datetime(item) for item in obj]
    return obj


class DatabaseStore:
    """Manages the SQLite database initialization, sessions, and saving raw records."""

    def __init__(self, db_path: str = "~/.awsentinel/db.sqlite"):
        # Resolve the tilde to the absolute user directory
        self.raw_db_path = os.path.expanduser(db_path)

        # Ensure parent directory exists
        db_dir = os.path.dirname(self.raw_db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        self.engine = create_engine(f"sqlite:///{self.raw_db_path}")
        self.SessionLocal = sessionmaker(
            autocommit=False, autoflush=False, bind=self.engine
        )

        # Create tables if they do not exist
        Base.metadata.create_all(bind=self.engine)

    def save_users(self, users: List[UserRecord]) -> None:
        """Persists raw user JSON payloads in the database."""
        with self.SessionLocal() as session:
            for user in users:
                raw_item = UserRaw(
                    aws_account_id=user.account_id,
                    resource_type="user",
                    resource_arn=user.arn,
                    raw_json=serialize_datetime(user.raw_response),
                )
                session.add(raw_item)
            session.commit()

    def save_roles(self, roles: List[RoleRecord]) -> None:
        """Persists raw role JSON payloads in the database."""
        with self.SessionLocal() as session:
            for role in roles:
                raw_item = RoleRaw(
                    aws_account_id=role.account_id,
                    resource_type="role",
                    resource_arn=role.arn,
                    raw_json=serialize_datetime(role.raw_response),
                )
                session.add(raw_item)
            session.commit()

    def save_groups(self, groups: List[GroupRecord]) -> None:
        """Persists raw group JSON payloads in the database."""
        with self.SessionLocal() as session:
            for group in groups:
                raw_item = GroupRaw(
                    aws_account_id=group.account_id,
                    resource_type="group",
                    resource_arn=group.arn,
                    raw_json=serialize_datetime(group.raw_response),
                )
                session.add(raw_item)
            session.commit()

    def save_policies(self, policies: List[PolicyRecord]) -> None:
        """Persists raw policy JSON payloads in the database."""
        with self.SessionLocal() as session:
            for policy in policies:
                raw_item = PolicyRaw(
                    aws_account_id=policy.account_id,
                    resource_type="policy",
                    resource_arn=policy.arn,
                    raw_json=serialize_datetime(policy.raw_response),
                )
                session.add(raw_item)
            session.commit()
