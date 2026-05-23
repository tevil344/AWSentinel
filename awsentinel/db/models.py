from datetime import datetime, timezone
from typing import Any, Dict
from sqlalchemy import String, JSON, DateTime, Integer
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative Base for SQLAlchemy Models."""

    pass


class UserRaw(Base):
    """ORM representation of the users_raw table storing raw IAM User crawl data."""

    __tablename__ = "users_raw"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    aws_account_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    resource_type: Mapped[str] = mapped_column(String, default="user", nullable=False)
    resource_arn: Mapped[str] = mapped_column(String, index=True, nullable=False)
    raw_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    crawled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class RoleRaw(Base):
    """ORM representation of the roles_raw table storing raw IAM Role crawl data."""

    __tablename__ = "roles_raw"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    aws_account_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    resource_type: Mapped[str] = mapped_column(String, default="role", nullable=False)
    resource_arn: Mapped[str] = mapped_column(String, index=True, nullable=False)
    raw_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    crawled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class GroupRaw(Base):
    """ORM representation of the groups_raw table storing raw IAM Group crawl data."""

    __tablename__ = "groups_raw"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    aws_account_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    resource_type: Mapped[str] = mapped_column(String, default="group", nullable=False)
    resource_arn: Mapped[str] = mapped_column(String, index=True, nullable=False)
    raw_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    crawled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class PolicyRaw(Base):
    """ORM representation of the policies_raw table storing raw IAM Policy crawl data."""

    __tablename__ = "policies_raw"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    aws_account_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    resource_type: Mapped[str] = mapped_column(String, default="policy", nullable=False)
    resource_arn: Mapped[str] = mapped_column(String, index=True, nullable=False)
    raw_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    crawled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
