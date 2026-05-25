from datetime import datetime, timezone
from typing import Any, Dict
from sqlalchemy import Float, Index, JSON, String, DateTime, Integer
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative Base for SQLAlchemy Models."""

    pass


class UserRaw(Base):
    """ORM representation of the users_raw table storing raw IAM User crawl data."""

    __tablename__ = "users_raw"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    aws_account_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    resource_type: Mapped[str] = mapped_column(String, default="user", nullable=False)
    resource_arn: Mapped[str] = mapped_column(String, index=True, nullable=False)
    raw_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    crawled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    version_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_users_raw_resource_arn_scan_id", "resource_arn", "scan_id"),
        Index("ix_users_raw_crawled_at", "crawled_at"),
    )


class RoleRaw(Base):
    """ORM representation of the roles_raw table storing raw IAM Role crawl data."""

    __tablename__ = "roles_raw"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    aws_account_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    resource_type: Mapped[str] = mapped_column(String, default="role", nullable=False)
    resource_arn: Mapped[str] = mapped_column(String, index=True, nullable=False)
    raw_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    crawled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    version_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_roles_raw_resource_arn_scan_id", "resource_arn", "scan_id"),
        Index("ix_roles_raw_crawled_at", "crawled_at"),
    )


class GroupRaw(Base):
    """ORM representation of the groups_raw table storing raw IAM Group crawl data."""

    __tablename__ = "groups_raw"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    aws_account_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    resource_type: Mapped[str] = mapped_column(String, default="group", nullable=False)
    resource_arn: Mapped[str] = mapped_column(String, index=True, nullable=False)
    raw_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    crawled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    version_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_groups_raw_resource_arn_scan_id", "resource_arn", "scan_id"),
        Index("ix_groups_raw_crawled_at", "crawled_at"),
    )


class PolicyRaw(Base):
    """ORM representation of the policies_raw table storing raw IAM Policy crawl data."""

    __tablename__ = "policies_raw"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    aws_account_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    resource_type: Mapped[str] = mapped_column(String, default="policy", nullable=False)
    resource_arn: Mapped[str] = mapped_column(String, index=True, nullable=False)
    raw_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    crawled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    version_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_policies_raw_resource_arn_scan_id", "resource_arn", "scan_id"),
        Index("ix_policies_raw_crawled_at", "crawled_at"),
    )


class CloudTrailEventRaw(Base):
    """Raw CloudTrail lookup event payload captured during a scan."""

    __tablename__ = "cloudtrail_events_raw"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    event_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    event_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    event_name: Mapped[str] = mapped_column(String, index=True, nullable=False)
    principal_arn: Mapped[str] = mapped_column(String, index=True, nullable=True)
    raw_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    crawled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_cloudtrail_events_raw_scan_event", "scan_id", "event_id"),
        Index("ix_cloudtrail_events_raw_crawled_at", "crawled_at"),
    )


class CrawlRun(Base):
    """Lifecycle metadata for one AWSentinel crawl execution."""

    __tablename__ = "crawl_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(
        String, unique=True, index=True, nullable=False
    )
    aws_account_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(String, index=True, nullable=False)
    users_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    roles_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    groups_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    policies_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    api_errors_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    throttling_events: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    partial_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
