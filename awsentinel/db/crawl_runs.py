from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Optional

from sqlalchemy.orm import sessionmaker

from awsentinel.db.models import CrawlRun


class CrawlRunStatus(StrEnum):
    """Allowed crawl run lifecycle states."""

    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    FAILED = "FAILED"


@dataclass(frozen=True)
class CrawlRunCounts:
    users_count: int = 0
    roles_count: int = 0
    groups_count: int = 0
    policies_count: int = 0
    api_errors_count: int = 0
    throttling_events: int = 0
    partial_failures: int = 0


class CrawlRunRepository:
    """Persists crawl lifecycle metadata."""

    def __init__(self, session_factory: sessionmaker):
        self._session_factory = session_factory

    def start(self, scan_id: str, aws_account_id: str) -> CrawlRun:
        now = datetime.now(timezone.utc)
        run = CrawlRun(
            scan_id=scan_id,
            aws_account_id=aws_account_id,
            started_at=now,
            status=CrawlRunStatus.RUNNING.value,
        )
        with self._session_factory() as session:
            session.add(run)
            session.commit()
            session.refresh(run)
            return run

    def complete(
        self,
        scan_id: str,
        status: CrawlRunStatus,
        counts: CrawlRunCounts,
        completed_at: Optional[datetime] = None,
    ) -> None:
        completed = completed_at or datetime.now(timezone.utc)
        with self._session_factory() as session:
            run = session.query(CrawlRun).filter_by(scan_id=scan_id).one()
            started_at = _ensure_aware(run.started_at)
            run.completed_at = completed
            run.duration_seconds = round((completed - started_at).total_seconds(), 2)
            run.status = status.value
            run.users_count = counts.users_count
            run.roles_count = counts.roles_count
            run.groups_count = counts.groups_count
            run.policies_count = counts.policies_count
            run.api_errors_count = counts.api_errors_count
            run.throttling_events = counts.throttling_events
            run.partial_failures = counts.partial_failures
            session.commit()


def _ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value
