from datetime import datetime
from awsentinel.db.intelligence_models import SuppressedFindingRaw
from awsentinel.intelligence.models import SuppressionRecord


class SuppressionRepository:
    def __init__(self, session_factory):
        self._session_factory = session_factory

    def add(self, record: SuppressionRecord) -> None:
        with self._session_factory() as session:
            session.add(
                SuppressedFindingRaw(
                    suppression_id=record.suppression_id,
                    finding_hash=record.finding_hash,
                    reason=record.reason,
                    created_by=record.created_by,
                    expires_at=record.expires_at,
                    created_at=record.created_at,
                )
            )
            session.commit()

    def active(self, now: datetime) -> tuple[SuppressionRecord, ...]:
        with self._session_factory() as session:
            rows = session.query(SuppressedFindingRaw).all()
        records = tuple(_to_record(row) for row in rows)
        return tuple(record for record in records if not record.is_expired(now))


def _to_record(row: SuppressedFindingRaw) -> SuppressionRecord:
    return SuppressionRecord(
        suppression_id=row.suppression_id,
        finding_hash=row.finding_hash,
        reason=row.reason,
        created_by=row.created_by,
        expires_at=row.expires_at,
        created_at=row.created_at,
    )
