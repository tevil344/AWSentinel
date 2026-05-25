from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from awsentinel.db.models import Base


class SuppressedFindingRaw(Base):
    __tablename__ = "suppressed_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    suppression_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    finding_hash: Mapped[str] = mapped_column(String, index=True, nullable=False)
    reason: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[str] = mapped_column(String, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class GraphSnapshotRaw(Base):
    __tablename__ = "graph_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    graph_hash: Mapped[str] = mapped_column(String, index=True, nullable=False)
    graph_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    findings_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    attack_chains_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
