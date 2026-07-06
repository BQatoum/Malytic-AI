import enum
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Enum, String
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


class PipelineStatus(str, enum.Enum):
    pending      = "pending"
    running      = "running"
    complete     = "complete"
    failed       = "failed"
    paused_osint = "paused_osint"


def _now() -> datetime:
    return datetime.now(timezone.utc)


class CaseFile(Base):
    __tablename__ = "case_files"

    case_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    pipeline_status: Mapped[PipelineStatus] = mapped_column(
        Enum(PipelineStatus), default=PipelineStatus.pending, index=True
    )
    # Full case file JSON: matches the orchestrator's schema exactly.
    # Top-level keys: case_id, sample, route, options, status,
    # static_analysis, dynamic_analysis, osint, attribution, detection, report, elastic.
    data: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )
