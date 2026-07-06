from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm.attributes import flag_modified

from sqlalchemy.ext.asyncio import AsyncSession

from ..models.case_file import CaseFile, PipelineStatus
from .sample_intake import SampleInfo


def _build_initial_data(
    case_id: str,
    info: SampleInfo,
    report_format: str,
    internal_iocs: list[Any] | None = None,
    provided_static: dict[str, Any] | None = None,
    provided_dynamic: dict[str, Any] | None = None,
    pause_for_osint: bool = False,
) -> dict[str, Any]:
    """
    Build the initial case file JSON.
    Matches the orchestrator skill's schema exactly; all phase blocks start null.
    """
    return {
        "case_id": case_id,
        "sample": {
            "name": info.original_name,
            "stored_name": info.stored_name,
            "size": info.size,
            "type": info.mime_type,
            "magic_description": info.magic_description,
            "md5": info.md5,
            "sha1": info.sha1,
            "sha256": info.sha256,
            "extracted_primary_stored_name": info.extracted_primary_stored_name,
            "extracted_primary_hashes": info.extracted_primary_hashes,
        },
        "route": info.route,
        "options": {"report_format": report_format, "pause_for_osint": pause_for_osint},
        "internal_iocs": internal_iocs or [],
        "provided_static": provided_static or None,
        "provided_dynamic": provided_dynamic or None,
        "status": {
            "phase": "intake",
            "completed": [],
            "skipped": [],
            "failed": [],
            "early_findings": info.early_findings,
            "archive_contents": info.archive_contents,
            "archive_primary": info.archive_primary,
        },
        "static_analysis": None,
        "dynamic_analysis": None,
        "osint": None,
        "attribution": None,
        "detection": None,
        "report": None,
        "elastic": None,
    }


async def create_case(
    db: AsyncSession,
    case_id: str,
    info: SampleInfo,
    report_format: str,
    internal_iocs: list[Any] | None = None,
    provided_static: dict[str, Any] | None = None,
    provided_dynamic: dict[str, Any] | None = None,
    pause_for_osint: bool = False,
) -> CaseFile:
    data = _build_initial_data(
        case_id, info, report_format,
        internal_iocs=internal_iocs,
        provided_static=provided_static,
        provided_dynamic=provided_dynamic,
        pause_for_osint=pause_for_osint,
    )
    row = CaseFile(
        case_id=case_id,
        pipeline_status=PipelineStatus.pending,
        data=data,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


async def get_case(db: AsyncSession, case_id: str) -> CaseFile | None:
    result = await db.execute(select(CaseFile).where(CaseFile.case_id == case_id))
    return result.scalar_one_or_none()


async def update_phase_block(
    db: AsyncSession,
    case_id: str,
    phase_key: str,
    block_data: dict[str, Any],
) -> CaseFile:
    """
    Write one phase's output block into the case file without touching any other block.
    phase_key must be one of: static_analysis, dynamic_analysis, osint,
    attribution, detection, report, elastic.
    """
    row = await get_case(db, case_id)
    if row is None:
        raise ValueError(f"Case {case_id!r} not found")
    # Assign a new dict so SQLAlchemy detects the change; flag_modified for safety.
    updated = dict(row.data)
    updated[phase_key] = block_data
    row.data = updated
    row.updated_at = datetime.now(timezone.utc)
    flag_modified(row, "data")
    await db.commit()
    await db.refresh(row)
    return row


async def update_pipeline_status(
    db: AsyncSession,
    case_id: str,
    status: PipelineStatus,
) -> None:
    row = await get_case(db, case_id)
    if row is None:
        raise ValueError(f"Case {case_id!r} not found")
    row.pipeline_status = status
    row.updated_at = datetime.now(timezone.utc)
    await db.commit()


async def list_cases(db: AsyncSession) -> list[CaseFile]:
    result = await db.execute(
        select(CaseFile).order_by(CaseFile.created_at.desc())
    )
    return list(result.scalars().all())
