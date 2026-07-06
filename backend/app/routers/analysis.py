import asyncio
import json as _json
import logging
import uuid
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..database import get_db
from ..schemas.case_file import AnalyzeResponse, CaseFileDetail, CaseListItem
from ..services import case_file as cf_svc
from ..services.pipeline import run_pipeline, resume_pipeline
from ..services.sample_intake import process_sample

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["analysis"])

_VALID_FORMATS     = {"markdown", "docx", "pdf"}
_VALID_IOC_EXTS    = {".csv", ".json"}
_VALID_STATIC_EXT  = ".json"
_VALID_DYNAMIC_EXT = ".json"


@router.post("/analyze", response_model=AnalyzeResponse, status_code=202)
async def submit_sample(
    file: UploadFile,
    background_tasks: BackgroundTasks,
    password: str | None = Form(default=None),
    report_format: str = Form(default="markdown"),
    ioc_file: UploadFile | None = File(default=None),
    static_findings_file: UploadFile | None = File(default=None),
    dynamic_findings_file: UploadFile | None = File(default=None),
    pause_for_osint: bool = Form(default=False),
    db: AsyncSession = Depends(get_db),
) -> AnalyzeResponse:
    if report_format not in _VALID_FORMATS:
        raise HTTPException(
            status_code=422,
            detail=f"report_format must be one of {sorted(_VALID_FORMATS)}",
        )

    # Read one byte past the limit so we can detect an oversized upload before
    # touching disk.
    raw = await file.read(settings.max_upload_bytes + 1)
    if len(raw) > settings.max_upload_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds the {settings.max_upload_bytes:,}-byte upload limit",
        )
    if not raw:
        raise HTTPException(status_code=422, detail="Uploaded file is empty")

    # ── Optional internal IOC database ────────────────────────────────────────
    internal_iocs: list[dict] = []
    if ioc_file and ioc_file.filename:
        ext = Path(ioc_file.filename).suffix.lower()
        if ext not in _VALID_IOC_EXTS:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"IOC file must be .csv or .json — received {ext!r}. "
                    "See the API docs for the expected file format."
                ),
            )
        ioc_raw = await ioc_file.read(settings.max_upload_bytes + 1)
        if len(ioc_raw) > settings.max_upload_bytes:
            raise HTTPException(
                status_code=413,
                detail="IOC file exceeds the upload size limit",
            )
        if ioc_raw:
            from ..services.ioc_parser import parse_ioc_file  # lazy import
            internal_iocs = parse_ioc_file(ioc_raw, ioc_file.filename)
            log.info(
                "IOC file %r parsed: %d indicator(s)", ioc_file.filename, len(internal_iocs)
            )

    # ── Optional analyst-provided static findings ─────────────────────────────
    provided_static: dict | None = None
    if static_findings_file and static_findings_file.filename:
        ext = Path(static_findings_file.filename).suffix.lower()
        if ext != _VALID_STATIC_EXT:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Static findings file must be .json — received {ext!r}. "
                    "Upload a JSON object matching the static_analysis schema."
                ),
            )
        sf_raw = await static_findings_file.read(settings.max_upload_bytes + 1)
        if len(sf_raw) > settings.max_upload_bytes:
            raise HTTPException(
                status_code=413,
                detail="Static findings file exceeds the upload size limit",
            )
        if sf_raw:
            import json as _json
            try:
                parsed = _json.loads(sf_raw.decode("utf-8"))
            except (_json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise HTTPException(
                    status_code=400,
                    detail=f"Static findings file is not valid JSON: {exc}",
                )
            if not isinstance(parsed, dict):
                raise HTTPException(
                    status_code=400,
                    detail="Static findings must be a JSON object (not an array or scalar)",
                )
            # Unwrap if analyst wrapped findings in a "static_analysis" key
            if "static_analysis" in parsed and isinstance(parsed["static_analysis"], dict):
                parsed = parsed["static_analysis"]
            provided_static = parsed
            log.info("Static findings file %r accepted", static_findings_file.filename)

    # ── Optional analyst-provided dynamic findings ────────────────────────────
    provided_dynamic: dict | None = None
    if dynamic_findings_file and dynamic_findings_file.filename:
        ext = Path(dynamic_findings_file.filename).suffix.lower()
        if ext != _VALID_DYNAMIC_EXT:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Dynamic findings file must be .json — received {ext!r}. "
                    "Upload a JSON object matching the dynamic_analysis schema."
                ),
            )
        df_raw = await dynamic_findings_file.read(settings.max_upload_bytes + 1)
        if len(df_raw) > settings.max_upload_bytes:
            raise HTTPException(
                status_code=413,
                detail="Dynamic findings file exceeds the upload size limit",
            )
        if df_raw:
            import json as _json
            try:
                parsed = _json.loads(df_raw.decode("utf-8"))
            except (_json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise HTTPException(
                    status_code=400,
                    detail=f"Dynamic findings file is not valid JSON: {exc}",
                )
            if not isinstance(parsed, dict):
                raise HTTPException(
                    status_code=400,
                    detail="Dynamic findings must be a JSON object (not an array or scalar)",
                )
            # Unwrap if analyst wrapped findings in a "dynamic_analysis" key
            if "dynamic_analysis" in parsed and isinstance(parsed["dynamic_analysis"], dict):
                parsed = parsed["dynamic_analysis"]
            provided_dynamic = parsed
            log.info("Dynamic findings file %r accepted", dynamic_findings_file.filename)

    case_id = str(uuid.uuid4())
    original_name = file.filename or "unnamed"

    try:
        info = await asyncio.to_thread(
            process_sample, raw, original_name, password, case_id
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    row = await cf_svc.create_case(
        db, case_id, info, report_format,
        internal_iocs=internal_iocs,
        provided_static=provided_static,
        provided_dynamic=provided_dynamic,
        pause_for_osint=pause_for_osint,
    )
    background_tasks.add_task(run_pipeline, case_id)
    return AnalyzeResponse(
        case_id=row.case_id,
        message="Sample accepted; analysis pending",
    )


# /cases must be registered before /cases/{case_id} so the static segment wins.
@router.get("/cases", response_model=list[CaseListItem])
async def list_cases(db: AsyncSession = Depends(get_db)) -> list[CaseListItem]:
    rows = await cf_svc.list_cases(db)
    return [
        CaseListItem(
            case_id=r.case_id,
            sample_name=r.data.get("sample", {}).get("name", ""),
            route=r.data.get("route", ""),
            pipeline_status=r.pipeline_status,
            created_at=r.created_at,
        )
        for r in rows
    ]


@router.get("/cases/{case_id}", response_model=CaseFileDetail)
async def get_case(
    case_id: str,
    db: AsyncSession = Depends(get_db),
) -> CaseFileDetail:
    row = await cf_svc.get_case(db, case_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    return CaseFileDetail(
        case_id=row.case_id,
        pipeline_status=row.pipeline_status,
        created_at=row.created_at,
        updated_at=row.updated_at,
        data=row.data,
    )


@router.get("/cases/{case_id}/report.pdf")
async def get_report_pdf(
    case_id: str,
    db: AsyncSession = Depends(get_db),
) -> FileResponse:
    row = await cf_svc.get_case(db, case_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    file_path_rel: str = (row.data.get("report") or {}).get("file_path", "")
    if not file_path_rel:
        raise HTTPException(status_code=404, detail="PDF report not yet generated")

    pdf_path = Path(settings.upload_dir) / file_path_rel
    if not pdf_path.exists():
        raise HTTPException(status_code=404, detail=f"PDF not found on disk: {pdf_path}")

    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=f"report-{case_id}.pdf",
    )


@router.get("/cases/{case_id}/screenshots/{idx}")
async def get_screenshot(
    case_id: str,
    idx: int,
    db: AsyncSession = Depends(get_db),
) -> FileResponse:
    row = await cf_svc.get_case(db, case_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    shot_paths: list = (
        (row.data.get("dynamic_analysis") or {}).get("_screenshot_paths") or []
    )
    if not shot_paths:
        raise HTTPException(status_code=404, detail="No screenshots for this case")
    if idx < 0 or idx >= len(shot_paths):
        raise HTTPException(
            status_code=404,
            detail=f"Screenshot index {idx} out of range (0–{len(shot_paths) - 1})",
        )

    img_path = Path(shot_paths[idx])
    if not img_path.exists():
        raise HTTPException(status_code=404, detail="Screenshot file not found on disk")

    return FileResponse(
        path=str(img_path),
        media_type="image/png",
        filename=f"screenshot-{case_id}-{idx}.png",
    )


@router.get("/cases/{case_id}/intermediate-findings")
async def get_intermediate_findings(
    case_id: str,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """Return static + dynamic blocks as a downloadable JSON file.

    Available in any pipeline state (not locked to paused_osint) so analysts
    can always retrieve the platform's findings.  Each block is tagged with
    its source ("platform" or "analyst-provided") so the analyst knows which
    findings came from where.
    """
    row = await cf_svc.get_case(db, case_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    data = row.data
    static_block  = data.get("static_analysis")
    dynamic_block = data.get("dynamic_analysis")

    if static_block is None and dynamic_block is None:
        raise HTTPException(
            status_code=404,
            detail="Static and dynamic analysis have not run yet for this case",
        )

    def _tag_source(block: dict | None, default: str) -> dict | None:
        if block is None:
            return None
        tagged = dict(block)
        tagged.setdefault("source", default)
        return tagged

    sample = data.get("sample", {})
    payload = {
        "case_id":          case_id,
        "pipeline_status":  row.pipeline_status,
        "sample": {
            "name":   sample.get("name", ""),
            "sha256": sample.get("sha256", ""),
        },
        "pause_for_osint":  (data.get("options") or {}).get("pause_for_osint", False),
        "static_analysis":  _tag_source(static_block,  "platform"),
        "dynamic_analysis": _tag_source(dynamic_block, "platform"),
    }

    return JSONResponse(
        content=payload,
        headers={
            "Content-Disposition": f'attachment; filename="findings-{case_id}.json"',
        },
    )


_VALID_OSINT_EXT = ".json"


@router.post("/cases/{case_id}/resume-with-osint", status_code=202)
async def resume_with_osint(
    case_id: str,
    background_tasks: BackgroundTasks,
    osint_file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Accept analyst OSINT findings and resume the pipeline from correlation.

    The case must be in paused_osint state.  The OSINT JSON is written to the
    case file, tagged source="analyst-provided", then resume_pipeline() is
    scheduled as a background task — same pattern as run_pipeline().
    """
    row = await cf_svc.get_case(db, case_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    from ..models.case_file import PipelineStatus as PS
    if row.pipeline_status != PS.paused_osint:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Case is not awaiting OSINT — current status is "
                f"'{row.pipeline_status}'. Only paused_osint cases can be resumed."
            ),
        )

    # Validate the uploaded file.
    ext = Path(osint_file.filename or "").suffix.lower()
    if ext != _VALID_OSINT_EXT:
        raise HTTPException(
            status_code=400,
            detail=f"OSINT file must be .json — received {ext!r}.",
        )

    raw = await osint_file.read(settings.max_upload_bytes + 1)
    if len(raw) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="OSINT file exceeds the upload size limit")

    try:
        parsed = _json.loads(raw.decode("utf-8"))
    except (_json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail=f"OSINT file is not valid JSON: {exc}")

    if not isinstance(parsed, dict):
        raise HTTPException(
            status_code=400,
            detail="OSINT findings must be a JSON object (not an array or scalar)",
        )

    # Unwrap {"osint": {...}} wrapper if present.
    if "osint" in parsed and isinstance(parsed["osint"], dict):
        parsed = parsed["osint"]

    # Tag provenance.
    parsed["source"] = "analyst-provided"

    # Commit OSINT to DB BEFORE starting the background task so resume_pipeline
    # always finds it there, even if the task starts immediately.
    await cf_svc.update_phase_block(db, case_id, "osint", parsed)

    background_tasks.add_task(resume_pipeline, case_id)
    log.info("OSINT uploaded for case %s — resuming pipeline", case_id)

    return {
        "case_id": case_id,
        "message": "OSINT accepted; pipeline resuming from correlation",
    }


@router.get("/cases/{case_id}/ioc-export")
async def export_ioc_database(
    case_id: str,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """Return a merged IOC database JSON combining the analyst's uploaded internal IOC
    database with this sample's newly discovered indicators from detection.iocs.

    The file is ready to re-upload as the internal IOC database on the next analysis.
    Format: JSON array of {value, type, ...tags} objects — same schema as ioc_parser.py.

    Behaviour:
    - Uploaded internal_iocs come first (analyst data takes precedence).
    - New IOCs from detection.iocs are appended, skipping any whose value already
      appears in the uploaded set (case-insensitive dedup).
    - If the detection phase has not run yet, returns 404.
    - Works on complete, failed, and partial cases as long as detection.iocs exists.
    """
    from datetime import date as _date

    row = await cf_svc.get_case(db, case_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    data = row.data
    detection = data.get("detection") or {}
    raw_iocs: list = detection.get("iocs") or []

    if not raw_iocs and not data.get("internal_iocs"):
        raise HTTPException(
            status_code=404,
            detail="No IOCs available — detection phase has not run yet for this case",
        )

    # Pull family name and verdict from attribution for tagging new entries
    attr_block = (data.get("attribution") or {}).get("attribution") or {}
    family_obj  = attr_block.get("malware_family") or {}
    family_name = (
        family_obj.get("name", "") if isinstance(family_obj, dict) else str(family_obj)
    ).strip()
    verdict = str(attr_block.get("verdict", "")).strip()
    today   = _date.today().isoformat()

    # Build set of already-known values from the analyst's uploaded database
    uploaded: list[dict] = list(data.get("internal_iocs") or [])
    known_values: set[str] = {
        str(e.get("value", "")).strip().lower() for e in uploaded
    }

    # Convert detection.iocs → internal DB format; skip duplicates
    new_entries: list[dict] = []
    for ioc in raw_iocs:
        raw_val = str(ioc.get("value_original") or ioc.get("value") or "").strip()
        if not raw_val or raw_val.lower() in known_values:
            continue
        entry: dict = {
            "value":        raw_val,
            "type":         ioc.get("type", "unknown"),
            "source":       "malytic-pipeline",
            "date_added":   today,
            "case_id":      case_id,
            "source_phase": ioc.get("source_phase", ""),
            "confidence":   ioc.get("confidence", ""),
            "volatility":   ioc.get("volatility", ""),
        }
        if family_name:
            entry["family"] = family_name
        if verdict:
            entry["verdict"] = verdict
        new_entries.append(entry)
        known_values.add(raw_val.lower())

    merged = uploaded + new_entries
    log.info(
        "ioc-export case=%s  uploaded=%d  new=%d  total=%d",
        case_id, len(uploaded), len(new_entries), len(merged),
    )

    return JSONResponse(
        content=merged,
        headers={
            "Content-Disposition": f'attachment; filename="ioc-database-{case_id}.json"',
        },
    )
