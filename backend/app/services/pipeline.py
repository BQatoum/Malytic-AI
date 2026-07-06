"""
Pipeline orchestrator runner.

run_pipeline(case_id) is scheduled as a FastAPI BackgroundTask after a sample
is accepted. It opens its own DB session, sequences the analysis phases in order,
writes each phase's output into the case file as it completes, and updates the
pipeline_status / status block throughout.

Adding a future phase = append one _Phase entry to _PHASES and write the
corresponding _run_* async function.

Failure policy: a failing phase is recorded in status.failed and the pipeline
CONTINUES to subsequent phases. Every phase reads prior phases with `or {}`
so missing/failed predecessors never cause a crash. At the end:
  - all phases succeeded  → PipelineStatus.complete, phase="done"
  - any phase failed      → PipelineStatus.failed,   phase="partial"
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Awaitable, Callable

log = logging.getLogger(__name__)

from ..config import settings
from ..database import AsyncSessionLocal
from ..models.case_file import PipelineStatus
from . import case_file as cf_svc
from .correlation_analyzer import analyze_correlation
from .detection_engineer import analyze_detection
from .dynamic_analyzer import analyze_dynamic
from .osint_analyzer import analyze_osint
from .report_generator import generate_report
from .sandbox_client import analyze_and_wait
from .static_analyzer import analyze_static
from .static_extractors import extract_static


# ---------------------------------------------------------------------------
# Phase descriptor
# ---------------------------------------------------------------------------

@dataclass
class _Phase:
    name: str                              # written to status.phase / status.completed
    case_key: str                          # top-level key in case_data to write result into
    run: Callable[[dict], Awaitable[dict]] # async (case_data: dict) -> result dict


# ---------------------------------------------------------------------------
# Target file resolution
# ---------------------------------------------------------------------------

def _resolve_analysis_target(case_data: dict) -> tuple[Path, dict]:
    """
    Return (file_path, meta) for the file that analysis phases should operate on.

    For archive uploads, intake extracts the primary file (e.g. the PE inside the
    ZIP) and records its path and hashes in sample.extracted_primary_stored_name /
    extracted_primary_hashes. Phases must analyze that file, not the outer archive.

    For plain uploads (no extraction), falls back to sample.stored_name.
    """
    sample = case_data["sample"]
    upload_dir = Path(settings.upload_dir)

    extracted = sample.get("extracted_primary_stored_name")
    if extracted:
        file_path = upload_dir / extracted
        h = sample.get("extracted_primary_hashes") or {}
        meta = {
            "name":   Path(extracted).name,
            "sha256": h.get("sha256", ""),
            "size":   file_path.stat().st_size if file_path.exists() else 0,
            "route":  case_data.get("route", "unknown"),
        }
        return file_path, meta

    file_path = upload_dir / sample["stored_name"]
    meta = {
        "name":   sample["name"],
        "sha256": sample["sha256"],
        "size":   sample["size"],
        "route":  case_data.get("route", "unknown"),
    }
    return file_path, meta


# ---------------------------------------------------------------------------
# Phase implementations
# ---------------------------------------------------------------------------

async def _run_dynamic(case_data: dict) -> dict:
    provided = case_data.get("provided_dynamic")
    if provided and isinstance(provided, dict):
        # Analyst uploaded their own dynamic findings — skip sandbox detonation entirely.
        _, meta = _resolve_analysis_target(case_data)
        static_analysis = case_data.get("static_analysis") or {}
        from .dynamic_analyzer import normalize_provided_dynamic
        return await asyncio.to_thread(normalize_provided_dynamic, provided, static_analysis, meta)

    file_path, meta = _resolve_analysis_target(case_data)

    # static_analysis may be None if the static phase failed — pass {} so the
    # dynamic skill receives an empty (but valid) static context rather than None.
    static_analysis = case_data.get("static_analysis") or {}

    sandbox = settings.dynamic_sandbox.lower().strip()

    if sandbox == "triage":
        # TEMPORARY: Playwright browser bridge — replace with Triage REST API
        # once the research account is approved (triage_api_key will be set).
        try:
            from . import triage_playwright  # lazy: keeps startup fast
            evidence = await asyncio.to_thread(
                triage_playwright.submit_and_fetch,
                str(file_path),
                "infected",      # archive password
            )
        except Exception as exc:
            log.error("Triage bridge failed for %s: %s", file_path.name, exc)
            return {
                "_parse_error": True,
                "error": f"Triage bridge failed: {exc}",
            }
        return await asyncio.to_thread(analyze_dynamic, evidence, static_analysis, meta)

    # hybrid_analysis path (original)
    sandbox_report = await asyncio.to_thread(analyze_and_wait, str(file_path))
    return await asyncio.to_thread(analyze_dynamic, sandbox_report, static_analysis, meta)


async def _run_static(case_data: dict) -> dict:
    provided = case_data.get("provided_static")
    if provided and isinstance(provided, dict):
        # Analyst uploaded their own static findings — skip extraction and full Claude analysis.
        _, meta = _resolve_analysis_target(case_data)
        from .static_analyzer import normalize_provided_static
        return await asyncio.to_thread(normalize_provided_static, provided, meta)

    file_path, meta = _resolve_analysis_target(case_data)
    # Both functions do blocking I/O — run them off the event loop.
    extractor_out = await asyncio.to_thread(extract_static, str(file_path), meta.get("route", "pe"))
    return await asyncio.to_thread(analyze_static, extractor_out, meta)


async def _run_osint(case_data: dict) -> dict:
    # Either prior phase may be absent (not yet run) or null (phase failed) —
    # normalize to {} so osint_analyzer never receives None.
    static_analysis  = case_data.get("static_analysis")  or {}
    dynamic_analysis = case_data.get("dynamic_analysis") or {}

    # Use the resolved target so the sha256 is the extracted file's hash for archives.
    _, meta = _resolve_analysis_target(case_data)

    # Blocking: VT HTTP calls (with rate-limit sleeps) + Claude API + web search.
    return await asyncio.to_thread(analyze_osint, static_analysis, dynamic_analysis, meta)


async def _run_correlation(case_data: dict) -> dict:
    static_analysis  = case_data.get("static_analysis")  or {}
    dynamic_analysis = case_data.get("dynamic_analysis") or {}
    osint            = case_data.get("osint")            or {}
    internal_iocs    = case_data.get("internal_iocs")    or []

    _, meta = _resolve_analysis_target(case_data)

    # Blocking Claude call — no web search, so it's fast.
    return await asyncio.to_thread(
        analyze_correlation, static_analysis, dynamic_analysis, osint, meta,
        internal_iocs=internal_iocs,
    )


def _get_verdict(attribution: dict) -> str:
    """
    Extract the verdict from the attribution block.

    Returns "MALICIOUS", "SUSPICIOUS", or "BENIGN".
    Defaults to "MALICIOUS" when unknown — safer to generate rules than to silently skip them.

    Falls back to heuristics for cases attributed before the verdict field was added:
    if the malware family is unknown/benign AND severity is none/low, treat as BENIGN.
    """
    v = (attribution.get("verdict") or "").upper().strip()
    if v in ("MALICIOUS", "SUSPICIOUS", "BENIGN"):
        return v

    # Heuristic fallback for pre-verdict attribution blocks.
    # Require non-empty explicit values — a missing block must not silently become BENIGN.
    family   = (attribution.get("malware_family") or {}).get("name", "")
    severity = (attribution.get("impact_assessment") or {}).get("severity", "")
    if family and family.lower() in ("unknown", "benign", "legitimate", "clean"):
        if severity and severity.lower() in ("none", "low", "minimal"):
            return "BENIGN"

    return "MALICIOUS"


_BENIGN_DETECTION_NOOP: dict = {
    "detection": {
        "iocs": [],
        "yara_rules": [],
        "sigma_rules": [],
        "suricata_rules": [],
        "hunting_queries": [],
        "stix_bundle": None,
        "validation": {
            "yara_ok": None, "sigma_ok": None,
            "suricata_ok": None, "stix_ok": None,
        },
        "notes": (
            "Sample assessed BENIGN by correlation phase — "
            "detection rule generation skipped. "
            "No malicious IOCs to score or rules to deploy."
        ),
    }
}


async def _run_detection(case_data: dict) -> dict:
    attribution      = case_data.get("attribution")      or {}
    verdict          = _get_verdict(attribution)

    if verdict == "BENIGN":
        log.info("detection phase: verdict=BENIGN — skipping rule generation")
        return _BENIGN_DETECTION_NOOP

    static_analysis  = case_data.get("static_analysis")  or {}
    dynamic_analysis = case_data.get("dynamic_analysis") or {}
    osint            = case_data.get("osint")            or {}

    _, meta = _resolve_analysis_target(case_data)

    # Blocking Claude call — uses settings.detection_max_tokens internally.
    return await asyncio.to_thread(
        analyze_detection, static_analysis, dynamic_analysis, osint, attribution, meta
    )


async def _run_elastic_push(case_data: dict) -> dict:
    attribution = case_data.get("attribution") or {}
    verdict     = _get_verdict(attribution)

    if verdict == "BENIGN":
        log.info("elastic push: verdict=BENIGN — skipping IOC index and rule push")
        return {
            "iocs":  {"iocs_indexed": 0, "iocs_total": 0,
                      "skipped": "verdict=BENIGN — no malicious IOCs to index"},
            "sigma": {"rules_created": 0, "rules_skipped": 0, "rules_failed": 0,
                      "rules_total": 0,
                      "skipped": "verdict=BENIGN — no detection rules to push"},
        }

    detection = case_data.get("detection") or {}
    if not detection:
        raise RuntimeError("detection block absent — nothing to push to Elastic")

    _, meta = _resolve_analysis_target(case_data)
    case_id = case_data.get("case_id", "unknown")

    # Lazy import keeps startup fast and skips the module when Elastic is unused.
    from .elastic_push import index_iocs, push_sigma_rules

    ioc_result: dict = {}
    sigma_result: dict = {}
    errors: list[str] = []

    try:
        ioc_result = await asyncio.to_thread(index_iocs, detection, meta, case_id)
        ioc_errs = ioc_result.get("errors") or []
        log.info(
            "elastic IOC index: %d/%d indexed, %d error(s)",
            ioc_result.get("iocs_indexed", 0),
            ioc_result.get("iocs_total", 0),
            len(ioc_errs),
        )
        if ioc_errs:
            errors.append(
                f"{len(ioc_errs)} IOC index error(s): {ioc_errs[0]}"
                + (f" (+{len(ioc_errs) - 1} more)" if len(ioc_errs) > 1 else "")
            )
    except Exception as exc:
        ioc_result = {"error": str(exc)}
        errors.append(f"IOC index raised: {exc}")
        log.error("elastic index_iocs raised: %s", exc)

    try:
        sigma_result = await asyncio.to_thread(push_sigma_rules, detection, meta, case_id)
        failed = sigma_result.get("rules_failed", 0)
        log.info(
            "elastic Sigma push: %d created, %d skipped, %d failed",
            sigma_result.get("rules_created", 0),
            sigma_result.get("rules_skipped", 0),
            failed,
        )
        if failed:
            errors.append(
                f"{failed} of {sigma_result.get('rules_total', '?')} Sigma rule(s) failed"
            )
    except Exception as exc:
        sigma_result = {"error": str(exc)}
        errors.append(f"Sigma push raised: {exc}")
        log.error("elastic push_sigma_rules raised: %s", exc)

    if errors:
        raise RuntimeError("; ".join(errors))

    return {"iocs": ioc_result, "sigma": sigma_result}


async def _run_report(case_data: dict) -> dict:
    static_analysis  = case_data.get("static_analysis")  or {}
    dynamic_analysis = case_data.get("dynamic_analysis") or {}
    osint            = case_data.get("osint")            or {}
    attribution      = case_data.get("attribution")      or {}
    detection        = case_data.get("detection")        or {}

    _, meta = _resolve_analysis_target(case_data)

    # Blocking Claude call — uses settings.report_max_tokens internally.
    result = await asyncio.to_thread(
        generate_report, static_analysis, dynamic_analysis, osint, attribution, detection, meta
    )

    # Render to PDF — Markdown is the primary deliverable; PDF failure must not
    # break the report phase.
    case_id = case_data.get("case_id", "unknown")
    report_block = result.get("report", {})
    md_content = report_block.get("content", "")

    if md_content and not result.get("_parse_error"):
        try:
            from . import report_pdf  # lazy import — avoids WeasyPrint load on startup
            pdf_rel = f"reports/{case_id}.pdf"
            pdf_abs = Path(settings.upload_dir) / pdf_rel
            pdf_meta = {
                "sha256":             meta.get("sha256", ""),
                "overall_confidence": report_block.get("overall_confidence", ""),
            }

            # Collect screenshot frames to embed if the dynamic phase judged them
            # worth showing (screenshot_analysis.include_in_report == true).
            da  = case_data.get("dynamic_analysis") or {}
            sa  = da.get("screenshot_analysis") or {}
            pdf_screenshots: list[dict] = []
            if sa.get("include_in_report"):
                shot_paths    = da.get("_screenshot_paths") or []
                frame_indices = sa.get("report_frames") or list(range(len(shot_paths)))
                caption       = sa.get("caption", "")
                for idx in frame_indices[:3]:
                    path = ""
                    if isinstance(idx, int) and 0 <= idx < len(shot_paths):
                        path = shot_paths[idx]
                    elif isinstance(idx, str):
                        path = next((p for p in shot_paths if idx in p), "")
                    if path:
                        pdf_screenshots.append({"path": path, "caption": caption})
                        caption = ""  # caption only on the first frame

            await asyncio.to_thread(
                report_pdf.render_report_pdf,
                md_content, str(pdf_abs), pdf_meta,
                pdf_screenshots or None,
            )
            result["report"]["file_path"] = pdf_rel
            log.info("PDF rendered → %s", pdf_abs)
        except Exception as exc:
            log.warning("PDF rendering failed (report Markdown still available): %s", exc)
            result["report"]["file_path"] = ""

    return result


# ---------------------------------------------------------------------------
# Phase registry
# ---------------------------------------------------------------------------
# Split at the OSINT boundary so the pause-for-OSINT feature can run only the
# first half, pause cleanly, then resume from the second half.  _PHASES is
# the concatenation and is kept for any external code that references it.

_PHASES_PRE: list[_Phase] = [
    _Phase("static",  "static_analysis",  _run_static),
    _Phase("dynamic", "dynamic_analysis", _run_dynamic),
]

_PHASES_POST: list[_Phase] = [
    _Phase("osint",       "osint",       _run_osint),
    _Phase("correlation", "attribution", _run_correlation),
    _Phase("detection",   "detection",   _run_detection),
    _Phase("report",      "report",      _run_report),
    _Phase("elastic",     "elastic",     _run_elastic_push),
]

_PHASES: list[_Phase] = _PHASES_PRE + _PHASES_POST


# ---------------------------------------------------------------------------
# Status helpers
# ---------------------------------------------------------------------------

async def _set_status_field(
    db, case_id: str, case_data: dict, **fields
) -> dict:
    """Merge **fields into data["status"] and commit; return updated case_data."""
    status_block = dict(case_data.get("status", {}))
    status_block.update(fields)
    row = await cf_svc.update_phase_block(db, case_id, "status", status_block)
    return dict(row.data)


# ---------------------------------------------------------------------------
# Shared phase-runner loop (used by both run_pipeline and resume_pipeline)
# ---------------------------------------------------------------------------

async def _run_phases(db, case_id: str, phases: list[_Phase]) -> dict:
    """Run *phases* in order, committing each result to DB.

    Each phase reloads case_data from DB first so it always sees the full
    committed state of all prior phases.  Failures are recorded in
    status.failed and the loop continues (same policy as the full pipeline).

    Returns the latest case_data dict (reloaded after the last phase).
    """
    case_data: dict = {}
    for phase in phases:
        # Reload so each phase sees all prior phases' committed output.
        row = await cf_svc.get_case(db, case_id)
        case_data = dict(row.data)

        # Announce which phase is running.
        case_data = await _set_status_field(db, case_id, case_data, phase=phase.name)

        try:
            result = await phase.run(case_data)

            # A parse-error structure from analyze_* is a phase failure,
            # not a crash — surface the Claude error honestly.
            if result.get("_parse_error"):
                raise RuntimeError(
                    f"Claude returned unparseable JSON: {result.get('error', 'unknown')}"
                )

            # Skills wrap their output in a top-level key matching the
            # phase (e.g. {"static_analysis": {...}}). Unwrap it so the
            # case file stores one level: case_data["static_analysis"] = {...}.
            if len(result) == 1 and phase.case_key in result:
                result = result[phase.case_key]

            # Commit phase output.
            await cf_svc.update_phase_block(db, case_id, phase.case_key, result)

            # Record completion.
            row = await cf_svc.get_case(db, case_id)
            case_data = dict(row.data)
            completed = list(case_data.get("status", {}).get("completed", []))
            completed.append(phase.name)
            case_data = await _set_status_field(
                db, case_id, case_data, completed=completed
            )

        except Exception as exc:  # noqa: BLE001
            # Reload to capture whatever was already committed.
            row = await cf_svc.get_case(db, case_id)
            case_data = dict(row.data)
            failed = list(case_data.get("status", {}).get("failed", []))
            failed.append({"phase": phase.name, "error": str(exc)})

            # Record the failure but CONTINUE — later phases read prior
            # outputs with `or {}` so they tolerate a missing predecessor.
            case_data = await _set_status_field(
                db, case_id, case_data, failed=failed
            )
            continue

    return case_data


async def _finalize_pipeline(db, case_id: str) -> None:
    """Set the final pipeline_status (complete or failed) from the status block."""
    row = await cf_svc.get_case(db, case_id)
    case_data = dict(row.data)
    if case_data.get("status", {}).get("failed"):
        await _set_status_field(db, case_id, case_data, phase="partial")
        await cf_svc.update_pipeline_status(db, case_id, PipelineStatus.failed)
    else:
        await _set_status_field(db, case_id, case_data, phase="done")
        await cf_svc.update_pipeline_status(db, case_id, PipelineStatus.complete)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def run_pipeline(case_id: str) -> None:
    """
    Execute the analysis pipeline for *case_id* in a background task.

    Opens its own DB session — never reuses the request session, which is
    closed before this function is called.

    When options.pause_for_osint is True the pipeline runs static + dynamic,
    then persists PipelineStatus.paused_osint and returns cleanly.  The
    resume_pipeline() function picks up from OSINT onward when the analyst
    uploads their own OSINT findings.
    """
    async with AsyncSessionLocal() as db:
        # 1. Load case — silently bail if it disappeared (shouldn't happen).
        row = await cf_svc.get_case(db, case_id)
        if row is None:
            return

        case_data = dict(row.data)

        # 2. Mark running.
        await cf_svc.update_pipeline_status(db, case_id, PipelineStatus.running)
        case_data = await _set_status_field(db, case_id, case_data, phase="running")

        # 3. Run static + dynamic.
        case_data = await _run_phases(db, case_id, _PHASES_PRE)

        # 4. Pause gate — only active when explicitly requested; zero-cost on
        #    the default path (options["pause_for_osint"] absent or False).
        if case_data.get("options", {}).get("pause_for_osint"):
            await cf_svc.update_pipeline_status(db, case_id, PipelineStatus.paused_osint)
            await _set_status_field(db, case_id, case_data, phase="awaiting_osint")
            return  # Task ends cleanly; DB is fully committed.

        # 5. Default path: run the remaining phases and set final status.
        await _run_phases(db, case_id, _PHASES_POST)
        await _finalize_pipeline(db, case_id)


async def resume_pipeline(case_id: str) -> None:
    """
    Resume the pipeline from the OSINT phase onward after analyst uploads OSINT.

    Called as a background task by POST /cases/{id}/resume-with-osint.
    Opens its own DB session (same pattern as run_pipeline) so it works
    correctly after a server restart.
    """
    async with AsyncSessionLocal() as db:
        row = await cf_svc.get_case(db, case_id)
        if row is None or row.pipeline_status != PipelineStatus.paused_osint:
            return  # Safety guard — idempotent if called twice or in wrong state.

        case_data = dict(row.data)

        await cf_svc.update_pipeline_status(db, case_id, PipelineStatus.running)
        case_data = await _set_status_field(db, case_id, case_data, phase="running")

        # _PHASES_POST starts with osint — but when analyst provided their OSINT
        # the osint block is already in case_data["osint"]; _run_osint would
        # overwrite it.  Skip the platform osint phase and go straight to
        # correlation.  The analyst's OSINT (tagged source="analyst-provided")
        # is already committed to the DB by the resume endpoint.
        await _run_phases(db, case_id, _PHASES_POST[1:])  # correlation → elastic
        await _finalize_pipeline(db, case_id)
