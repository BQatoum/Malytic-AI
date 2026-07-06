"""
Detection engineering — Claude detection layer (Phase 5).

Turns all prior analysis into deployable detection content: defanged/scored IOCs,
YARA rules (file), Sigma rules (log/behavior), Suricata rules (network/C2),
hunting queries, and an Elastic-ready bundle (+ optional STIX export).

No external tools or web search — this phase reasons purely over the prior
phase outputs already in the case file.

NOT wired into the pipeline yet — call analyze_detection() directly to test.

CLI:
    python -m backend.app.services.detection_engineer --case <path_to_case_json>
"""
from __future__ import annotations

import json
import re

from ..config import settings
from .claude_client import call_claude
from .skill_loader import load_ref, load_skill

_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)


# ── rule validation ───────────────────────────────────────────────────────────

def _apply_validation(result: dict) -> dict:
    """
    Run each YARA / Sigma / Suricata rule through the appropriate validator and
    write per-rule results into result["detection"]["validation"].

    Operates on the unwrapped inner dict if Claude wrapped output as
    {"detection": {...}}, otherwise on result directly.

    One rule's validator crash never aborts the others.
    """
    from .rule_validator import (  # noqa: PLC0415
        repair_yara_rule, repair_sigma_rule,
        validate_yara, validate_sigma, validate_suricata,
    )

    detection = result.get("detection") if isinstance(result.get("detection"), dict) else result

    def _run(rules: list[dict], validator_fn, repair_fn=None) -> list[dict]:
        out = []
        for r in rules or []:
            name      = r.get("name", "")
            rule_text = r.get("rule", "")
            repaired  = False
            if repair_fn and rule_text:
                fixed = repair_fn(rule_text)
                if fixed != rule_text:
                    r["rule"]  = fixed
                    rule_text  = fixed
                    repaired   = True
            try:
                v = validator_fn(rule_text)
            except Exception as exc:  # noqa: BLE001
                v = {"valid": False, "error": f"Validator error: {exc}"}
            entry = {"name": name, **v}
            if repaired:
                entry["repaired"] = True
            out.append(entry)
        return out

    yara_results     = _run(detection.get("yara_rules"),     validate_yara,     repair_yara_rule)
    sigma_results    = _run(detection.get("sigma_rules"),    validate_sigma,    repair_sigma_rule)
    suricata_results = _run(detection.get("suricata_rules"), validate_suricata)

    def _agg(results: list[dict]):
        return None if not results else all(r["valid"] for r in results)

    validation = dict(detection.get("validation") or {})
    validation.update({
        "yara_ok":       _agg(yara_results),
        "yara_rules":    yara_results,
        "sigma_ok":      _agg(sigma_results),
        "sigma_rules":   sigma_results,
        "suricata_ok":   _agg(suricata_results),
        "suricata_rules": suricata_results,
        # stix_ok: no STIX validator — preserve whatever Claude set
    })
    detection["validation"] = validation

    if "detection" in result:
        result["detection"] = detection
    return result


# ── prompt assembly ───────────────────────────────────────────────────────────

def _build_system_prompt() -> str:
    skill = load_skill("detection")
    ref   = load_ref("detection_reference")
    return f"{skill}\n\n---\n\n## Reference: Detection Templates and Scoring\n\n{ref}"


def _phase_summary(
    static_analysis: dict,
    dynamic_analysis: dict,
    osint: dict,
    attribution: dict,
) -> str:
    def _status(block: dict, name: str) -> str:
        return f"  - {name}: {'PRESENT' if block else 'ABSENT (phase did not run or failed)'}"

    return "\n".join([
        _status(static_analysis,  "static_analysis"),
        _status(dynamic_analysis, "dynamic_analysis"),
        _status(osint,            "osint"),
        _status(attribution,      "attribution"),
    ])


def _pp(obj: object) -> str:
    return json.dumps(obj, indent=2, default=str)


def _phase_block(block: dict, label: str) -> str:
    if block:
        return f"## {label}\n{_pp(block)}"
    return f"## {label}\n(not available — phase did not run or failed)"


def _build_user_message(
    static_analysis: dict,
    dynamic_analysis: dict,
    osint: dict,
    attribution: dict,
    sample_meta: dict,
) -> str:
    name   = sample_meta.get("name",   "unknown")
    sha256 = sample_meta.get("sha256", "")
    route  = sample_meta.get("route",  "unknown")

    return f"""\
## Sample metadata
- Name: {name}
- SHA-256: {sha256 or "(unknown)"}
- Route: {route}

## Phase availability
The following phases fed into this detection run. Where a phase is ABSENT, its \
evidence is unavailable — produce rules only from what is present, note gaps in \
the `notes` field:
{_phase_summary(static_analysis, dynamic_analysis, osint, attribution)}

{_phase_block(static_analysis,  "Static analysis")}

{_phase_block(dynamic_analysis, "Dynamic analysis")}

{_phase_block(osint,            "OSINT")}

{_phase_block(attribution,      "Attribution")}

Produce the detection JSON block as specified in your instructions. \
Return only the JSON object — no prose, no markdown fences."""


# ── JSON parsing ──────────────────────────────────────────────────────────────

def _is_truncated(response: str) -> bool:
    """Return True if the response looks cut off (does not end with a closing brace)."""
    stripped = response.rstrip()
    return bool(stripped) and stripped[-1] != "}"


def _extract_json(response: str) -> dict:
    fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", response)
    candidate   = fence_match.group(1).strip() if fence_match else response.strip()

    truncated_hint = (
        " Response appears truncated — likely hit max_tokens;"
        " increase DETECTION_MAX_TOKENS in .env."
        if _is_truncated(response) else ""
    )

    obj_match = _JSON_OBJECT_RE.search(candidate)
    if not obj_match:
        return {
            "_parse_error": True,
            "error": f"No JSON object found in Claude's response.{truncated_hint}",
            "_raw_response": response[:2000],
        }

    try:
        return json.loads(obj_match.group())
    except json.JSONDecodeError as exc:
        return {
            "_parse_error": True,
            "error": f"JSON decode failed: {exc}.{truncated_hint}",
            "_raw_response": response[:2000],
        }


# ── public entry point ────────────────────────────────────────────────────────

def analyze_detection(
    static_analysis: dict,
    dynamic_analysis: dict,
    osint: dict,
    attribution: dict,
    sample_meta: dict,
) -> dict:
    """
    Turn all prior analysis into deployable detection content.

    Parameters
    ----------
    static_analysis:
        The static_analysis block from the case file (may be {} if phase failed).
    dynamic_analysis:
        The dynamic_analysis block from the case file (may be {} if phase failed).
    osint:
        The osint block from the case file (may be {} if phase failed).
    attribution:
        The attribution block from the case file (may be {} if phase failed or
        correlation phase has not run yet).
    sample_meta:
        {"name": str, "sha256": str, "route": str}

    Returns
    -------
    dict
        Claude's detection block, parsed from JSON. On parse failure returns
        {"_parse_error": True, "error": str}.
    """
    system_prompt = _build_system_prompt()
    user_message  = _build_user_message(
        static_analysis, dynamic_analysis, osint, attribution, sample_meta
    )

    raw_response = call_claude(
        system_prompt=system_prompt,
        user_content=user_message,
        max_tokens=settings.detection_max_tokens,
    )

    result = _extract_json(raw_response)
    if not result.get("_parse_error"):
        result = _apply_validation(result)
    return result


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    import sys
    from pathlib import Path

    parser = argparse.ArgumentParser(
        description="Detection engineering — offline test on a saved case file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m backend.app.services.detection_engineer \\\n"
            "      --case test_fixtures/agenttesla_case.json\n"
        ),
    )
    parser.add_argument(
        "--case", metavar="PATH", required=True,
        help="Path to a saved case JSON file (output of dump_case.py).",
    )
    args = parser.parse_args()

    case_path = Path(args.case)
    if not case_path.exists():
        print(f"[!] File not found: {case_path}", file=sys.stderr)
        sys.exit(1)

    try:
        case = json.loads(case_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"[!] Invalid JSON in {case_path}: {exc}", file=sys.stderr)
        sys.exit(1)

    static_analysis  = case.get("static_analysis")  or {}
    dynamic_analysis = case.get("dynamic_analysis") or {}
    osint            = case.get("osint")            or {}
    attribution      = case.get("attribution")      or {}

    sample = case.get("sample") or {}
    sha256 = (
        (sample.get("extracted_primary_hashes") or {}).get("sha256")
        or sample.get("sha256", "")
    )
    sample_meta = {
        "name":   sample.get("name", case_path.stem),
        "sha256": sha256,
        "route":  case.get("route", "unknown"),
    }

    for label, block in [
        ("static_analysis",  static_analysis),
        ("dynamic_analysis", dynamic_analysis),
        ("osint",            osint),
        ("attribution",      attribution),
    ]:
        status = "present" if block else "ABSENT"
        print(f"  [{status:7s}] {label}", file=sys.stderr)

    print("[*] Calling Claude for detection engineering …", file=sys.stderr)

    result = analyze_detection(
        static_analysis, dynamic_analysis, osint, attribution, sample_meta
    )

    print(json.dumps(result, indent=2, default=str))
