"""
Correlation & attribution — Claude reasoning layer (Phase 4).

Fuses the static, dynamic, and OSINT blocks into a single coherent verdict:
malware family, MITRE ATT&CK mapping, kill chain, attack narrative, and actor
attribution. No tools are invoked — this phase is pure reasoning over already-
gathered evidence.

Optionally cross-references the sample's indicators against an internal IOC
database (case_data["internal_iocs"]) supplied at submission time. Matches are
stamped into attribution["internal_correlation"] with per-match confidence.

CLI:
    python -m backend.app.services.correlation_analyzer --case <path_to_case_json>
"""
from __future__ import annotations

import json
import re

from ..config import settings
from .claude_client import call_claude
from .skill_loader import load_ref, load_skill

_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)

# ── IOC cross-reference helpers ───────────────────────────────────────────────

_IP_RE     = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
_HASH_RE   = re.compile(r'^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$')
_DOMAIN_RE = re.compile(r'^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$')


def _defang(s: str) -> str:
    return (s
            .replace("hxxp://", "http://")
            .replace("hxxps://", "https://")
            .replace("[.]", ".")
            .replace("[://]", "://")
            .replace("[@]", "@"))


def _collect_typed_strings(
    obj: object,
    ips: set[str],
    domains: set[str],
    hashes: set[str],
    urls: set[str],
) -> None:
    """
    Recursively walk any JSON structure and add recognized indicator strings to
    the appropriate typed set. Values are lowercased and defanged before storage.
    """
    if isinstance(obj, str):
        v = _defang(obj.strip()).lower()
        if len(v) < 4:
            return
        if _IP_RE.match(v):
            ips.add(v)
        elif _HASH_RE.match(v):
            hashes.add(v)
        elif v.startswith("http://") or v.startswith("https://"):
            urls.add(v)
        elif _DOMAIN_RE.match(v):
            domains.add(v)
    elif isinstance(obj, dict):
        for val in obj.values():
            _collect_typed_strings(val, ips, domains, hashes, urls)
    elif isinstance(obj, list):
        for item in obj:
            _collect_typed_strings(item, ips, domains, hashes, urls)


def _match_internal_iocs(
    static_analysis: dict,
    dynamic_analysis: dict,
    osint: dict,
    internal_iocs: list[dict],
) -> list[dict]:
    """
    Cross-reference internal_iocs against indicators extracted from phase data.

    Matching strategy (in priority order):
      1. Field-level match — declared type == set the value was found in → "high" confidence
      2. Field-level match — found in a different typed set (type mismatch) → "medium"
      3. Substring fallback — value appears somewhere in the serialized phase JSON → "medium"

    Returns a list of match dicts; empty if no matches or no internal_iocs provided.
    """
    if not internal_iocs:
        return []

    ips: set[str]     = set()
    domains: set[str] = set()
    hashes: set[str]  = set()
    urls: set[str]    = set()

    for block in (static_analysis, dynamic_analysis, osint):
        if block:
            _collect_typed_strings(block, ips, domains, hashes, urls)

    typed_sets: dict[str, set[str]] = {
        "ip": ips, "domain": domains, "hash": hashes, "url": urls,
    }
    all_field_values: set[str] = ips | domains | hashes | urls

    # Corpus for substring fallback: full phase JSON, defanged + lowercased
    corpus = _defang(
        json.dumps([static_analysis, dynamic_analysis, osint], default=str)
    ).lower()

    matches: list[dict] = []
    for ioc in internal_iocs:
        raw_value = (ioc.get("value") or "").strip()
        if not raw_value or len(raw_value) < 4:
            continue

        normalized    = _defang(raw_value).lower()
        declared_type = (ioc.get("type") or "unknown").lower()
        target_set    = typed_sets.get(declared_type, all_field_values)

        # 1 & 2: Field-level match
        field_match_in: str | None = None
        if normalized in target_set:
            # Exact type match
            field_match_in = declared_type
            confidence     = "high"
        else:
            # Check other typed sets
            for t, s in typed_sets.items():
                if t != declared_type and normalized in s:
                    field_match_in = t
                    confidence     = "medium"
                    break

        if field_match_in is not None:
            matches.append({
                "matched_value":  raw_value,
                "declared_type":  declared_type,
                "matched_in":     field_match_in,
                "confidence":     confidence,
                "match_method":   "field",
                "tags":           ioc.get("tags") or {},
            })
        elif normalized in corpus:
            # 3: Substring fallback
            matches.append({
                "matched_value":  raw_value,
                "declared_type":  declared_type,
                "matched_in":     "text",
                "confidence":     "medium",
                "match_method":   "substring",
                "tags":           ioc.get("tags") or {},
            })

    return matches


def _format_matches_for_claude(matches: list[dict]) -> str:
    """Format internal IOC matches as a block to inject into Claude's user message."""
    if not matches:
        return ""
    lines = [
        "## Internal IOC Database Cross-Reference",
        f"Cross-reference of this sample's indicators against the organization's internal "
        f"IOC database found {len(matches)} match(es). Include an 'internal_correlation' "
        "object in your JSON output with an 'ai_interpretation' string field describing "
        "what these matches imply (repeat adversary, campaign linkage, TTPs re-use, etc.). "
        "Weight 'high' confidence matches (exact field match) more strongly than 'medium' "
        "(type mismatch or substring-only — may be coincidental).",
        "",
        "Matches:",
    ]
    for m in matches:
        tags_str = (
            ", ".join(f"{k}={v}" for k, v in m["tags"].items())
            if m.get("tags") else "none"
        )
        lines.append(
            f"  • {m['matched_value']}"
            f"  [type={m['declared_type']}, confidence={m['confidence']},"
            f" method={m['match_method']}, tags: {tags_str}]"
        )
    lines.append("")
    return "\n".join(lines)


# ── prompt assembly ───────────────────────────────────────────────────────────

def _build_system_prompt() -> str:
    skill = load_skill("attribution")
    ref   = load_ref("mitre_reference")
    return f"{skill}\n\n---\n\n## Reference: MITRE ATT&CK\n\n{ref}"


def _phase_summary(
    static_analysis: dict,
    dynamic_analysis: dict,
    osint: dict,
) -> str:
    """One-line status for each input phase — tells Claude which layers are absent."""
    def _status(block: dict, name: str) -> str:
        return f"  - {name}: {'PRESENT' if block else 'ABSENT (phase did not run or failed)'}"

    return "\n".join([
        _status(static_analysis,  "static_analysis"),
        _status(dynamic_analysis, "dynamic_analysis"),
        _status(osint,            "osint"),
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
    sample_meta: dict,
    internal_corr_block: str = "",
) -> str:
    name   = sample_meta.get("name",   "unknown")
    sha256 = sample_meta.get("sha256", "")
    route  = sample_meta.get("route",  "unknown")

    corr_section = f"\n{internal_corr_block}" if internal_corr_block else ""

    return f"""\
## Sample metadata
- Name: {name}
- SHA-256: {sha256 or "(unknown)"}
- Route: {route}

## Phase availability
The following phases fed into this correlation. Where a phase is ABSENT, its \
evidence is unavailable — reflect this in your confidence levels accordingly:
{_phase_summary(static_analysis, dynamic_analysis, osint)}

{_phase_block(static_analysis,  "Static analysis")}

{_phase_block(dynamic_analysis, "Dynamic analysis")}

{_phase_block(osint,            "OSINT")}
{corr_section}
Fuse the evidence above and produce the attribution JSON block as specified in \
your instructions. Return only the JSON object — no prose, no markdown fences."""


# ── JSON parsing (identical approach to all other analyzers) ──────────────────

def _extract_json(response: str) -> dict:
    fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", response)
    candidate   = fence_match.group(1).strip() if fence_match else response.strip()

    obj_match = _JSON_OBJECT_RE.search(candidate)
    if not obj_match:
        return {
            "_parse_error": True,
            "error": "No JSON object found in Claude's response.",
            "_raw_response": response[:2000],
        }

    try:
        return json.loads(obj_match.group())
    except json.JSONDecodeError as exc:
        return {
            "_parse_error": True,
            "error": f"JSON decode failed: {exc}",
            "_raw_response": response[:2000],
        }


# ── public entry point ────────────────────────────────────────────────────────

def analyze_correlation(
    static_analysis: dict,
    dynamic_analysis: dict,
    osint: dict,
    sample_meta: dict,
    *,
    internal_iocs: list[dict] | None = None,
) -> dict:
    """
    Fuse static, dynamic, and OSINT evidence into the attribution block.

    Parameters
    ----------
    static_analysis / dynamic_analysis / osint:
        Phase blocks from the case file (may be {} if that phase failed).
    sample_meta:
        {"name": str, "sha256": str, "route": str}
    internal_iocs:
        Optional list of internal IOC entries parsed from the user-supplied IOC
        database file. When provided, indicators are cross-referenced against the
        phase data and the matches are injected into Claude's context and stored
        in attribution["internal_correlation"].

    Returns
    -------
    dict
        Claude's attribution block, parsed from JSON. On parse failure returns
        {"_parse_error": True, "error": str}.
    """
    # Cross-reference internal IOCs before the Claude call so matches can be
    # included in the prompt and stamped into the result unconditionally.
    matches: list[dict] = _match_internal_iocs(
        static_analysis, dynamic_analysis, osint, internal_iocs or []
    )
    corr_block = _format_matches_for_claude(matches)

    system_prompt = _build_system_prompt()
    user_message  = _build_user_message(
        static_analysis, dynamic_analysis, osint, sample_meta,
        internal_corr_block=corr_block,
    )

    raw_response = call_claude(
        system_prompt=system_prompt,
        user_content=user_message,
        max_tokens=settings.correlation_max_tokens,
    )

    result = _extract_json(raw_response)

    # Always stamp the authoritative match list into the result, whether or not
    # Claude chose to write an internal_correlation field.
    if not result.get("_parse_error") and matches:
        ai_interp = ""
        if isinstance(result.get("internal_correlation"), dict):
            ai_interp = result["internal_correlation"].get("ai_interpretation", "")
        result["internal_correlation"] = {
            "matches":           matches,
            "ai_interpretation": ai_interp,
        }

    return result


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    import sys
    from pathlib import Path

    parser = argparse.ArgumentParser(
        description="Correlation & attribution analyzer — offline test on a saved case file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m backend.app.services.correlation_analyzer \\\n"
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

    sample = case.get("sample") or {}
    # For archive uploads, the extracted primary's sha256 is the analysed file.
    sha256 = (
        (sample.get("extracted_primary_hashes") or {}).get("sha256")
        or sample.get("sha256", "")
    )
    sample_meta = {
        "name":   sample.get("name", case_path.stem),
        "sha256": sha256,
        "route":  case.get("route", "unknown"),
    }

    # Report which phases are available so the user knows what Claude will see.
    for label, block in [
        ("static_analysis",  static_analysis),
        ("dynamic_analysis", dynamic_analysis),
        ("osint",            osint),
    ]:
        status = "present" if block else "ABSENT"
        print(f"  [{status:7s}] {label}", file=sys.stderr)

    print("[*] Calling Claude for correlation & attribution …", file=sys.stderr)

    result = analyze_correlation(static_analysis, dynamic_analysis, osint, sample_meta)

    print(json.dumps(result, indent=2, default=str))
