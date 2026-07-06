"""
Static analysis — Claude interpretation layer (Phase 2).

Receives raw extractor output (from static_extractors.extract_static) and
sample metadata, sends them to Claude under the static-analysis skill, and
returns Claude's parsed static_analysis dict.

NOT wired into the pipeline yet — call analyze_static() directly to test.

CLI:
    python -m backend.app.services.static_analyzer <file>
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..config import settings
from .claude_client import call_claude
from .skill_loader import load_ref, load_skill
from .static_extractors import extract_static

# Maximum strings to include in the user message per type.
# Claude doesn't need all 500; a representative head is enough for pattern recognition.
_STRINGS_IN_PROMPT = 50

# Static analysis on rich PE samples (many imports, FLOSS strings, capa rules) can exceed
# 8192 tokens. Configured via settings.static_max_tokens (STATIC_MAX_TOKENS in .env).

# Matches a JSON object (outermost { ... }) across newlines.
_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)


def _build_system_prompt() -> str:
    """
    Combine the static-analysis skill with its API-categories reference.

    The skill instructs Claude to read ref-static-api_categories.md before
    categorizing IAT imports. We satisfy that by embedding the reference
    directly in the system prompt so it's available in the same context window.
    """
    skill = load_skill("static_analysis")
    ref = load_ref("static_api_categories")
    return f"{skill}\n\n---\n\n## Reference: Windows API Categories\n\n{ref}"


def _pp(obj: object) -> str:
    return json.dumps(obj, indent=2, default=str)


def _trim_strings(strings_block: dict) -> dict:
    return {
        **strings_block,
        "ascii":   strings_block.get("ascii",   [])[:_STRINGS_IN_PROMPT],
        "unicode": strings_block.get("unicode", [])[:_STRINGS_IN_PROMPT],
        "_note": (
            f"Lists trimmed to {_STRINGS_IN_PROMPT} per type for this prompt. "
            "See total_ascii_found / total_unicode_found for full counts."
        ),
    }


def _build_user_message_office(extractor_output: dict, sample_meta: dict) -> str:
    """Office-shaped user message: full macro source + oletools analysis for Claude."""
    name  = sample_meta.get("name", "unknown")
    size  = sample_meta.get("size", 0)
    route = sample_meta.get("route", "office")
    info  = extractor_output.get("office_info", {})

    return f"""\
## Sample metadata
- Name: {name}
- Size: {size:,} bytes
- Route: {route}

## Raw extractor output

### Hashes
{_pp(extractor_output.get("hashes", {}))}

### Office document analysis (oletools)

#### oleid risk flags
{_pp(info.get("oleid_flags", []))}

#### Macro presence
- has_macros: {info.get("has_macros", False)}
- mraptor verdict: {_pp(info.get("mraptor_verdict", {}))}

#### Auto-exec triggers (macros that run without user action)
{_pp(info.get("auto_exec_triggers", []))}

#### Suspicious keywords flagged by olevba
{_pp(info.get("suspicious_keywords", []))}

#### Extracted IOCs (URLs, IPs, other)
{_pp(info.get("iocs", {}))}

#### Full VBA macro source
(Interpret every macro — deobfuscate logic, identify the payload/download/exec \
chain, assess what the infection chain does end-to-end.)
{_pp(info.get("macros", []))}

### YARA matches
{_pp(extractor_output.get("yara_matches", []))}

### Strings (raw — supplement macro analysis)
{_pp(_trim_strings(extractor_output.get("strings", {})))}

### Extraction errors
{_pp(extractor_output.get("extraction_errors", {}))}

Analyze the raw tool output above and produce the static_analysis JSON block \
as specified in your instructions. Return only the JSON object — no prose, no \
markdown fences."""


def _build_user_message_pdf(extractor_output: dict, sample_meta: dict) -> str:
    """PDF-shaped user message: structural flags + full JS source for Claude."""
    name  = sample_meta.get("name", "unknown")
    size  = sample_meta.get("size", 0)
    route = sample_meta.get("route", "pdf")
    info  = extractor_output.get("pdf_info", {})

    return f"""\
## Sample metadata
- Name: {name}
- Size: {size:,} bytes
- Route: {route}

## Raw extractor output

### Hashes
{_pp(extractor_output.get("hashes", {}))}

### PDF structural analysis

#### Document properties
- PDF version: {info.get("pdf_version", "unknown")}
- Page count: {info.get("page_count", "unknown")}
- Object count: {info.get("object_count", "unknown")}
- Encrypted: {info.get("is_encrypted", False)}

#### Document metadata
{_pp(info.get("metadata", {}))}

#### Suspicious element counts (pdfid-style)
(Present keys = those PDF object types found in the document. /JavaScript, /OpenAction, \
/Launch, /EmbeddedFile are high-risk. Assess what each implies in context.)
{_pp(info.get("suspicious_elements", {}))}

#### Auto-launch actions (/OpenAction — executes immediately on document open)
{_pp(info.get("open_actions", []))}

#### Additional actions (/AA — event-triggered auto-execution on page/field events)
{_pp(info.get("additional_actions", []))}

#### Launch actions (/Launch — can execute OS commands / external programs)
{_pp(info.get("launch_actions", []))}

#### Full embedded JavaScript source
(This is the primary attack vector. Interpret every script: deobfuscate strings, \
trace the execution chain, identify the exploit primitive or payload delivery mechanism, \
assess what runs on the victim's machine.)
{_pp(info.get("javascript", []))}

#### Embedded files (potential payloads)
(Hash + magic bytes let you assess the embedded file type without executing it.)
{_pp(info.get("embedded_files", []))}

#### URIs (phishing links, C2 endpoints, download URLs)
{_pp(info.get("uris", []))}

### YARA matches
{_pp(extractor_output.get("yara_matches", []))}

### Strings (raw — supplement JS and structural analysis)
{_pp(_trim_strings(extractor_output.get("strings", {})))}

### Extraction errors
{_pp(extractor_output.get("extraction_errors", {}))}

Analyze the raw tool output above and produce the static_analysis JSON block \
as specified in your instructions. Return only the JSON object — no prose, no \
markdown fences."""


def _build_user_message(extractor_output: dict, sample_meta: dict) -> str:
    """
    Format raw extractor facts as a structured text prompt for Claude.
    Branches on route: pdf/office/pe each get a layout tuned to their signal type.
    """
    route = sample_meta.get("route", "pe")
    if route == "pdf":
        return _build_user_message_pdf(extractor_output, sample_meta)
    if route == "office":
        return _build_user_message_office(extractor_output, sample_meta)

    name = sample_meta.get("name", "unknown")
    size = sample_meta.get("size", 0)

    return f"""\
## Sample metadata
- Name: {name}
- Size: {size:,} bytes
- Route: {route}

## Raw extractor output

### Hashes
{_pp(extractor_output.get("hashes", {}))}

### PE structure
{_pp(extractor_output.get("pe_info", {}))}

### Capability detection (capa)
{_pp(extractor_output.get("capabilities", {}))}

### YARA matches
{_pp(extractor_output.get("yara_matches", []))}

### Strings
{_pp(_trim_strings(extractor_output.get("strings", {})))}

### Extraction errors
{_pp(extractor_output.get("extraction_errors", {}))}

Analyze the raw tool output above and produce the static_analysis JSON block \
as specified in your instructions. Return only the JSON object — no prose, no \
markdown fences."""


def _extract_json(response: str) -> dict:
    """
    Pull a JSON object out of Claude's response.

    Handles:
    - Clean JSON (ideal case)
    - JSON wrapped in markdown code fences (```json ... ``` or ``` ... ```)
    - JSON preceded or followed by prose
    """
    # 1. Strip markdown fences if present.
    fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", response)
    candidate = fence_match.group(1).strip() if fence_match else response.strip()

    # 2. Find the outermost JSON object.
    obj_match = _JSON_OBJECT_RE.search(candidate)
    if not obj_match:
        return {
            "_parse_error": True,
            "error": "No JSON object found in Claude's response.",
            "_raw_response": response[:2000],
        }

    # 3. Parse.
    try:
        return json.loads(obj_match.group())
    except json.JSONDecodeError as exc:
        return {
            "_parse_error": True,
            "error": f"JSON decode failed: {exc}",
            "_raw_response": response[:2000],
        }


def analyze_static(extractor_output: dict, sample_meta: dict) -> dict:
    """
    Interpret raw static extractor facts with Claude and return the
    static_analysis dict matching the schema defined in the skill file.

    Parameters
    ----------
    extractor_output:
        The dict returned by static_extractors.extract_static().
    sample_meta:
        Lightweight sample context: {"name": str, "size": int, "route": str}.
        Matches what the orchestrator stores in the case file.

    Returns
    -------
    dict
        Claude's static_analysis block, parsed from JSON. If parsing fails,
        returns a dict with "_parse_error": True and "error": <reason> instead
        of raising — the caller decides how to handle it.
    """
    system_prompt = _build_system_prompt()
    user_message = _build_user_message(extractor_output, sample_meta)

    raw_response = call_claude(
        system_prompt=system_prompt,
        user_content=user_message,
        max_tokens=settings.static_max_tokens,
    )

    return _extract_json(raw_response)


# ── Analyst-provided static findings ─────────────────────────────────────────

# Required top-level keys that mark a block as schema-conformant.
# If all are present the provided findings are used directly (no extra Claude call).
_REQUIRED_KEYS = {"hashes", "file_info", "behavior_hypothesis", "static_verdict", "iocs"}


def _is_schema_conformant(findings: dict) -> bool:
    """Return True if findings already match our static_analysis schema closely enough."""
    if not _REQUIRED_KEYS.issubset(findings.keys()):
        return False
    sv = findings.get("static_verdict")
    return isinstance(sv, dict) and sv.get("type") and sv.get("confidence")


def normalize_provided_static(raw_findings: dict, sample_meta: dict) -> dict:
    """
    Accept analyst-provided static findings and return a schema-conformant
    static_analysis dict tagged with source="analyst-provided".

    Fast path: if findings already pass the conformance check, deep-copy and tag them.
    Slow path: ask Claude to normalize partial/non-standard findings into our schema
    (fills null for missing fields, never fabricates evidence).
    """
    if _is_schema_conformant(raw_findings):
        result = dict(raw_findings)
        result["source"] = "analyst-provided"
        return result

    # Slow path — Claude normalizes the partial findings.
    system_prompt = _build_system_prompt()
    user_message = f"""\
The analyst provided the following static analysis findings for this sample.
Normalize them into the standard static_analysis JSON schema defined in your instructions.
Rules:
- Keep ALL findings the analyst provided — do not drop, alter, or downgrade any of them.
- Fill null for schema fields that the analyst did not cover.
- Do NOT fabricate findings — only include what the analyst provided plus null-fills.
- Return only the JSON object — no prose, no markdown fences.

## Sample metadata
- Name: {sample_meta.get("name", "unknown")}
- SHA-256: {sample_meta.get("sha256", sample_meta.get("sha256", ""))}

## Analyst-provided findings
{json.dumps(raw_findings, indent=2, default=str)}
"""

    raw_response = call_claude(
        system_prompt=system_prompt,
        user_content=user_message,
        max_tokens=settings.static_max_tokens,
    )
    result = _extract_json(raw_response)

    # Unwrap if Claude added a static_analysis wrapper key
    if not result.get("_parse_error") and "static_analysis" in result:
        inner = result["static_analysis"]
        if isinstance(inner, dict):
            result = inner

    result["source"] = "analyst-provided"
    return result


# ---------------------------------------------------------------------------
# CLI — python -m backend.app.services.static_analyzer <file>
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print(
            "Usage: python -m backend.app.services.static_analyzer <file>",
            file=sys.stderr,
        )
        sys.exit(1)

    target = sys.argv[1]
    target_path = Path(target)

    print(f"[1/2] Running static extractors on: {target_path.name}", file=sys.stderr)
    extractor_out = extract_static(target)

    meta = {
        "name": target_path.name,
        "size": target_path.stat().st_size,
        "route": "unknown",  # no magic detection here; override if needed
    }

    print("[2/2] Calling Claude for interpretation…", file=sys.stderr)
    result = analyze_static(extractor_out, meta)

    print(json.dumps(result, indent=2, default=str))
