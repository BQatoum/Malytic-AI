"""
OSINT research — Claude interpretation layer (Phase 4).

Collects IOCs from the static and dynamic phases, queries VirusTotal for
structured reputation data, then asks Claude to interpret the VT data AND
do a single focused web search on the hash + family name.

CLI:
    python -m backend.app.services.osint_analyzer --hash <sha256>
    python -m backend.app.services.osint_analyzer --case <path_to_case.json>
"""
from __future__ import annotations

import json
import re
import time
from typing import Any


from ..config import settings
from .claude_client import call_claude
from .skill_loader import load_skill
from .virustotal_client import (
    VTNotFoundError,
    VTRateLimitError,
    VTError,
    get_domain_report,
    get_file_report,
    get_ip_report,
)

# VT lookup caps — stay within free-tier budget (4 req/min, 500/day).
# With vt_request_delay=15s the worst case is (1+5+5)*15s ≈ 2.5 min of sleeping.
_MAX_IPS     = 5
_MAX_DOMAINS = 5

# Context-only caps — fed to Claude but no VT call made.
_MAX_MUTEXES          = 10
_MAX_PDB_PATHS        = 5
_MAX_DECODED_STRINGS  = 10

# ── IOC collection ────────────────────────────────────────────────────────────

def _as_str_list(value: Any) -> list[str]:
    """Coerce a list of strings or dicts to a flat list of strings."""
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            out.append(item.strip())
        elif isinstance(item, dict):
            # Try common indicator key names
            for key in ("indicator", "value", "ioc", "ip", "domain", "url"):
                v = item.get(key, "")
                if isinstance(v, str) and v.strip():
                    out.append(v.strip())
                    break
    return out


def _dedupe_ordered(items: list[str]) -> list[str]:
    """Remove duplicates while preserving order."""
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        low = item.lower()
        if low not in seen:
            seen.add(low)
            out.append(item)
    return out


def _collect_iocs(
    static_analysis: dict,
    dynamic_analysis: dict,
    sample_meta: dict,
) -> dict:
    """
    Extract and deduplicate IOCs from prior phases for VT lookups and
    web-research context.

    Returns
    -------
    dict with keys:
        sha256           – sample hash (always present)
        ips              – up to _MAX_IPS unique IPs for VT lookup
        domains          – up to _MAX_DOMAINS unique domains for VT lookup
        mutexes          – context only (no VT call)
        pdb_paths        – context only
        decoded_strings  – up to _MAX_DECODED_STRINGS notable decoded strings
        family_hints     – suspected family names from both phases
        to_research_osint – items explicitly flagged by dynamic for OSINT
    """
    # ── 1. Sample hash ────────────────────────────────────────────────────────
    sha256 = (
        sample_meta.get("sha256")
        or (static_analysis.get("hashes") or {}).get("sha256", "")
    )

    # ── 2. Network IOCs — priority: confirmed > dynamic network > static iocs ─
    dyn_net      = dynamic_analysis.get("network") or {}
    static_iocs  = static_analysis.get("iocs") or {}
    confirmed    = _as_str_list(dynamic_analysis.get("confirmed_iocs", []))

    # Collect raw IPs and domains in priority order.
    raw_ips: list[str] = (
        confirmed
        + _as_str_list(dyn_net.get("ips", []))
        + _as_str_list(static_iocs.get("ips", []))
    )
    raw_domains: list[str] = (
        confirmed
        + _as_str_list(dyn_net.get("domains", []))
        + _as_str_list(dyn_net.get("urls", []))   # URLs often carry the domain
        + _as_str_list(static_iocs.get("domains", []))
        + _as_str_list(static_iocs.get("urls", []))
    )

    # Very basic type filter: IPs are dotted-decimal or contain colons (IPv6).
    _is_ip = lambda s: re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s) or ":" in s
    # Keep only IPs in the IP list; strip IPs from the domain list.
    ips     = _dedupe_ordered([s for s in raw_ips if _is_ip(s)])[:_MAX_IPS]
    domains = _dedupe_ordered([s for s in raw_domains if not _is_ip(s) and "." in s])[:_MAX_DOMAINS]

    # ── 3. Context-only artifacts ─────────────────────────────────────────────
    mutexes = _dedupe_ordered(_as_str_list(static_iocs.get("mutexes", [])))[:_MAX_MUTEXES]
    pdb_paths = _dedupe_ordered(_as_str_list(static_iocs.get("pdb_paths", [])))[:_MAX_PDB_PATHS]

    raw_decoded = static_analysis.get("decoded_strings") or []
    decoded_strings: list[str] = []
    for entry in raw_decoded[:_MAX_DECODED_STRINGS]:
        if isinstance(entry, str):
            decoded_strings.append(entry)
        elif isinstance(entry, dict):
            v = entry.get("value", entry.get("string", ""))
            if v:
                decoded_strings.append(str(v))

    # ── 4. Family hints ───────────────────────────────────────────────────────
    family_hints: list[str] = []
    for path in [
        (static_analysis, "static_verdict", "type"),
        (dynamic_analysis, "claude_verdict", "type"),
        (dynamic_analysis, "sandbox_verdict", "family_guess"),
    ]:
        obj, *keys = path
        for k in keys:
            obj = (obj or {}).get(k) if isinstance(obj, dict) else None
        if isinstance(obj, str) and obj.strip():
            family_hints.append(obj.strip())
    family_hints = list(dict.fromkeys(family_hints))  # dedupe, preserve order

    to_research_osint = _as_str_list(dynamic_analysis.get("to_research_osint", []))

    return {
        "sha256":            sha256,
        "ips":               ips,
        "domains":           domains,
        "mutexes":           mutexes,
        "pdb_paths":         pdb_paths,
        "decoded_strings":   decoded_strings,
        "family_hints":      family_hints,
        "to_research_osint": to_research_osint,
    }


# ── VirusTotal lookups ─────────────────────────────────────────────────────────

def _safe_vt_call(fn, indicator: str) -> dict:
    """
    Wrap a single VT lookup in isolation.

    Returns the raw data dict on success, or a small error/not-found marker
    so one failed lookup never aborts the rest.
    """
    try:
        return fn(indicator)
    except VTNotFoundError:
        return {"found": False}
    except VTRateLimitError as exc:
        return {"error": "rate_limited", "detail": str(exc)}
    except VTError as exc:
        return {"error": "lookup_failed", "detail": str(exc)}


def _run_vt_lookups(sha256: str, ips: list[str], domains: list[str]) -> dict:
    """
    Query VirusTotal for the sample hash, then each IP, then each domain.

    Sleeps settings.vt_request_delay seconds between consecutive calls to
    respect the free-tier 4-requests/minute limit (set VT_REQUEST_DELAY=0 in
    .env to disable during testing).

    Returns
    -------
    {
        "file":    data_or_error,
        "ips":     {ip: data_or_error, ...},
        "domains": {domain: data_or_error, ...},
    }
    """
    delay = settings.vt_request_delay
    first_call = True

    def _call(fn, indicator: str) -> dict:
        nonlocal first_call
        if not first_call and delay > 0:
            time.sleep(delay)
        first_call = False
        return _safe_vt_call(fn, indicator)

    file_result = _call(get_file_report, sha256) if sha256 else {"error": "no_hash"}

    ip_results: dict[str, dict] = {}
    for ip in ips:
        ip_results[ip] = _call(get_ip_report, ip)

    domain_results: dict[str, dict] = {}
    for domain in domains:
        domain_results[domain] = _call(get_domain_report, domain)

    return {"file": file_result, "ips": ip_results, "domains": domain_results}


# ── prompt assembly ───────────────────────────────────────────────────────────

def _build_system_prompt() -> str:
    return load_skill("osint")


def _build_user_message(
    vt_data: dict,
    iocs: dict,
    static_analysis: dict,
    dynamic_analysis: dict,
    sample_meta: dict,
) -> str:
    """Minimal context: hashes + family + VT file result only. No process lists,
    no network IOCs, no decoded strings — those ballooned the prompt to 25K+ chars."""
    name   = sample_meta.get("name", "unknown")
    sha256 = iocs.get("sha256", "")

    # Pull md5/sha1 from static hashes or sample_meta
    hashes = (static_analysis.get("hashes") or {})
    md5  = hashes.get("md5",  sample_meta.get("md5",  ""))
    sha1 = hashes.get("sha1", sample_meta.get("sha1", ""))

    # Compact verdict/score lines
    dyn_verdict = (dynamic_analysis.get("claude_verdict") or {})
    sbox_verdict = (dynamic_analysis.get("sandbox_verdict") or {})
    family_hints = iocs.get("family_hints", [])
    verdict_line = ", ".join(filter(None, [
        dyn_verdict.get("type", ""),
        sbox_verdict.get("family_guess", ""),
    ] + family_hints)) or "unknown"
    score_line = str(sbox_verdict.get("score", ""))

    vt_file = json.dumps(vt_data.get("file", {}), indent=2, default=str)

    return f"""\
## Sample
- Name: {name}
- SHA-256: {sha256 or "(unknown)"}
- MD5: {md5 or "(unknown)"}
- SHA-1: {sha1 or "(unknown)"}

## Suspected family / verdict
{verdict_line}
{f"- Sandbox score: {score_line}" if score_line else ""}

## VirusTotal file lookup
{vt_file}

Research this sample using ONLY the hash and the suspected family name. \
Your single web search should target: "{sha256} {verdict_line.split(",")[0].strip()}".
Return ONLY the JSON object — no prose, no markdown fences."""


# ── JSON parsing (same approach as static/dynamic analyzers) ─────────────────

def _extract_json(response: str) -> dict:
    """Parse the first valid JSON object anywhere in the response.

    Scans forward from each '{' using raw_decode so prose wrapping, fences,
    and partial garbage before the JSON are all handled correctly.
    """
    decoder = json.JSONDecoder()
    for i, ch in enumerate(response):
        if ch != "{":
            continue
        try:
            obj, _ = decoder.raw_decode(response, i)
            return obj
        except json.JSONDecodeError:
            continue
    return {
        "_parse_error": True,
        "error": "No JSON object found in Claude's response.",
        "_raw_response": response[:2000],
    }


# ── public entry point ────────────────────────────────────────────────────────

def analyze_osint(
    static_analysis: dict,
    dynamic_analysis: dict,
    sample_meta: dict,
) -> dict:
    """
    Run the OSINT phase: query VirusTotal, then ask Claude to interpret the VT
    data and perform its own web research, producing the osint block.

    Parameters
    ----------
    static_analysis:
        The static_analysis block from the case file (may be {} for testing).
    dynamic_analysis:
        The dynamic_analysis block from the case file (may be {} for testing).
    sample_meta:
        {"name": str, "sha256": str, "route": str}

    Returns
    -------
    dict
        Claude's osint block, parsed from JSON. On parse failure returns
        {"_parse_error": True, "error": str}.
    """
    iocs          = _collect_iocs(static_analysis, dynamic_analysis, sample_meta)
    vt_data       = _run_vt_lookups(iocs["sha256"], iocs["ips"], iocs["domains"])
    system_prompt = _build_system_prompt()
    user_message  = _build_user_message(
        vt_data, iocs, static_analysis, dynamic_analysis, sample_meta
    )

    raw_response = call_claude(
        system_prompt=system_prompt,
        user_content=user_message,
        max_tokens=settings.osint_max_tokens,
        enable_web_search=True,
        max_web_searches=settings.osint_max_web_searches,
    )

    return _extract_json(raw_response)


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="OSINT analyzer — standalone test",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m backend.app.services.osint_analyzer --hash <sha256>\n"
            "  python -m backend.app.services.osint_analyzer --case /tmp/case.json\n"
        ),
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--hash", metavar="SHA256",
        help="Run OSINT on just this SHA-256 (empty static/dynamic context).",
    )
    group.add_argument(
        "--case", metavar="PATH",
        help="Run OSINT from a full case JSON (uses existing static/dynamic blocks).",
    )
    args = parser.parse_args()

    if args.case:
        import pathlib
        case_data = json.loads(pathlib.Path(args.case).read_text())
        static_analysis  = case_data.get("static_analysis", {})
        dynamic_analysis = case_data.get("dynamic_analysis", {})
        sha256 = (
            case_data.get("sha256")
            or (static_analysis.get("hashes") or {}).get("sha256", "")
        )
        sample_meta = {
            "name":   case_data.get("file_name", sha256),
            "sha256": sha256,
            "route":  case_data.get("route", "unknown"),
        }
    else:
        static_analysis  = {}
        dynamic_analysis = {}
        sample_meta = {
            "name":   args.hash,
            "sha256": args.hash,
            "route":  "unknown",
        }
        sha256 = args.hash

    print(f"[1/2] Running VirusTotal lookups for {sha256} …", file=sys.stderr)
    print(
        f"      (VT_REQUEST_DELAY={settings.vt_request_delay}s between calls, "
        f"max_web_searches={settings.osint_max_web_searches})",
        file=sys.stderr,
    )

    print("[2/2] Calling Claude with web search enabled …", file=sys.stderr)
    try:
        result = analyze_osint(
            static_analysis=static_analysis,
            dynamic_analysis=dynamic_analysis,
            sample_meta=sample_meta,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"[!] ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(result, indent=2, default=str))
