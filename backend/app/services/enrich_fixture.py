"""
Dev helper: enrich a saved case fixture with the correlation/attribution and
detection phases so the fixture is complete for report-generation and PDF testing.

Runs only phases that are absent from the input — already-present blocks are
kept untouched. No sandbox, no VT, no web search.

CLI:
    python -m backend.app.services.enrich_fixture <input_case.json> <output_case.json>
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from .correlation_analyzer import analyze_correlation
from .detection_engineer import analyze_detection


# ── helpers ───────────────────────────────────────────────────────────────────

def _resolve_sample_meta(case: dict) -> dict:
    sample = case.get("sample") or {}
    sha256 = (
        (sample.get("extracted_primary_hashes") or {}).get("sha256")
        or sample.get("sha256", "")
    )
    return {
        "name":   sample.get("name", "unknown"),
        "sha256": sha256,
        "md5":    sample.get("md5",  ""),
        "sha1":   sample.get("sha1", ""),
        "route":  case.get("route",  "unknown"),
    }


def _unwrap(result: dict, key: str) -> dict:
    """Unwrap a single top-level key if present — mirrors pipeline.py behaviour."""
    if len(result) == 1 and key in result:
        return result[key]
    return result


def _phase_status(case: dict) -> None:
    phases = [
        ("static_analysis",  "static_analysis"),
        ("dynamic_analysis", "dynamic_analysis"),
        ("osint",            "osint"),
        ("attribution",      "attribution"),
        ("detection",        "detection"),
        ("report",           "report"),
    ]
    for label, key in phases:
        present = bool(case.get(key))
        tag = "present" if present else "ABSENT "
        print(f"  [{tag}] {label}", file=sys.stderr)


# ── public entry point ────────────────────────────────────────────────────────

def enrich(case: dict) -> dict:
    """
    Add missing attribution and/or detection blocks to *case* in-place.

    Returns the (mutated) case dict.
    """
    meta             = _resolve_sample_meta(case)
    static_analysis  = case.get("static_analysis")  or {}
    dynamic_analysis = case.get("dynamic_analysis") or {}
    osint            = case.get("osint")            or {}

    # ── Phase 4: correlation / attribution ────────────────────────────────────
    if not case.get("attribution"):
        print("[*] attribution missing — running correlation phase …", file=sys.stderr)
        result = analyze_correlation(static_analysis, dynamic_analysis, osint, meta)
        if result.get("_parse_error"):
            print(f"[!] correlation failed: {result.get('error')}", file=sys.stderr)
            sys.exit(1)
        case["attribution"] = _unwrap(result, "attribution")
        print("[+] attribution: done", file=sys.stderr)
    else:
        print("[~] attribution: already present — skipping", file=sys.stderr)

    # ── Phase 5: detection engineering ───────────────────────────────────────
    if not case.get("detection"):
        print("[*] detection missing — running detection phase …", file=sys.stderr)
        # Use attribution freshly written above (if it was just added).
        attribution = case.get("attribution") or {}
        result = analyze_detection(static_analysis, dynamic_analysis, osint, attribution, meta)
        if result.get("_parse_error"):
            print(f"[!] detection failed: {result.get('error')}", file=sys.stderr)
            sys.exit(1)
        case["detection"] = _unwrap(result, "detection")
        print("[+] detection: done", file=sys.stderr)
    else:
        print("[~] detection: already present — skipping", file=sys.stderr)

    return case


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Enrich a case fixture with correlation/attribution and detection phases.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m backend.app.services.enrich_fixture \\\n"
            "      test_fixtures/agenttesla_partial.json \\\n"
            "      test_fixtures/agenttesla_full.json\n"
        ),
    )
    parser.add_argument("input",  metavar="INPUT",  help="Path to the input case JSON.")
    parser.add_argument("output", metavar="OUTPUT", help="Path to write the enriched case JSON.")
    args = parser.parse_args()

    input_path  = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"[!] File not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    try:
        case = json.loads(input_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"[!] Invalid JSON in {input_path}: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Loaded {input_path}", file=sys.stderr)
    _phase_status(case)
    print("", file=sys.stderr)

    enriched = enrich(case)

    print("", file=sys.stderr)
    print("[*] Final phase inventory:", file=sys.stderr)
    _phase_status(enriched)

    output_path.write_text(
        json.dumps(enriched, indent=2, default=str), encoding="utf-8"
    )
    print(f"\n[+] Written to {output_path}", file=sys.stderr)
