"""
PDF renderer for malware analysis reports (Phase 6 output layer).

Markdown → styled HTML → WeasyPrint PDF.
Pure rendering — no API calls.

CLI (free, for design iteration):
    python -m backend.app.services.report_pdf --md /tmp/report.md --out /tmp/report.pdf

CLI (calls generate_report then renders — costs an API call):
    python -m backend.app.services.report_pdf --case /tmp/case.json --out /tmp/report.pdf
"""
from __future__ import annotations

import base64
import logging
import re
from pathlib import Path

# Suppress WeasyPrint font/CSS warnings that fire on every run.
logging.getLogger("weasyprint").setLevel(logging.ERROR)
logging.getLogger("weasyprint.text.fonts").setLevel(logging.ERROR)


# ── Markdown → HTML ───────────────────────────────────────────────────────────

def _md_to_html(text: str) -> str:
    import markdown
    return markdown.markdown(
        text,
        extensions=["tables", "fenced_code"],
        output_format="html",
    )


# ── Metadata extraction from Markdown ────────────────────────────────────────

def _extract_h1(md_text: str) -> str:
    for line in md_text.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return "Malware Analysis Report"


def _extract_table_value(md_text: str, key: str) -> str:
    """Pull a value from the top markdown table by bold key name."""
    m = re.search(
        rf"\|\s*\*\*{re.escape(key)}\*\*\s*\|\s*([^|\n]+?)\s*\|",
        md_text,
        re.IGNORECASE,
    )
    return m.group(1).strip() if m else ""


def _confidence_color(confidence: str) -> str:
    c = confidence.lower()
    if "high" in c:
        return "#c0392b"   # red  — kept for badge; header uses brand blue
    if "medium" in c:
        return "#d97706"   # amber
    return "#6b7280"       # gray


# ── HTML post-processing ──────────────────────────────────────────────────────

def _postprocess(html: str) -> str:
    """Add semantic classes to elements that need special styling."""
    # Numbered action items: **1. Isolate...** → amber callout
    html = re.sub(
        r"<p><strong>(\d+\.\s)",
        r'<p class="callout-action"><strong>\1',
        html,
    )
    # Warning-level callouts
    html = re.sub(
        r"<p><strong>(Priority action:|Any user who|Immediate action)",
        r'<p class="callout-warning"><strong>\1',
        html,
    )
    return html


# ── CSS ───────────────────────────────────────────────────────────────────────

_CSS = """
/* ═══════════════════════════════════════════════════════════════════════════
   Malware.AI-inspired clinical security report — brand blue #2b5797
   ═══════════════════════════════════════════════════════════════════════════ */

/* ── Page layout ───────────────────────────────────────────────────────────── */
@page {
    size: A4;
    margin: 1.8cm 1.8cm 2.4cm 1.8cm;
    @top-left {
        content: element(running-header);
    }
    @bottom-center {
        content: "Page " counter(page) " / " counter(pages);
        font-size: 7pt;
        color: #9ca3af;
        font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
    }
}

@page :first {
    @top-left { content: none; }
}

/* ── Base ───────────────────────────────────────────────────────────────────── */
* { box-sizing: border-box; }

body {
    font-family: "Helvetica Neue", Helvetica, Arial, "DejaVu Sans", sans-serif;
    font-size: 9.5pt;
    line-height: 1.58;
    color: #1a1f2e;
    margin: 0;
    background: #ffffff;
}

/* ── Running header ─────────────────────────────────────────────────────────── */
.running-header {
    position: running(running-header);
    font-family: "Helvetica Neue", Helvetica, Arial, "DejaVu Sans", sans-serif;
    font-size: 7pt;
    color: #2b5797;
    font-weight: bold;
    letter-spacing: 0.2pt;
    padding-bottom: 2pt;
    border-bottom: 0.75pt solid #2b5797;
    width: 100%;
}

/* ── Title band (white, clinical — accent rule at bottom) ───────────────────── */
.title-band {
    background: #ffffff;
    padding: 0 0 18pt 0;
    margin: -1.8cm -1.8cm 22pt -1.8cm;
    border-bottom: 3pt solid #2b5797;
    page-break-after: avoid;
}

.title-band-inner {
    padding: 24pt 24pt 0 24pt;
}

.title-band h1 {
    color: #2b5797;
    font-size: 17pt;
    font-weight: bold;
    margin: 0 0 8pt 0;
    line-height: 1.25;
    border: none;
    letter-spacing: -0.2pt;
}

p.title-badge-row {
    margin: 0 0 10pt 0;
    color: #4b5563;
    font-size: 8.5pt;
}

.confidence-badge {
    display: inline-block;
    padding: 2pt 8pt;
    border-radius: 2pt;
    font-size: 7.5pt;
    font-weight: bold;
    color: #ffffff;
    letter-spacing: 0.4pt;
    text-transform: uppercase;
}

/* Metadata table inside title band */
.title-band table {
    margin: 0;
    width: auto;
    table-layout: auto;
    font-size: 8pt;
    border-collapse: collapse;
}

.title-band table thead { display: none; }

.title-band table td {
    background: transparent !important;
    border: none !important;
    padding: 1.5pt 24pt 1.5pt 0 !important;
    color: #4b5563 !important;
    vertical-align: top;
    word-break: break-word;
    overflow-wrap: anywhere;
}

.title-band table td strong {
    color: #1a1f2e !important;
    font-weight: bold;
}

/* ── Section headings ───────────────────────────────────────────────────────── */
h1 {
    color: #2b5797;
    font-size: 15pt;
    font-weight: bold;
    margin-top: 18pt;
    margin-bottom: 8pt;
}

h2 {
    color: #2b5797;
    font-size: 11.5pt;
    font-weight: bold;
    border-bottom: 1.25pt solid #2b5797;
    padding-bottom: 3pt;
    margin-top: 22pt;
    margin-bottom: 8pt;
    page-break-before: always;   /* each top-level section starts on a new page */
    page-break-after: avoid;
    letter-spacing: 0.1pt;
}

h3 {
    color: #1a1f2e;
    font-size: 10pt;
    font-weight: bold;
    margin-top: 14pt;
    margin-bottom: 5pt;
    page-break-after: avoid;
}

h4 {
    color: #374151;
    font-size: 9.5pt;
    font-weight: bold;
    margin-top: 10pt;
    margin-bottom: 4pt;
}

hr {
    border: none;
    border-top: 0.5pt solid #e5e7eb;
    margin: 14pt 0;
}

/* ── Body text ──────────────────────────────────────────────────────────────── */
p { margin: 0 0 7pt 0; }

a {
    color: #2b5797;
    text-decoration: none;
}

strong { font-weight: bold; }

/* ── Tables — fixed layout prevents overflow ─────────────────────────────────── */
table {
    border-collapse: collapse;
    width: 100%;
    table-layout: fixed;
    margin: 8pt 0 14pt 0;
    font-size: 8pt;
}

thead th {
    background: #2b5797;
    color: #ffffff;
    padding: 5pt 7pt;
    text-align: left;
    font-weight: bold;
    border: 0.75pt solid #1e4080;
    word-break: break-word;
    overflow-wrap: anywhere;
}

tbody td {
    padding: 4pt 7pt;
    border: 0.5pt solid #dde3ef;
    vertical-align: top;
    word-break: break-word;
    overflow-wrap: anywhere;
}

tbody tr:nth-child(odd)  td { background: #ffffff; }
tbody tr:nth-child(even) td { background: #f4f7fb; }

/* ── Code blocks ─────────────────────────────────────────────────────────────── */
pre {
    background: #f4f7fb;
    border-left: 3pt solid #2b5797;
    border-radius: 0 2pt 2pt 0;
    padding: 10pt 13pt;
    margin: 8pt 0 12pt 0;
    white-space: pre-wrap;
    word-break: break-word;
    overflow-wrap: anywhere;
}

pre code {
    font-family: "DejaVu Sans Mono", "Courier New", monospace;
    font-size: 7.5pt;
    background: none;
    padding: 0;
    color: #1a1f2e;
    line-height: 1.48;
}

code {
    font-family: "DejaVu Sans Mono", "Courier New", monospace;
    font-size: 8pt;
    background: #f0f3f9;
    padding: 1pt 3pt;
    border-radius: 2pt;
    color: #1a1f2e;
}

/* ── Blockquotes ─────────────────────────────────────────────────────────────── */
blockquote {
    border-left: 3pt solid #2b5797;
    background: #f4f7fb;
    margin: 10pt 0;
    padding: 8pt 14pt;
    border-radius: 0 2pt 2pt 0;
}

blockquote p {
    margin: 0;
    font-size: 8.5pt;
    color: #374151;
}

/* ── Callout boxes ───────────────────────────────────────────────────────────── */
p.callout-action {
    background: #fffbeb;
    border-left: 3pt solid #f59e0b;
    padding: 6pt 11pt;
    margin: 5pt 0;
    border-radius: 0 2pt 2pt 0;
}

p.callout-warning {
    background: #fef2f2;
    border-left: 3pt solid #ef4444;
    padding: 6pt 11pt;
    margin: 5pt 0;
    border-radius: 0 2pt 2pt 0;
}

/* ── Lists ───────────────────────────────────────────────────────────────────── */
ul, ol {
    margin: 4pt 0 8pt 0;
    padding-left: 16pt;
}

li {
    margin-bottom: 2pt;
}

li p { margin: 0; }

/* ── Detonation screenshots ──────────────────────────────────────────────────── */
figure.detonation-screenshot {
    margin: 10pt 0 14pt 0;
    page-break-inside: avoid;
    border: 0.75pt solid #dde3ef;
    border-radius: 2pt;
    background: #f4f7fb;
    padding: 8pt;
}

figure.detonation-screenshot img {
    max-width: 100%;
    height: auto;
    display: block;
}

figure.detonation-screenshot figcaption {
    font-size: 7.5pt;
    color: #4b5563;
    font-style: italic;
    margin-top: 5pt;
    padding-top: 4pt;
    border-top: 0.5pt solid #dde3ef;
    line-height: 1.4;
}
"""


# ── Screenshot embedding helpers ─────────────────────────────────────────────

def _build_screenshot_html(screenshots: list[dict]) -> str:
    """
    Build an HTML fragment containing one <figure> per screenshot.

    Each item in *screenshots* is {"path": str, "caption": str}.
    Images are embedded as base64 data URIs so the PDF is self-contained.
    Missing / unreadable files are silently skipped.
    Returns an empty string if no images loaded.
    """
    figures: list[str] = []
    fig_num = 1
    for i, ss in enumerate(screenshots):
        path    = ss.get("path", "")
        caption = ss.get("caption", "")
        if not path:
            continue
        try:
            img_b64 = base64.b64encode(Path(path).read_bytes()).decode("ascii")
        except Exception:
            continue
        # Prefix "Fig N: " so captions read as figure labels in the PDF.
        # Only add the prefix when there is caption text; leave blank captions blank.
        if caption:
            labeled_caption = f"Fig {fig_num}: {caption}"
        else:
            labeled_caption = ""
        cap_html = (
            f"<figcaption>{labeled_caption}</figcaption>" if labeled_caption else ""
        )
        figures.append(
            f'<figure class="detonation-screenshot">'
            f'<img src="data:image/png;base64,{img_b64}" '
            f'alt="Detonation screenshot {fig_num}">'
            f'{cap_html}'
            f'</figure>'
        )
        fig_num += 1
    return "\n".join(figures)


def _inject_screenshots(body_html: str, screenshot_html: str) -> str:
    """
    Inject *screenshot_html* into *body_html* after the Dynamic Analysis section.

    Strategy: find the H2 whose text contains "Dynamic", then find the next H2
    after it and insert the screenshot block immediately before that H2.
    Falls back to appending before </body> if the Dynamic H2 is not found.
    """
    if not screenshot_html:
        return body_html

    # Locate the Dynamic Analysis H2
    dyn_m = re.search(
        r'<h2>[^<]*(?:Dynamic|Behavioral|Sandbox)[^<]*</h2>',
        body_html,
        re.IGNORECASE,
    )
    if not dyn_m:
        return body_html + screenshot_html

    # Find the next H2 after it
    rest_start = dyn_m.end()
    next_h2 = re.search(r'<h2>', body_html[rest_start:], re.IGNORECASE)
    insert_at = rest_start + next_h2.start() if next_h2 else len(body_html)

    return body_html[:insert_at] + screenshot_html + body_html[insert_at:]


# ── HTML document assembly ────────────────────────────────────────────────────

def _build_html(
    md_text: str,
    meta: dict | None = None,
    screenshots: list[dict] | None = None,
) -> str:
    meta = meta or {}
    title      = _extract_h1(md_text)
    sha256     = _extract_table_value(md_text, "SHA-256") or meta.get("sha256", "")
    confidence = _extract_table_value(md_text, "Overall confidence") or meta.get("overall_confidence", "")

    # Body: strip the H1 (re-rendered in the title band)
    body_md   = re.sub(r"^#\s+[^\n]+\n?", "", md_text, count=1)
    body_html = _md_to_html(body_md)
    body_html = _postprocess(body_html)

    # Inject screenshot figures after the Dynamic Analysis section
    if screenshots:
        screenshot_html = _build_screenshot_html(screenshots)
        body_html = _inject_screenshots(body_html, screenshot_html)

    # Confidence badge — shown in title band below the H1
    badge_html = ""
    if confidence:
        badge_color = _confidence_color(confidence)
        badge_html = (
            f'<p class="title-badge-row">'
            f'Overall confidence: '
            f'<span class="confidence-badge" style="background:{badge_color};">'
            f'{confidence}</span></p>'
        )

    # Running header (truncated to avoid overflow)
    running_text = title if len(title) <= 90 else title[:87] + "…"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>{_CSS}</style>
</head>
<body>

<div class="running-header">{running_text}</div>

<div class="title-band">
  <div class="title-band-inner">
    <h1>{title}</h1>
    {badge_html}
  </div>
</div>

{body_html}

</body>
</html>"""


# ── Public API ────────────────────────────────────────────────────────────────

def render_report_pdf(
    report_markdown: str,
    output_path: str,
    meta: dict | None = None,
    screenshots: list[dict] | None = None,
) -> str:
    """
    Render *report_markdown* to a PDF at *output_path*.

    Parameters
    ----------
    report_markdown : str
        Full Markdown content of the report (raw text, not JSON-wrapped).
    output_path : str
        Destination file path for the PDF.
    meta : dict, optional
        Supplementary metadata (sha256, overall_confidence) used as fallback
        when those values are not present in the Markdown.
    screenshots : list[dict], optional
        Detonation screenshot frames to embed in the PDF.  Each dict:
        {"path": str, "caption": str}.  Images are embedded as base64 data
        URIs.  Missing files are silently skipped.

    Returns
    -------
    str
        The resolved absolute path of the written PDF.
    """
    from weasyprint import HTML as WP_HTML

    html    = _build_html(report_markdown, meta, screenshots)
    out     = Path(output_path).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    WP_HTML(string=html).write_pdf(str(out))
    return str(out)


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Render a malware-analysis report Markdown to PDF.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Free — render from existing .md file:\n"
            "  python -m backend.app.services.report_pdf \\\n"
            "      --md /tmp/report.md --out /tmp/report.pdf\n\n"
            "  # API call — generate report from case fixture then render:\n"
            "  python -m backend.app.services.report_pdf \\\n"
            "      --case test_fixtures/agenttesla_full.json --out /tmp/report.pdf\n"
        ),
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--md",   metavar="PATH", help="Markdown file to render directly.")
    group.add_argument("--case", metavar="PATH", help="Case JSON file — calls generate_report first.")
    parser.add_argument("--out", metavar="PATH", required=True, help="Output PDF path.")
    args = parser.parse_args()

    if args.md:
        md_path = Path(args.md)
        if not md_path.exists():
            print(f"[!] File not found: {md_path}", file=sys.stderr)
            sys.exit(1)
        md_text = md_path.read_text(encoding="utf-8")
        meta: dict = {}
        print(f"[*] Source: {md_path}", file=sys.stderr)

    else:
        import json
        case_path = Path(args.case)
        if not case_path.exists():
            print(f"[!] File not found: {case_path}", file=sys.stderr)
            sys.exit(1)
        case = json.loads(case_path.read_text(encoding="utf-8"))

        from .report_generator import generate_report

        sample           = case.get("sample") or {}
        sha256           = (
            (sample.get("extracted_primary_hashes") or {}).get("sha256")
            or sample.get("sha256", "")
        )
        sample_meta      = {
            "name":   sample.get("name", case_path.stem),
            "sha256": sha256,
            "md5":    sample.get("md5",  ""),
            "sha1":   sample.get("sha1", ""),
            "route":  case.get("route", "unknown"),
        }
        static_analysis  = case.get("static_analysis")  or {}
        dynamic_analysis = case.get("dynamic_analysis") or {}
        osint            = case.get("osint")            or {}
        attribution      = case.get("attribution")      or {}
        detection        = case.get("detection")        or {}

        print("[*] Calling Claude for report generation …", file=sys.stderr)
        result = generate_report(
            static_analysis, dynamic_analysis, osint, attribution, detection, sample_meta
        )
        if result.get("_parse_error"):
            print(f"[!] Report generation failed: {result.get('error')}", file=sys.stderr)
            sys.exit(1)

        md_text = result["report"]["content"]
        meta    = {"overall_confidence": result["report"].get("overall_confidence", "")}
        print("[+] Report generated.", file=sys.stderr)

    print("[*] Rendering PDF …", file=sys.stderr)
    out = render_report_pdf(md_text, args.out, meta)
    print(f"[+] PDF written to {out}", file=sys.stderr)
