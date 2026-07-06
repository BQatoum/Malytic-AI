"""
Dynamic analysis — Claude interpretation layer (Phase 3).

Receives a raw Hybrid Analysis sandbox report plus the static_analysis block from
Phase 2, sends them to Claude under the dynamic-analysis skill, and returns
Claude's parsed dynamic_analysis dict.

NOT wired into the pipeline yet — call analyze_dynamic() directly to test.

CLI:
    python -m backend.app.services.dynamic_analyzer --hash <sha256>
"""
from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any

from ..config import settings
from .claude_client import call_claude
from .skill_loader import load_ref, load_skill

# Per-section caps — keeps the user message within a reasonable token budget
# while still giving Claude enough raw evidence to work from.
_CAP_PROCESSES       = 50
_CAP_DNS             = 50
_CAP_HTTP            = 30
_CAP_DOMAINS         = 50
_CAP_HOSTS           = 50
_CAP_NETWORK_LIST    = 30
_CAP_COMPROMISED     = 20
_CAP_FILES           = 50
_CAP_DROPPED         = 30
_CAP_REGISTRY        = 50
_CAP_MUTEXES         = 30
_CAP_MEMORY_STRINGS  = 100
_CAP_SIGNATURES      = 100

_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)


# ── report extraction ─────────────────────────────────────────────────────────

def _pluck_str(item: Any, *keys: str) -> str:
    """Return the first non-empty string found in *item* under *keys*.

    Handles both plain-string list entries and dict entries gracefully.
    """
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        for k in keys:
            v = item.get(k, "")
            if v:
                return str(v)
    return str(item) if item else ""


def _safe_list(report: dict, *keys: str) -> list:
    """Return the first non-None list found under any of *keys*, else []."""
    for k in keys:
        val = report.get(k)
        if isinstance(val, list):
            return val
    return []


def _extract_sandbox_evidence(report: dict) -> dict:
    """
    Walk a Hybrid Analysis report (either /overview/{sha256} or
    /report/{id}/file/json format) and extract the behaviorally relevant
    sections into a clean, capped dict.

    Every section is wrapped in .get()/.or-[] so missing data silently
    produces empty lists — nothing here can raise.
    """

    # ── 1. Sandbox verdict / scoring ─────────────────────────────────────────
    sandbox_verdict = {
        "verdict":      report.get("verdict", ""),
        "threat_score": report.get("threat_score"),
        "threat_level": report.get("threat_level"),
        "family":       report.get("vx_family", report.get("family", "")),
        "type_short":   report.get("type_short", []),
        "environment":  report.get("environment_description", ""),
    }

    # ── 2. Behavior signatures ────────────────────────────────────────────────
    signatures = []
    for sig in _safe_list(report, "signatures")[:_CAP_SIGNATURES]:
        if isinstance(sig, dict):
            signatures.append({
                "name":         sig.get("name", sig.get("identifier", "")),
                "threat_level": sig.get("threat_level_human", sig.get("threat_level", "")),
                "category":     sig.get("category", ""),
                "description":  sig.get("description", ""),
            })
        elif isinstance(sig, str):
            signatures.append({"name": sig})

    # ── 3. Processes ──────────────────────────────────────────────────────────
    # Full report → "processes"; overview → "process_list"
    processes = []
    for p in _safe_list(report, "processes", "process_list")[:_CAP_PROCESSES]:
        if not isinstance(p, dict):
            continue
        processes.append({
            "pid":          p.get("pid"),
            "parent_pid":   p.get("parentid", p.get("parent_pid")),
            "name":         p.get("name", p.get("normalized_path", "")),
            "command_line": p.get("command_line", p.get("commandline", "")),
            "injected":     p.get("injected", False),
            "sha256":       p.get("sha256", ""),
        })

    # ── 4. Network ────────────────────────────────────────────────────────────
    # Domains — may be strings or {"domain": "…", "ip": "…"} objects
    domains = [
        _pluck_str(d, "domain", "name", "host")
        for d in _safe_list(report, "domains")[:_CAP_DOMAINS]
    ]

    # Hosts / IPs
    hosts = [
        _pluck_str(h, "ip", "host", "address")
        for h in _safe_list(report, "hosts")[:_CAP_HOSTS]
    ]

    # DNS requests (full report)
    dns_requests = []
    for d in _safe_list(report, "dns")[:_CAP_DNS]:
        if not isinstance(d, dict):
            continue
        dns_requests.append({
            "query":    d.get("query", d.get("requestdomain", "")),
            "type":     d.get("type", ""),
            "response": d.get("response", d.get("response_data", "")),
        })

    # HTTP requests (full report)
    http_requests = []
    for r in _safe_list(report, "http_requests")[:_CAP_HTTP]:
        if not isinstance(r, dict):
            continue
        # user_agent may be top-level or nested inside a headers dict
        ua = r.get("user_agent", "")
        if not ua and isinstance(r.get("request_headers"), dict):
            ua = r["request_headers"].get("User-Agent", "")
        http_requests.append({
            "url":        r.get("url", r.get("uri", "")),
            "method":     r.get("method", r.get("request_method", "")),
            "user_agent": ua,
            "status":     r.get("status", r.get("response_status", "")),
        })

    # Overview-style network_list (flattened connection records)
    network_list = []
    for entry in _safe_list(report, "network_list")[:_CAP_NETWORK_LIST]:
        if not isinstance(entry, dict):
            continue
        network_list.append({
            "host":     entry.get("host", entry.get("ip", entry.get("domain", ""))),
            "port":     entry.get("port", ""),
            "protocol": entry.get("protocol", ""),
            "country":  entry.get("country", ""),
        })

    # Compromised hosts
    compromised = [
        _pluck_str(h, "ip", "host", "address")
        for h in _safe_list(report, "compromised_hosts")[:_CAP_COMPROMISED]
    ]

    # ── 5. File activity ──────────────────────────────────────────────────────
    # Full report → "files"; overview → "file_list"
    file_created:  list[dict] = []
    file_modified: list[dict] = []
    file_deleted:  list[dict] = []

    for f in _safe_list(report, "files", "file_list")[:_CAP_FILES]:
        if not isinstance(f, dict):
            continue
        status = (f.get("status", f.get("type", ""))).lower()
        entry = {
            "path":   f.get("file_path", f.get("path", "")),
            "sha256": f.get("sha256", ""),
            "size":   f.get("file_size", f.get("size", "")),
        }
        if "creat" in status:
            file_created.append(entry)
        elif "modif" in status or "writ" in status:
            file_modified.append(entry)
        elif "delet" in status:
            file_deleted.append(entry)
        # Entries with unrecognised status are silently skipped — they're
        # unlikely to add signal and would bloat the prompt.

    # Dropped / extracted files
    dropped = []
    for f in _safe_list(report, "extracted_files")[:_CAP_DROPPED]:
        if not isinstance(f, dict):
            continue
        dropped.append({
            "name":         f.get("name", f.get("filename", "")),
            "path":         f.get("file_path", f.get("path", "")),
            "sha256":       f.get("sha256", ""),
            "threat_level": f.get("threat_level_human", f.get("threat_level", "")),
            "type_tag":     f.get("type_tag", f.get("type_short", "")),
        })

    # ── 6. Registry changes ───────────────────────────────────────────────────
    # Full report → "registry"; overview → "registry_list"
    registry = []
    for r in _safe_list(report, "registry", "registry_list")[:_CAP_REGISTRY]:
        if not isinstance(r, dict):
            continue
        registry.append({
            "operation":  r.get("status", r.get("operation", r.get("type", ""))),
            "key":        r.get("path", r.get("key", r.get("registry_key", ""))),
            "value_name": r.get("key", r.get("value_name", "")),
            "data":       r.get("value", r.get("data", "")),
        })

    # ── 7. Mutexes ────────────────────────────────────────────────────────────
    mutexes = []
    for m in _safe_list(report, "mutexes")[:_CAP_MUTEXES]:
        mutexes.append(_pluck_str(m, "name"))

    # ── 8. Memory strings ─────────────────────────────────────────────────────
    memory_strings: list[str] = []
    for s in _safe_list(report, "memory_strings", "strings")[:_CAP_MEMORY_STRINGS]:
        if isinstance(s, str):
            memory_strings.append(s)
        elif isinstance(s, dict):
            memory_strings.append(s.get("string", s.get("value", "")))

    return {
        "sandbox_verdict": sandbox_verdict,
        "signatures":      signatures,
        "processes":       processes,
        "network": {
            "domains":          domains,
            "hosts":            hosts,
            "dns_requests":     dns_requests,
            "http_requests":    http_requests,
            "network_list":     network_list,
            "compromised_hosts": compromised,
        },
        "file_activity": {
            "created":  file_created,
            "modified": file_modified,
            "deleted":  file_deleted,
            "dropped":  dropped,
        },
        "registry":       registry,
        "mutexes":        mutexes,
        "memory_strings": memory_strings,
    }


# ── PCAP analysis helper ──────────────────────────────────────────────────────

def _run_pcap_analysis(pcap_path: str) -> dict | None:
    """
    Call pcap_analyzer.analyze_pcap on *pcap_path* and return the result,
    or None if the path is empty / the analysis fails.  Never raises.
    """
    if not pcap_path:
        return None
    try:
        from .pcap_analyzer import analyze_pcap  # noqa: PLC0415
        result = analyze_pcap(pcap_path)
        if result.get("_pcap_error"):
            import sys
            print(f"[!] PCAP analysis failed ({pcap_path}): {result['_pcap_error']}",
                  file=sys.stderr)
            return None
        return result
    except Exception as exc:
        import sys
        print(f"[!] PCAP analysis raised ({pcap_path}): {exc}", file=sys.stderr)
        return None


# ── Triage evidence adapter ───────────────────────────────────────────────────

def _extract_triage_evidence(report: dict) -> dict:
    """
    Map a Triage-sourced evidence dict (source=='triage') onto the same internal
    shape that _build_user_message() consumes.  Triage has no file/registry/mutex
    data from the web scrape, so those sections are empty lists.
    """
    mc     = report.get("malware_config") or {}
    family = mc.get("family") or report.get("family", "")

    score_str = report.get("score", "")
    try:
        score_num = int(score_str.split("/")[0]) if "/" in score_str else 0
    except (ValueError, AttributeError):
        score_num = 0

    verdict = report.get("verdict", "")
    if not verdict or verdict == "unknown":
        verdict = ("malicious" if score_num >= 7 else
                   "suspicious" if score_num >= 4 else "clean")

    sandbox_verdict = {
        "verdict":      verdict,
        "threat_score": score_num,
        "threat_level": score_num,
        "family":       family,
        "type_short":   report.get("tags", []),
        "environment":  "Triage (tria.ge) automated sandbox",
    }

    # Signatures
    signatures = []
    for sig in (report.get("signatures") or [])[:_CAP_SIGNATURES]:
        if isinstance(sig, dict):
            signatures.append({
                "name":         sig.get("name", ""),
                "threat_level": (sig.get("tags") or [""])[0],
                "category":     "",
                "description":  sig.get("description", ""),
            })
        elif isinstance(sig, str):
            signatures.append({"name": sig, "threat_level": "", "category": "",
                                "description": ""})

    # Processes
    processes = []
    for p in (report.get("processes") or [])[:_CAP_PROCESSES]:
        if isinstance(p, dict):
            processes.append({
                "pid":          None,
                "parent_pid":   None,
                "name":         p.get("image", ""),
                "command_line": p.get("command_line", ""),
                "injected":     False,
                "sha256":       "",
            })

    # Network
    net  = report.get("network") or {}
    dns_requests  = [{"query": d, "type": "A", "response": ""}
                     for d in (net.get("dns") or [])[:_CAP_DNS]]
    http_requests = [{"url": u, "method": "", "user_agent": "", "status": ""}
                     for u in (net.get("http") or [])[:_CAP_HTTP]]
    domains = list(net.get("dns") or [])[:_CAP_DOMAINS]

    # Build network_list from tcp + udp + c2 entries
    network_list: list[dict] = []
    for proto, entries in (("tcp", net.get("tcp") or []),
                            ("udp", net.get("udp") or []),
                            ("c2",  net.get("c2")  or [])):
        for entry in entries[:_CAP_NETWORK_LIST]:
            parts = str(entry).rsplit(":", 1)
            network_list.append({
                "host":     parts[0],
                "port":     parts[1] if len(parts) > 1 else "",
                "protocol": proto,
                "country":  "",
            })
    hosts = [e["host"] for e in network_list if e["host"]][:_CAP_HOSTS]

    # Memory strings: malware_config C2 + attributes as enrichment
    memory_strings: list[str] = []
    for addr in (mc.get("c2") or []):
        memory_strings.append(f"C2: {addr}")
    for k, v in (mc.get("attributes") or {}).items():
        memory_strings.append(f"{k}: {v}")

    return {
        "sandbox_verdict": sandbox_verdict,
        "signatures":      signatures,
        "processes":       processes,
        "network": {
            "domains":            domains,
            "hosts":              hosts,
            "dns_requests":       dns_requests,
            "http_requests":      http_requests,
            "network_list":       network_list[:_CAP_NETWORK_LIST],
            "compromised_hosts":  [],
        },
        "file_activity": {"created": [], "modified": [], "deleted": [], "dropped": []},
        "registry":       [
            {"action": r.get("action", "accessed"),
             "key":    r.get("path", ""),
             "process": r.get("process", "")}
            for r in (report.get("registry") or [])
        ],
        "mutexes":        [],
        "memory_strings": memory_strings[:_CAP_MEMORY_STRINGS],
        # Bonus fields consumed by the extended _build_user_message
        "_malware_config":   mc,
        "_mitre":            report.get("mitre") or [],
        "_pcap_analysis":    _run_pcap_analysis(report.get("pcap_path", "")),
        "_report_fulltext":  report.get("report_fulltext", ""),
        "_screenshots":      report.get("screenshots") or [],
    }


# ── prompt assembly ───────────────────────────────────────────────────────────

def _build_system_prompt() -> str:
    skill = load_skill("dynamic_analysis")
    ref   = load_ref("dynamic_reference")
    return f"{skill}\n\n---\n\n## Reference: Dynamic Analysis Lookup Tables\n\n{ref}"


def _build_user_message(
    evidence: dict,
    static_analysis: dict,
    sample_meta: dict,
) -> str | list:
    def _pp(obj: object) -> str:
        return json.dumps(obj, indent=2, default=str)

    name   = sample_meta.get("name",   "unknown")
    sha256 = sample_meta.get("sha256", sample_meta.get("hashes", {}).get("sha256", ""))
    route  = sample_meta.get("route",  "unknown")
    env    = evidence["sandbox_verdict"].get("environment", "")

    # Pull the cross-phase items from static_analysis (may be empty in standalone test)
    behavior_hypothesis    = static_analysis.get("behavior_hypothesis", "")
    to_confirm_dynamically = static_analysis.get("to_confirm_dynamically", [])
    static_iocs            = static_analysis.get("iocs", static_analysis.get("network_iocs", []))

    net = evidence["network"]
    fa  = evidence["file_activity"]

    # Optional Triage-specific sections (absent in Hybrid Analysis reports)
    mc          = evidence.get("_malware_config")
    mitre       = evidence.get("_mitre")
    pcap        = evidence.get("_pcap_analysis")
    fulltext    = evidence.get("_report_fulltext", "")
    screenshots = evidence.get("_screenshots") or []
    extra = ""

    # Full report text is the primary evidence source — present it first so Claude
    # reads EVERYTHING the sandbox reported, including fields the structured parser
    # may have missed (credentials, collapsed IOC tables, custom config keys, etc.)
    if fulltext:
        extra += (
            "\n## Complete Triage behavioral report (verbatim)\n"
            "Read the entire text below. Extract ALL indicators, config values, "
            "credentials, registry keys, network endpoints, and behaviors present — "
            "not just those summarised in the structured fields above.\n\n"
            + fulltext
            + "\n"
        )

    if screenshots:
        labels = ["start of detonation", "mid-detonation", "near end of detonation"]
        desc   = ", ".join(
            f"({i+1}) {labels[i]}" for i in range(min(len(screenshots), len(labels)))
        )
        extra += (
            f"\n## Detonation replay screenshots ({len(screenshots)} frames: {desc})\n"
            "Canvas screenshots from the Triage Replay Monitor are embedded below "
            "in image order. Examine each for visible malware impact: ransomware "
            "wallpaper/ransom-note changes, UAC prompts, unusual windows, "
            "desktop state changes, or any other behavioral indicators.\n"
        )

    if mc:
        extra += f"\n## Malware configuration (parser-extracted summary)\n{_pp(mc)}\n"
    if mitre:
        extra += f"\n## MITRE ATT&CK techniques observed\n{_pp(mitre)}\n"
    if pcap:
        # Lead with the highest-value facts: resolved IPs and external connections.
        dns_resolved = [
            f"  {e['query']} → {', '.join(e['responses'])}"
            for e in pcap.get("dns", [])
            if e.get("responses")
        ]
        extra += "\n## Network packet capture (PCAP) analysis\n"
        extra += f"### Summary\n{_pp(pcap['summary'])}\n"
        if dns_resolved:
            extra += "\n### DNS resolutions (domain → resolved IP)\n"
            extra += "\n".join(dns_resolved) + "\n"
        if pcap.get("external_ips"):
            extra += f"\n### External destination IPs\n{_pp(pcap['external_ips'])}\n"
        if pcap.get("tls"):
            extra += f"\n### TLS SNI (ClientHello server names)\n{_pp(pcap['tls'])}\n"
        if pcap.get("beaconing"):
            extra += f"\n### Beaconing indicators (repeated SYN clusters)\n{_pp(pcap['beaconing'])}\n"
        if pcap.get("http"):
            extra += f"\n### Plaintext HTTP requests\n{_pp(pcap['http'])}\n"
        top_convs = [
            c for c in pcap.get("conversations", [])[:15]
            if not c["src_ip"].startswith(("10.", "192.168.", "172."))
            or not c["dst_ip"].startswith(("10.", "192.168.", "172."))
        ]
        if top_convs:
            extra += f"\n### Top external conversations (by bytes)\n{_pp(top_convs)}\n"

    text = f"""\
## Sample metadata
- Name: {name}
- SHA-256: {sha256}
- Route: {route}
- Detonation environment: {env or "unknown"}

## Sandbox verdict  ←  DO NOT adopt as your own verdict
This is the sandbox's automated opinion. Use it only at step 8 (cross-check).
{_pp(evidence["sandbox_verdict"])}

## Behavior signatures flagged by sandbox  ←  raw list, not interpreted
{_pp(evidence["signatures"])}

## Static phase output to confirm or refute
### Behavior hypothesis from static analysis
{behavior_hypothesis or "(none — standalone test or static phase not yet run)"}

### Items flagged to confirm dynamically
{_pp(to_confirm_dynamically) if to_confirm_dynamically else "(none)"}

### Key static IOCs
{_pp(static_iocs) if static_iocs else "(none)"}

## Process tree (raw)
{_pp(evidence["processes"])}

## Network activity

### DNS requests
{_pp(net["dns_requests"])}

### HTTP requests
{_pp(net["http_requests"])}

### Contacted domains
{_pp(net["domains"])}

### Contacted IPs / hosts
{_pp(net["hosts"])}

### Network connection list (overview format, if present)
{_pp(net["network_list"])}

### Compromised hosts
{_pp(net["compromised_hosts"])}

## File activity

### Created
{_pp(fa["created"])}

### Modified
{_pp(fa["modified"])}

### Deleted
{_pp(fa["deleted"])}

### Dropped / extracted files
{_pp(fa["dropped"])}

## Registry changes
{_pp(evidence["registry"])}

## Mutexes
{_pp(evidence["mutexes"])}

## Memory strings (post-execution)
{_pp(evidence["memory_strings"])}
{extra}
Analyze the raw sandbox evidence above and produce the dynamic_analysis JSON block \
as specified in your instructions. Return only the JSON object — no prose, no \
markdown fences."""

    # If there are screenshots, build a multimodal content list with the text
    # prompt followed by base64-encoded PNG image blocks.  Claude vision will
    # see the actual VM desktop state at each captured moment.
    if not screenshots:
        return text

    content: list = [{"type": "text", "text": text}]
    for img_path in screenshots[:3]:
        try:
            img_data = base64.b64encode(Path(img_path).read_bytes()).decode("ascii")
            content.append({
                "type": "image",
                "source": {
                    "type":       "base64",
                    "media_type": "image/png",
                    "data":       img_data,
                },
            })
        except Exception as exc:
            import sys as _sys
            print(f"[!] Could not load screenshot {img_path}: {exc}", file=_sys.stderr)

    # Fall back to plain text if no images loaded successfully
    return content if len(content) > 1 else text


# ── JSON parsing (identical approach to static_analyzer) ─────────────────────

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

def analyze_dynamic(
    sandbox_report: dict,
    static_analysis: dict,
    sample_meta: dict,
) -> dict:
    """
    Interpret raw sandbox evidence with Claude and return the dynamic_analysis
    dict matching the schema defined in the dynamic-analysis skill file.

    Parameters
    ----------
    sandbox_report:
        Raw JSON from sandbox_client.get_report() or get_report_by_hash().
    static_analysis:
        The static_analysis block from the case file (may be {} for standalone
        testing — the skill handles missing static context gracefully).
    sample_meta:
        {"name": str, "sha256": str, "route": str}. Matches case file fields.

    Returns
    -------
    dict
        Claude's dynamic_analysis block, parsed from JSON. On parse failure,
        returns {"_parse_error": True, "error": str} instead of raising.
    """
    if sandbox_report.get("source") == "triage":
        evidence = _extract_triage_evidence(sandbox_report)
    else:
        evidence = _extract_sandbox_evidence(sandbox_report)
    system_prompt = _build_system_prompt()
    user_message  = _build_user_message(evidence, static_analysis, sample_meta)

    raw_response = call_claude(
        system_prompt=system_prompt,
        user_content=user_message,
        max_tokens=settings.dynamic_max_tokens,
    )

    result = _extract_json(raw_response)

    # Carry screenshot paths into the case file so the report phase can embed them.
    # Claude wraps its output as {"dynamic_analysis": {...}}, so inject into the
    # inner dict — the pipeline unwrapper strips the outer key before committing.
    if not result.get("_parse_error"):
        shot_paths = evidence.get("_screenshots") or []
        if shot_paths:
            inner = result.get("dynamic_analysis")
            target = inner if isinstance(inner, dict) else result
            target["_screenshot_paths"] = shot_paths

    return result


# ── Analyst-provided dynamic findings ────────────────────────────────────────

_REQUIRED_DYNAMIC_KEYS = {"claude_verdict", "network", "confirmed_iocs"}

_DEFAULT_SCREENSHOT_ANALYSIS = {
    "visible_impact":    False,
    "observations":      "No detonation screenshots (analyst-provided findings).",
    "include_in_report": False,
    "report_frames":     [],
    "caption":           "",
}


def _is_dynamic_conformant(findings: dict) -> bool:
    """Return True if findings already match our dynamic_analysis schema closely enough."""
    if not _REQUIRED_DYNAMIC_KEYS.issubset(findings.keys()):
        return False
    cv = findings.get("claude_verdict")
    return isinstance(cv, dict) and cv.get("type") and cv.get("confidence")


def normalize_provided_dynamic(
    raw_findings: dict,
    static_analysis: dict,
    sample_meta: dict,
) -> dict:
    """
    Accept analyst-provided dynamic findings and return a schema-conformant
    dynamic_analysis dict tagged with source="analyst-provided".

    Fast path: findings pass the conformance check → deep-copy, tag, ensure
    screenshot_analysis is present with include_in_report=False, return.
    Slow path: partial/non-standard findings → Claude normalizes via the
    dynamic-analysis skill (fills null for missing, never fabricates).
    _screenshot_paths is never set — no Triage screenshots exist.
    """
    if _is_dynamic_conformant(raw_findings):
        result = dict(raw_findings)
        result.setdefault("screenshot_analysis", dict(_DEFAULT_SCREENSHOT_ANALYSIS))
        result["screenshot_analysis"]["include_in_report"] = False
        result["source"] = "analyst-provided"
        return result

    # Slow path — Claude normalizes the partial findings.
    system_prompt = _build_system_prompt()
    user_message = f"""\
The analyst provided the following dynamic analysis findings for this sample.
Normalize them into the standard dynamic_analysis JSON schema defined in your instructions.
Rules:
- Keep ALL findings the analyst provided — do not drop, alter, or downgrade any of them.
- Fill null (or empty arrays) for schema fields the analyst did not cover.
- Do NOT fabricate findings — only include what the analyst provided plus null-fills.
- Set screenshot_analysis.include_in_report = false and screenshot_analysis.visible_impact = false
  (no detonation screenshots exist for analyst-provided findings).
- Return only the JSON object wrapped in {{"dynamic_analysis": {{...}}}} — no prose, no markdown fences.

## Sample metadata
- Name: {sample_meta.get("name", "unknown")}
- SHA-256: {sample_meta.get("sha256", "")}

## Prior static analysis (for context — do not re-analyze, just normalize the dynamic findings)
{json.dumps(static_analysis, indent=2, default=str)[:2000]}

## Analyst-provided dynamic findings
{json.dumps(raw_findings, indent=2, default=str)}
"""

    raw_response = call_claude(
        system_prompt=system_prompt,
        user_content=user_message,
        max_tokens=settings.dynamic_max_tokens,
    )
    result = _extract_json(raw_response)

    # Unwrap dynamic_analysis wrapper key if Claude added it
    if not result.get("_parse_error"):
        inner = result.get("dynamic_analysis")
        if isinstance(inner, dict):
            result = inner

    # Guarantee screenshot_analysis is safe regardless of Claude's output
    result.setdefault("screenshot_analysis", dict(_DEFAULT_SCREENSHOT_ANALYSIS))
    result["screenshot_analysis"]["include_in_report"] = False
    result.pop("_screenshot_paths", None)  # never carry sandbox paths
    result["source"] = "analyst-provided"
    return result


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    import pathlib
    import sys

    # ── shared helper ─────────────────────────────────────────────────────────

    def _meta_from_triage_evidence(evidence: dict) -> dict:
        """Derive sample_meta from a Triage evidence dict."""
        sha256 = ""
        name   = "unknown"
        procs  = evidence.get("processes") or []
        if procs:
            raw_img = procs[0].get("image", "").strip('"')
            fname   = raw_img.replace("\\", "/").rsplit("/", 1)[-1]
            stem    = fname.rsplit(".", 1)[0] if "." in fname else fname
            if len(stem) == 64 and all(c in "0123456789abcdefABCDEF" for c in stem):
                sha256 = stem.lower()
                name   = fname
            else:
                name = fname or evidence.get("sample_id", "unknown")
        if not sha256:
            sha256 = evidence.get("sha256", "")
        return {"name": name, "sha256": sha256, "route": "triage"}

    def _load_static(path_str: str | None) -> dict:
        """Load an optional static_analysis block from a file path."""
        if not path_str:
            return {}
        sp = pathlib.Path(path_str)
        if not sp.exists():
            print(f"[!] --static file not found: {sp}", file=sys.stderr)
            sys.exit(1)
        raw = json.loads(sp.read_text(encoding="utf-8"))
        return raw.get("static_analysis", raw)

    def _run_triage_analysis(evidence: dict, static_path: str | None) -> None:
        """Print progress, call analyze_dynamic, dump JSON result."""
        meta   = _meta_from_triage_evidence(evidence)
        static = _load_static(static_path)

        print(f"    sample_id = {evidence.get('sample_id', '?')}", file=sys.stderr)
        print(f"    family    = {evidence.get('family', '?')}", file=sys.stderr)
        print(f"    score     = {evidence.get('score', '?')}", file=sys.stderr)
        print(f"    verdict   = {evidence.get('verdict', '?')}", file=sys.stderr)
        print(f"    sha256    = {meta['sha256'] or '(not found in process paths)'}",
              file=sys.stderr)
        print("[*] Calling Claude …", file=sys.stderr)

        result = analyze_dynamic(
            sandbox_report=evidence,
            static_analysis=static,
            sample_meta=meta,
        )
        print(json.dumps(result, indent=2, default=str))

    # ── argument parsing ──────────────────────────────────────────────────────

    parser = argparse.ArgumentParser(
        description="Dynamic analysis interpreter (standalone test)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Submit a fresh sample to Triage and interpret in one command:\n"
            "  python -m backend.app.services.dynamic_analyzer \\\n"
            "      --triage-submit /path/to/sample.zip --password infected\n"
            "\n"
            "  # Interpret a saved Triage evidence JSON:\n"
            "  python -m backend.app.services.dynamic_analyzer \\\n"
            "      --triage-evidence /tmp/triage_260620-xxx_evidence.json\n"
            "\n"
            "  # Either Triage mode with a static-phase block for context:\n"
            "  python -m backend.app.services.dynamic_analyzer \\\n"
            "      --triage-evidence /tmp/triage_260620-xxx_evidence.json \\\n"
            "      --static /path/to/case.json\n"
            "\n"
            "  # Hybrid Analysis (existing mode):\n"
            "  python -m backend.app.services.dynamic_analyzer --hash <sha256>\n"
        ),
    )
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "--triage-submit", metavar="SAMPLE_PATH",
        help="Submit a sample to Triage, wait for detonation, extract evidence, "
             "then interpret with Claude — full pipeline in one command.",
    )
    source_group.add_argument(
        "--triage-evidence", metavar="PATH",
        help="Load a saved Triage evidence JSON (source=='triage') and interpret it.",
    )
    source_group.add_argument(
        "--hash", metavar="SHA256",
        help="Fetch an existing Hybrid Analysis report by SHA-256 and interpret it.",
    )
    parser.add_argument(
        "--password", metavar="PASSWORD", default="infected",
        help="Archive password for --triage-submit (default: 'infected').",
    )
    parser.add_argument(
        "--static", metavar="PATH",
        help="Optional case JSON or static_analysis block to provide static-phase "
             "context (accepted by all modes).",
    )
    args = parser.parse_args()

    # ── branch: fresh Triage submission ──────────────────────────────────────
    if args.triage_submit:
        sample_path = pathlib.Path(args.triage_submit)
        if not sample_path.exists():
            print(f"[!] Sample file not found: {sample_path}", file=sys.stderr)
            sys.exit(1)

        from .triage_playwright import submit_and_fetch  # noqa: PLC0415

        print(f"[1/2] Submitting {sample_path.name} to Triage (headless) …",
              file=sys.stderr)
        print(f"      password = {args.password!r}", file=sys.stderr)
        evidence = submit_and_fetch(str(sample_path), password=args.password,
                                    headless=True)
        if not evidence or evidence.get("source") != "triage":
            print("[!] submit_and_fetch did not return valid Triage evidence.",
                  file=sys.stderr)
            sys.exit(1)

        print("[2/2] Detonation complete — interpreting evidence …", file=sys.stderr)
        _run_triage_analysis(evidence, args.static)
        sys.exit(0)

    # ── branch: saved Triage evidence file ───────────────────────────────────
    if args.triage_evidence:
        ev_path = pathlib.Path(args.triage_evidence)
        if not ev_path.exists():
            print(f"[!] File not found: {ev_path}", file=sys.stderr)
            sys.exit(1)

        evidence = json.loads(ev_path.read_text(encoding="utf-8"))
        if evidence.get("source") != "triage":
            print("[!] JSON does not have source=='triage' — is this a Triage evidence file?",
                  file=sys.stderr)
            sys.exit(1)

        print(f"[*] Triage evidence: {ev_path.name}", file=sys.stderr)
        _run_triage_analysis(evidence, args.static)
        sys.exit(0)

    # ── branch: Hybrid Analysis hash ─────────────────────────────────────────
    from .sandbox_client import SandboxError, get_report_by_hash  # noqa: PLC0415

    print(f"[1/2] Fetching sandbox report for {args.hash} …", file=sys.stderr)
    try:
        report = get_report_by_hash(args.hash)
    except SandboxError as exc:
        print(f"[!] Sandbox error: {exc}", file=sys.stderr)
        sys.exit(1)

    sha256 = report.get("sha256", args.hash)
    meta = {
        "name":   report.get("submit_name", report.get("type_short", ["unknown"])[0]
                             if report.get("type_short") else "unknown"),
        "sha256": sha256,
        "route":  "unknown",
    }
    static = _load_static(args.static)

    print("[2/2] Calling Claude for dynamic interpretation …", file=sys.stderr)
    result = analyze_dynamic(
        sandbox_report=report,
        static_analysis=static,
        sample_meta=meta,
    )
    print(json.dumps(result, indent=2, default=str))
