"""
Elastic push — Part A + B of the pipeline's Elastic integration step.

Part A: index detection IOCs as ECS threat indicators (POST /_bulk).
Part B: create Kibana detection rules from Sigma YAML (POST /api/detection_engine/rules).

ECS mapping (Part A — threat.indicator.*):
  sha256/md5/sha1    → type=file,                 threat.indicator.file.hash.<algo>
  domain             → type=domain-name,           threat.indicator.url.domain
  ipv4               → type=ipv4-addr,             threat.indicator.ip
  url                → type=url,                   threat.indicator.url.full
  registry           → type=windows-registry-key,  threat.indicator.registry.path
  path               → type=file,                  threat.indicator.file.path
  mutex/string/other → type=unknown,               threat.indicator.name

Sigma→KQL translator (Part B):
  Translates Sigma detection blocks to Kibana KQL custom-query rules directly
  via the Kibana Detections API — no pySigma dependency at runtime.
  pySigma is the recommended future enhancement for full Sigma compliance;
  this direct translator handles the specific process_creation / registry_set /
  file_event logsource patterns used by our detection engineering phase.

CLIs:
    python -m backend.app.services.elastic_push --case <path>          # index IOCs
    python -m backend.app.services.elastic_push --case <path> --rules  # push Sigma rules
    python -m backend.app.services.elastic_push --case <path> --iocs   # index IOCs (explicit)
"""
from __future__ import annotations

import io
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

import yaml

from ..config import settings
from .elastic_client import _es_headers, _kibana_headers, _post
from .rule_validator import repair_sigma_rule

# ── constants ─────────────────────────────────────────────────────────────────

IOC_INDEX      = "malware-pipeline-iocs"
_PROVIDER      = "malware-analysis-pipeline"
_FEED_NAME     = "malware-analysis-pipeline"
_DATASET       = "malware-pipeline.threat"

# Maps our IOC type strings → ECS threat.indicator.type values
_ECS_TYPE: dict[str, str] = {
    "sha256":   "file",
    "md5":      "file",
    "sha1":     "file",
    "domain":   "domain-name",
    "ipv4":     "ipv4-addr",
    "url":      "url",
    "registry": "windows-registry-key",
    "path":     "file",
    "mutex":    "unknown",
    "string":   "unknown",
}


# ── ECS document builder ──────────────────────────────────────────────────────

def _build_indicator_doc(
    ioc:         dict,
    sample_meta: dict,
    case_id:     str,
    family:      str,
    ts:          str,
) -> dict:
    """
    Map one IOC dict to an ECS 8.x threat indicator document.

    Required ioc keys: value_original, type, confidence, volatility, source_phase.
    Optional: value_defanged (ignored here — ES needs the real value).
    """
    ioc_type    = (ioc.get("type") or "string").lower()
    ecs_type    = _ECS_TYPE.get(ioc_type, "unknown")
    value       = ioc.get("value_original") or ioc.get("value", "")
    confidence  = (ioc.get("confidence") or "low").capitalize()   # ECS: High/Medium/Low
    source      = ioc.get("source_phase", "unknown")
    volatility  = ioc.get("volatility", "unknown")
    sha256      = sample_meta.get("sha256", "")

    # ── base ECS envelope ────────────────────────────────────────────────────
    doc: dict[str, Any] = {
        "@timestamp": ts,
        "event": {
            "kind":     "enrichment",
            "category": ["threat"],
            "type":     ["indicator"],
            "dataset":  _DATASET,
        },
        "threat": {
            "indicator": {
                "type":        ecs_type,
                "confidence":  confidence,
                "provider":    _PROVIDER,
                "first_seen":  ts,
                "description": value,
            },
            "feed": {
                "name": _FEED_NAME,
            },
        },
        "labels": {
            "case_id":        case_id,
            "source_phase":   source,
            "volatility":     volatility,
            "sample_sha256":  sha256,
            "malware_family": family,
            "ioc_type":       ioc_type,
        },
        "tags": list(filter(None, [
            "malware-pipeline",
            f"case:{case_id}" if case_id else None,
            f"family:{family}" if family else None,
            source,
        ])),
    }

    indicator = doc["threat"]["indicator"]

    # ── type-specific value placement ─────────────────────────────────────────
    if ioc_type == "sha256":
        indicator["file"] = {"hash": {"sha256": value}}
    elif ioc_type == "md5":
        indicator["file"] = {"hash": {"md5": value}}
    elif ioc_type == "sha1":
        indicator["file"] = {"hash": {"sha1": value}}
    elif ioc_type == "domain":
        indicator["url"] = {"domain": value}
    elif ioc_type == "ipv4":
        indicator["ip"] = value
    elif ioc_type == "url":
        indicator["url"] = {"full": value}
    elif ioc_type == "registry":
        indicator["registry"] = {"path": value}
    elif ioc_type == "path":
        indicator["file"] = {"path": value}
    else:
        # mutex, string, unknown — no dedicated ECS subfield
        indicator["name"] = value

    return doc


# ── bulk indexing ─────────────────────────────────────────────────────────────

def _build_bulk_body(docs: list[dict], index: str) -> str:
    """Serialise documents into NDJSON format for the _bulk API."""
    buf = io.StringIO()
    action = json.dumps({"index": {"_index": index}})
    for doc in docs:
        buf.write(action + "\n")
        buf.write(json.dumps(doc, default=str) + "\n")
    return buf.getvalue()


def _parse_bulk_response(response: Any, ioc_count: int) -> list[str]:
    """
    Extract per-item errors from a _bulk API response body.
    Returns a list of error strings (empty = no errors).
    """
    errors: list[str] = []
    if not isinstance(response, dict):
        errors.append(f"unexpected bulk response type: {type(response).__name__}")
        return errors

    if not response.get("errors"):
        return errors   # all succeeded

    for i, item in enumerate(response.get("items", [])):
        action_result = item.get("index") or item.get("create") or {}
        if action_result.get("error"):
            err = action_result["error"]
            errors.append(
                f"IOC #{i}: {err.get('type','?')} — {err.get('reason','?')}"
            )
    return errors


# ── public entry point ────────────────────────────────────────────────────────

def index_iocs(
    detection:   dict,
    sample_meta: dict,
    case_id:     str,
    index:       str = IOC_INDEX,
) -> dict:
    """
    Index the IOCs from *detection* into Elasticsearch.

    Parameters
    ----------
    detection:
        The detection block from the case file. Must contain an "iocs" list.
    sample_meta:
        {"name": str, "sha256": str, "route": str, …}
    case_id:
        The pipeline case identifier — embedded in each document's labels/tags.
    index:
        Target ES index name (default: "malware-pipeline-iocs").

    Returns
    -------
    dict
        {
          "index":          str,
          "iocs_total":     int,   # IOCs found in detection block
          "iocs_indexed":   int,   # successfully sent to ES
          "iocs_skipped":   int,   # skipped (empty value)
          "errors":         list[str],
          "es_status":      int,   # HTTP status from _bulk call
        }
    """
    iocs   = detection.get("iocs") or []
    family = (
        detection.get("malware_family")
        or detection.get("family")
        or ""
    )
    ts = datetime.now(timezone.utc).isoformat()

    # Build documents, skipping IOCs with no usable value
    docs:    list[dict] = []
    skipped: list[int]  = []
    for i, ioc in enumerate(iocs):
        value = (ioc.get("value_original") or ioc.get("value") or "").strip()
        if not value:
            skipped.append(i)
            continue
        docs.append(_build_indicator_doc(ioc, sample_meta, case_id, family, ts))

    summary: dict[str, Any] = {
        "index":        index,
        "iocs_total":   len(iocs),
        "iocs_indexed": 0,
        "iocs_skipped": len(skipped),
        "errors":       [],
        "es_status":    0,
    }

    if not docs:
        summary["errors"].append("no IOCs with non-empty values found in detection block")
        return summary

    # POST /_bulk
    base    = settings.elastic_url.rstrip("/")
    url     = f"{base}/_bulk"
    headers = {**_es_headers(), "Content-Type": "application/x-ndjson"}
    body    = _build_bulk_body(docs, index)

    code, response = _post(url, body, headers)
    summary["es_status"] = code

    if code == -1:
        # Transport-level failure
        summary["errors"].append(f"Transport error: {response}")
        return summary

    if code not in (200, 201):
        summary["errors"].append(
            f"ES returned HTTP {code}: {str(response)[:400]}"
        )
        return summary

    per_item_errors = _parse_bulk_response(response, len(docs))
    summary["errors"].extend(per_item_errors)
    summary["iocs_indexed"] = len(docs) - len(per_item_errors)
    return summary


# ══════════════════════════════════════════════════════════════════════════════
# Part B: Sigma → Kibana detection rules
# ══════════════════════════════════════════════════════════════════════════════

# ── field / level / index lookup tables ───────────────────────────────────────

# Sigma field name → ECS field name.
# Add entries here as new logsources are introduced; unmapped names fall
# through as lowercase(sigma_field) so rules still generate rather than crash.
_SIGMA_FIELD_MAP: dict[str, str] = {
    # process_creation
    "Image":              "process.executable",
    "CommandLine":        "process.command_line",
    "ParentImage":        "process.parent.executable",
    "ParentCommandLine":  "process.parent.command_line",
    "User":               "user.name",
    "IntegrityLevel":     "process.pe.integrity_level",
    # registry
    "TargetObject":       "registry.path",
    "Details":            "registry.data.strings",
    # file
    "TargetFilename":     "file.path",
    # network
    "DestinationIp":      "destination.ip",
    "DestinationPort":    "destination.port",
    "DestinationHostname": "destination.domain",
    # dns
    "QueryName":          "dns.question.name",
}

# Sigma rule level → (Kibana severity, risk_score).
_LEVEL_MAP: dict[str, tuple[str, int]] = {
    "critical": ("critical", 99),
    "high":     ("high",     73),
    "medium":   ("medium",   47),
    "low":      ("low",      21),
}

# Default index patterns for all rules.
_BASE_INDICES: list[str] = [
    "logs-endpoint.events.*",
    "logs-windows.*",
    "winlogbeat-*",
    ".ds-logs-*",
]

# Logsource category → extra, more-specific index patterns (prepended to base).
_CATEGORY_EXTRA: dict[str, list[str]] = {
    "process_creation": ["logs-endpoint.events.process-*"],
    "registry_set":     ["logs-endpoint.events.registry-*"],
    "file_event":       ["logs-endpoint.events.file-*"],
    "network_connection": ["logs-endpoint.events.network-*"],
    "dns_query":        ["logs-endpoint.events.network-*"],
}

# Sigma ATT&CK tactic tag (after stripping "attack.") → (MITRE ID, name).
_TACTIC_MAP: dict[str, tuple[str, str]] = {
    "initial_access":        ("TA0001", "Initial Access"),
    "execution":             ("TA0002", "Execution"),
    "persistence":           ("TA0003", "Persistence"),
    "privilege_escalation":  ("TA0004", "Privilege Escalation"),
    "defense_evasion":       ("TA0005", "Defense Evasion"),
    "credential_access":     ("TA0006", "Credential Access"),
    "discovery":             ("TA0007", "Discovery"),
    "lateral_movement":      ("TA0008", "Lateral Movement"),
    "collection":            ("TA0009", "Collection"),
    "exfiltration":          ("TA0010", "Exfiltration"),
    "command_and_control":   ("TA0011", "Command and Control"),
    "impact":                ("TA0040", "Impact"),
    "reconnaissance":        ("TA0043", "Reconnaissance"),
    "resource_development":  ("TA0042", "Resource Development"),
}


# ── KQL translation helpers ───────────────────────────────────────────────────

def _kql_escape(val: str) -> str:
    """Escape a value for a KQL wildcard pattern.

    Two-pass approach:
      1. Normalize: collapse runs of ≥2 consecutive backslashes down to half.
         Sigma values for Windows paths should have single backslashes, but
         YAML single-quoted strings with '\\' give double backslashes after
         yaml.safe_load. Normalizing makes escaping idempotent regardless of
         how the YAML was authored.
      2. Escape for KQL: '\' → '\\' (literal backslash), ':' → '\:' (KQL
         treats bare ':' as the field-separator operator, so a drive-letter
         colon like 'C:' breaks the query parser with "Expected ')', AND, OR
         but ':' found").
    """
    s = str(val)
    # Step 1 — normalize pre-doubled backslashes
    s = re.sub(r"\\{2,}", lambda m: "\\" * (len(m.group()) // 2), s)
    # Step 2 — KQL escaping (backslash first, then colon)
    s = s.replace("\\", "\\\\")
    s = s.replace(":", "\\:")
    return s


def _translate_field_condition(
    sigma_key: str,
    value: Any,
) -> tuple[str, list[str]]:
    """
    Translate one Sigma `key: value` pair from a selection dict to a KQL fragment.

    sigma_key is the raw YAML key, e.g. "Image|endswith" or "CommandLine|contains|all".
    Returns (kql_fragment, notes) where notes lists any caveats (regex fallback, etc.).
    """
    parts     = sigma_key.split("|")
    raw_field = parts[0]
    mods      = [m.lower() for m in parts[1:]]
    ecs_field = _SIGMA_FIELD_MAP.get(raw_field, raw_field.lower())
    notes: list[str] = []

    # ── regex modifier ────────────────────────────────────────────────────────
    if "re" in mods:
        pattern = str(value)
        kql_parts: list[str] = []
        if "TEMP" in pattern or "Temp" in pattern or "temp" in pattern:
            kql_parts.append(f"{ecs_field} : *Temp*")
        if ".ps1" in pattern:
            kql_parts.append(f"{ecs_field} : *.ps1*")
        if ".exe" in pattern:
            kql_parts.append(f"{ecs_field} : *.exe*")
        if not kql_parts:
            kql_parts.append(f"{ecs_field} : *")  # catch-all — flag prominently
        notes.append(
            f"'{sigma_key}' uses regex — KQL cannot express this precisely; "
            f"best-effort fallback generated. Validate and tighten in Kibana."
        )
        return " AND ".join(kql_parts), notes

    # ── value list (always OR unless "all" modifier overrides) ────────────────
    values = value if isinstance(value, list) else [value]
    contains_all = "contains" in mods and "all" in mods
    contains     = "contains" in mods and "all" not in mods
    startswith   = "startswith" in mods
    endswith     = "endswith"   in mods

    if contains_all:
        # All values must appear → AND chain
        clauses = [f"{ecs_field} : *{_kql_escape(v)}*" for v in values]
        return " AND ".join(clauses), notes

    if contains:
        clauses = [f"{ecs_field} : *{_kql_escape(v)}*" for v in values]
    elif startswith:
        clauses = [f"{ecs_field} : {_kql_escape(v)}*" for v in values]
    elif endswith:
        clauses = [f"{ecs_field} : *{_kql_escape(v)}" for v in values]
    else:
        # Exact match
        clauses = [f'{ecs_field} : "{_kql_escape(v)}"' for v in values]

    if len(clauses) == 1:
        return clauses[0], notes
    return "(" + " OR ".join(clauses) + ")", notes


def _selection_to_kql(selection_dict: dict) -> tuple[str, list[str]]:
    """
    Translate a Sigma selection dict (multiple field conditions) to KQL.
    Multiple fields inside a selection are AND-ed together.
    """
    if not isinstance(selection_dict, dict):
        return "*", [f"unexpected selection type {type(selection_dict).__name__} — using catch-all"]

    parts: list[str] = []
    all_notes: list[str] = []
    for sigma_key, val in selection_dict.items():
        frag, notes = _translate_field_condition(sigma_key, val)
        parts.append(frag)
        all_notes.extend(notes)

    if not parts:
        return "*", all_notes
    if len(parts) == 1:
        return parts[0], all_notes
    # AND all field conditions; each wrapped in parens for clarity
    return " AND ".join(f"({p})" for p in parts), all_notes


def _apply_condition(condition: str, selection_kqls: dict[str, str]) -> str:
    """
    Replace Sigma selection names with their KQL fragments and translate
    boolean operators (and/or/not → AND/OR/NOT).

    Sort by descending name length to avoid short names matching inside longer ones.
    """
    result = condition
    for name, kql in sorted(selection_kqls.items(), key=lambda x: -len(x[0])):
        # Use a lambda replacement so re.sub doesn't process backslashes in kql
        # (re.sub treats \\ in string replacements as an escape, halving backslash counts).
        _repl = f"({kql})"
        result = re.sub(rf"\b{re.escape(name)}\b", lambda _, r=_repl: r, result)
    # Translate sigma boolean ops (case-insensitive, whole-word only)
    result = re.sub(r"\band\b", "AND", result, flags=re.IGNORECASE)
    result = re.sub(r"\bor\b",  "OR",  result, flags=re.IGNORECASE)
    result = re.sub(r"\bnot\b", "NOT", result, flags=re.IGNORECASE)
    return result


def _sigma_detection_to_kql(detection_block: dict) -> tuple[str, list[str]]:
    """
    Convert a parsed Sigma `detection:` block into a KQL query string.
    Returns (kql_query, notes).
    """
    condition = detection_block.get("condition", "")
    notes: list[str] = []
    selection_kqls: dict[str, str] = {}

    for name, value in detection_block.items():
        if name == "condition":
            continue
        if isinstance(value, dict):
            kql_frag, sel_notes = _selection_to_kql(value)
            selection_kqls[name] = kql_frag
            notes.extend(sel_notes)
        elif isinstance(value, list):
            # Keyword list (any of these words in any field)
            clauses = [f'* : *{_kql_escape(str(v))}*' for v in value]
            selection_kqls[name] = "(" + " OR ".join(clauses) + ")"
        # scalar (unusual) — treat as keyword
        elif value is not None:
            selection_kqls[name] = f'* : *{_kql_escape(str(value))}*'

    if not condition:
        # No explicit condition — AND everything together
        kql = " AND ".join(f"({v})" for v in selection_kqls.values())
        return kql or "*", notes

    return _apply_condition(condition, selection_kqls), notes


# ── MITRE threat[] builder ─────────────────────────────────────────────────────

def _parse_mitre_from_tags(
    tags: list,
) -> tuple[list[dict], list[str], list[str]]:
    """
    Parse MITRE ATT&CK tactic + technique references from Sigma tags.

    Returns:
        threat_list   — Kibana threat[] (tactic level only; see note below)
        technique_ids — ["T1059.001", …] for the rule's tags array
        tactic_keys   — ["execution", …] for the rule's tags array

    Kibana's threat[].technique requires id+name+reference; technique names
    aren't available without a full MITRE lookup table, so techniques are
    placed in the rule's tags instead.  A future enhancement using the MITRE
    STIX data bundle or pySigma can fill in the name field and move them into
    threat[].technique.
    """
    seen_tactics: dict[str, dict] = {}   # MITRE ID → tactic dict (dedup)
    technique_ids: list[str]      = []
    tactic_keys:   list[str]      = []

    for tag in tags:
        if not isinstance(tag, str) or not tag.startswith("attack."):
            continue
        val = tag[7:]  # strip "attack."

        # Technique ID: starts with "t" followed by digits/dots
        if val and val[0] == "t" and len(val) > 1 and val[1].isdigit():
            technique_ids.append(val.upper())  # T1059.001
            continue

        # Tactic name tag
        tac_key = val.lower().replace("-", "_")
        tactic_keys.append(tac_key)
        if tac_key in _TACTIC_MAP:
            tac_id, tac_name = _TACTIC_MAP[tac_key]
            if tac_id not in seen_tactics:
                seen_tactics[tac_id] = {
                    "framework": "MITRE ATT&CK",
                    "tactic": {
                        "id":        tac_id,
                        "name":      tac_name,
                        "reference": f"https://attack.mitre.org/tactics/{tac_id}/",
                    },
                }

    return list(seen_tactics.values()), technique_ids, tactic_keys


# ── per-rule payload builder ───────────────────────────────────────────────────

def _sigma_rule_to_kibana_payload(
    sr:      dict,
    case_id: str,
    family:  str,
) -> tuple[dict, list[str]]:
    """
    Convert one Sigma rule dict (with a "rule" key containing YAML text) to a
    Kibana Detections API rule creation payload.

    Returns (payload, translation_notes).
    """
    rule_yaml = (sr.get("rule") or sr.get("sigma_yaml") or "").strip()
    rule_yaml = repair_sigma_rule(rule_yaml)
    parsed: dict = yaml.safe_load(rule_yaml) if rule_yaml else {}
    if not isinstance(parsed, dict):
        parsed = {}

    title       = (parsed.get("title") or sr.get("name") or "Unnamed rule").strip()
    description = parsed.get("description") or title
    if isinstance(description, str):
        description = description.strip()
    else:
        description = str(description).strip()

    level              = (parsed.get("level") or "medium").lower()
    severity, risk_sc  = _LEVEL_MAP.get(level, ("medium", 47))
    tags_raw: list     = parsed.get("tags") or []
    references_raw     = parsed.get("references") or []

    # MITRE
    threat, technique_ids, tactic_keys = _parse_mitre_from_tags(tags_raw)

    # Rule tags
    rule_tags = list(filter(None, [
        "malware-pipeline",
        case_id,
        f"family:{family}" if family else None,
    ]))
    rule_tags.extend(technique_ids)   # T1059.001, T1547.001, …
    rule_tags.extend(tactic_keys)     # execution, persistence, …

    # Translate Sigma detection block → KQL
    detection_block = parsed.get("detection") or {}
    kql_query, notes = _sigma_detection_to_kql(detection_block)
    if not kql_query:
        kql_query = "*"
        notes.append("empty detection block — using catch-all query (*)")

    # Index patterns (logsource-specific extras first)
    logsource = parsed.get("logsource") or {}
    category  = logsource.get("category", "")
    index_patterns = _CATEGORY_EXTRA.get(category, []) + _BASE_INDICES

    # Stable rule_id — same case_id + title always → same UUID → re-runs are idempotent
    rule_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"malware-pipeline:{case_id}:{title}"))

    # Only include http:// references (skip case-internal refs)
    references = [r for r in references_raw if isinstance(r, str) and r.startswith("http")]

    payload: dict[str, Any] = {
        "name":        title,
        "description": description,
        "type":        "query",
        "query":       kql_query,
        "language":    "kuery",
        "index":       index_patterns,
        "severity":    severity,
        "risk_score":  risk_sc,
        "enabled":     True,
        "rule_id":     rule_id,
        "tags":        rule_tags,
        "from":        "now-3650d",
        "interval":    "5m",
    }
    if threat:
        payload["threat"] = threat
    if references:
        payload["references"] = references

    return payload, notes


# ── Part B public entry point ──────────────────────────────────────────────────

def push_sigma_rules(
    detection:   dict,
    sample_meta: dict,
    case_id:     str,
) -> dict:
    """
    Push each Sigma rule in *detection* to Kibana as a custom-query detection rule.

    One API call per rule.  Per-rule isolation: a failure on one rule does not
    abort the others.  Duplicate rule_ids (409) are recorded as "already_exists"
    and counted as skipped, not failures.

    Parameters
    ----------
    detection:
        The detection block from the case file. Must contain "sigma_rules".
    sample_meta:
        {"name": str, "sha256": str, "route": str, …}
    case_id:
        Pipeline case identifier embedded in rule tags and the stable rule_id.

    Returns
    -------
    dict
        {
          "rules_total":   int,
          "rules_created": int,
          "rules_skipped": int,   # already_exists (409)
          "rules_failed":  int,
          "per_rule":      list[dict],
        }
    """
    sigma_rules = detection.get("sigma_rules") or []
    family      = detection.get("malware_family") or detection.get("family") or ""

    summary: dict[str, Any] = {
        "rules_total":   len(sigma_rules),
        "rules_created": 0,
        "rules_skipped": 0,
        "rules_failed":  0,
        "per_rule":      [],
    }

    kibana_base = settings.kibana_url.rstrip("/")
    rules_url   = f"{kibana_base}/api/detection_engine/rules"
    headers     = _kibana_headers()

    for sr in sigma_rules:
        name = sr.get("name") or "unnamed"

        # Translate Sigma → Kibana payload
        try:
            payload, notes = _sigma_rule_to_kibana_payload(sr, case_id, family)
        except Exception as exc:
            summary["rules_failed"] += 1
            summary["per_rule"].append({
                "name":               name,
                "status":             "translation_error",
                "error":              str(exc),
                "translation_notes":  [],
            })
            continue

        # POST to Kibana
        code, response = _post(rules_url, json.dumps(payload), headers)

        per = {"name": name, "translation_notes": notes}

        if code in (200, 201):
            summary["rules_created"] += 1
            kibana_id = response.get("id") if isinstance(response, dict) else None
            per.update({"status": "created", "kibana_id": kibana_id,
                        "rule_id": payload["rule_id"]})

        elif code == 409:
            summary["rules_skipped"] += 1
            per.update({"status": "already_exists", "rule_id": payload["rule_id"]})

        elif code == -1:
            summary["rules_failed"] += 1
            per.update({"status": "error", "http": code,
                        "error": f"Transport error: {response}"})

        else:
            summary["rules_failed"] += 1
            err_detail = (
                response.get("message", str(response)[:400])
                if isinstance(response, dict)
                else str(response)[:400]
            )
            per.update({"status": "error", "http": code, "error": err_detail})

        summary["per_rule"].append(per)

    return summary


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    import sys
    from pathlib import Path

    parser = argparse.ArgumentParser(
        description=(
            "Elastic push — Part A (IOCs) and Part B (Sigma rules).\n"
            "Default (no flag): index IOCs.  Use --rules to push Sigma rules instead."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Index IOCs (default)\n"
            "  python -m backend.app.services.elastic_push \\\n"
            "      --case test_fixtures/agenttesla_full.json\n\n"
            "  # Push Sigma rules to Kibana\n"
            "  python -m backend.app.services.elastic_push \\\n"
            "      --case test_fixtures/agenttesla_full.json --rules\n"
        ),
    )
    parser.add_argument("--case", metavar="PATH", required=True,
                        help="Path to a saved case JSON file.")
    parser.add_argument("--index", metavar="NAME", default=IOC_INDEX,
                        help=f"ES index for IOCs (default: {IOC_INDEX}).")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--iocs",  action="store_true",
                      help="Index IOCs into Elasticsearch (default).")
    mode.add_argument("--rules", action="store_true",
                      help="Push Sigma rules to Kibana Detections API.")
    args = parser.parse_args()

    # Default to IOC indexing
    do_rules = args.rules
    do_iocs  = not do_rules or args.iocs

    # Pre-flight: credentials
    required_creds = [("ELASTIC_URL", settings.elastic_url),
                      ("ELASTIC_API_KEY", settings.elastic_api_key)]
    if do_rules:
        required_creds.append(("KIBANA_URL", settings.kibana_url))

    missing = [k for k, v in required_creds if not v]
    if missing:
        print(f"[!] Missing in .env: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    case_path = Path(args.case)
    if not case_path.exists():
        print(f"[!] File not found: {case_path}", file=sys.stderr)
        sys.exit(1)

    try:
        case = json.loads(case_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"[!] Invalid JSON: {exc}", file=sys.stderr)
        sys.exit(1)

    detection = case.get("detection") or {}
    if not detection:
        print("[!] Case has no detection block — run enrich_fixture first.", file=sys.stderr)
        sys.exit(1)

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
    case_id = case.get("case_id", case_path.stem)

    print(f"[*] Case: {case_id}", file=sys.stderr)

    exit_code = 0

    # ── Part A: IOC indexing ────────────────────────────────────────────────
    if do_iocs:
        ioc_list = detection.get("iocs") or []
        print(f"[*] IOCs:     {len(ioc_list)} found in detection block", file=sys.stderr)
        print(f"[*] ES index: {args.index}", file=sys.stderr)
        print(f"[*] ES URL:   {settings.elastic_url}", file=sys.stderr)
        print("", file=sys.stderr)

        ioc_result = index_iocs(detection, sample_meta, case_id, index=args.index)
        print(json.dumps(ioc_result, indent=2))

        if ioc_result["errors"]:
            print(f"\n[!] {len(ioc_result['errors'])} IOC error(s):", file=sys.stderr)
            for e in ioc_result["errors"]:
                print(f"    {e}", file=sys.stderr)
            exit_code = 1
        else:
            print(
                f"\n[+] {ioc_result['iocs_indexed']}/{ioc_result['iocs_total']} IOCs "
                f"indexed into '{ioc_result['index']}'",
                file=sys.stderr,
            )

    # ── Part B: Sigma rules ─────────────────────────────────────────────────
    if do_rules:
        sigma_list = detection.get("sigma_rules") or []
        print(f"[*] Sigma rules: {len(sigma_list)} found", file=sys.stderr)
        print(f"[*] Kibana URL:  {settings.kibana_url}", file=sys.stderr)
        print("", file=sys.stderr)

        rules_result = push_sigma_rules(detection, sample_meta, case_id)
        print(json.dumps(rules_result, indent=2))

        if rules_result["rules_failed"]:
            print(
                f"\n[!] {rules_result['rules_failed']} rule(s) failed.",
                file=sys.stderr,
            )
            for pr in rules_result["per_rule"]:
                if pr.get("status") not in ("created", "already_exists"):
                    print(f"    {pr['name']}: {pr.get('error','?')}", file=sys.stderr)
            exit_code = 1
        else:
            print(
                f"\n[+] {rules_result['rules_created']} created  "
                f"{rules_result['rules_skipped']} already existed  "
                f"(total {rules_result['rules_total']})",
                file=sys.stderr,
            )

    sys.exit(exit_code)
