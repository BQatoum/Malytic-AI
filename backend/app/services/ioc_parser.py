"""
Parse an internal IOC database (.csv or .json) into a normalized indicator list.

Each entry:
  {"value": str, "type": "ip"|"domain"|"hash"|"url"|"unknown", "tags": dict}

CSV format (expected columns):
  value       — required; the raw indicator string
  type        — optional; inferred from value if missing
  tags        — optional; semicolon-separated k=v pairs (e.g. actor=APT28;campaign=GridIron)
  (any extra columns are also collected as tags)

  Example:
    value,type,tags
    185.220.101.45,ip,actor=APT28;campaign=GridIron2024
    evil-c2.com,domain,actor=Lazarus;date=2025-03-10
    d41d8cd98f00b204e9800998ecf8427e,hash,
    https://malicious.example/drop,url,actor=FIN7

JSON format (list of objects):
  "value" required; "type" optional; everything else becomes tags.

  Example:
    [
      {"value": "185.220.101.45", "type": "ip",     "actor": "APT28"},
      {"value": "evil-c2.com",     "type": "domain", "actor": "Lazarus"},
      {"value": "d41d8cd98f00b204e9800998ecf8427e", "type": "hash"}
    ]

Malformed rows are skipped with a log warning. Completely unparseable → returns [].
"""
from __future__ import annotations

import csv
import io
import json
import logging
import re
from pathlib import Path

log = logging.getLogger(__name__)

_IP_RE     = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
_HASH_RE   = re.compile(r'^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$')
_DOMAIN_RE = re.compile(r'^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$')
_VALID_TYPES = {"ip", "domain", "hash", "url", "unknown"}


def _infer_type(value: str) -> str:
    v = value.strip().lower()
    if _IP_RE.match(v):
        return "ip"
    if _HASH_RE.match(v):
        return "hash"
    vl = v.lstrip("hxxp").lstrip("s").lstrip("://")  # crude defang check
    if v.startswith(("http://", "https://", "hxxp://", "hxxps://")):
        return "url"
    if _DOMAIN_RE.match(v):
        return "domain"
    return "unknown"


def _parse_tags(tags_str: str) -> dict:
    """Parse 'k=v;k=v' tag string into a dict. Bare tokens (no =) are stored as True."""
    out: dict = {}
    for part in tags_str.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, _, v = part.partition("=")
            k, v = k.strip(), v.strip()
            if k:
                out[k] = v
        else:
            out[part] = True
    return out


def _build_entry(value: str, type_hint: str, tags: dict) -> dict:
    value = value.strip()
    t = type_hint.strip().lower()
    ioc_type = t if t in _VALID_TYPES else _infer_type(value)
    return {"value": value, "type": ioc_type, "tags": tags}


def _parse_csv(raw: bytes) -> list[dict]:
    text = raw.decode("utf-8-sig", errors="replace")  # utf-8-sig strips Excel BOM
    reader = csv.DictReader(io.StringIO(text))

    if reader.fieldnames is None:
        log.warning("ioc_parser: CSV appears empty or headerless")
        return []

    results: list[dict] = []
    for i, raw_row in enumerate(reader, start=2):
        row = {(h or "").strip().lower(): (v or "") for h, v in raw_row.items()}

        value = row.get("value", "").strip()
        if not value:
            log.debug("ioc_parser: CSV row %d missing value — skipped", i)
            continue

        type_hint = row.get("type", "")
        tags: dict = {}

        tags_col = row.get("tags", "")
        if tags_col:
            tags.update(_parse_tags(tags_col))
        # Extra columns (not value/type/tags) also become tags
        for k, v in row.items():
            if k not in ("value", "type", "tags") and k and v:
                tags[k] = v

        try:
            results.append(_build_entry(value, type_hint, tags))
        except Exception as exc:
            log.warning("ioc_parser: CSV row %d failed (%s) — skipped", i, exc)

    return results


def _parse_json(raw: bytes) -> list[dict]:
    try:
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        log.error("ioc_parser: JSON decode failed: %s", exc)
        return []

    if not isinstance(data, list):
        log.error("ioc_parser: JSON root must be a list, got %s", type(data).__name__)
        return []

    results: list[dict] = []
    for i, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            log.warning("ioc_parser: JSON item %d is not an object — skipped", i)
            continue
        value = str(item.get("value", "")).strip()
        if not value:
            log.warning("ioc_parser: JSON item %d missing 'value' — skipped", i)
            continue
        type_hint = str(item.get("type", ""))
        tags = {k: v for k, v in item.items() if k not in ("value", "type")}
        try:
            results.append(_build_entry(value, type_hint, tags))
        except Exception as exc:
            log.warning("ioc_parser: JSON item %d failed (%s) — skipped", i, exc)

    return results


def parse_ioc_file(raw: bytes, filename: str) -> list[dict]:
    """
    Parse raw bytes of an IOC database file. Returns a normalized indicator list.
    Never raises — malformed input produces warnings + returns [].
    """
    ext = Path(filename).suffix.lower()
    try:
        if ext == ".csv":
            indicators = _parse_csv(raw)
        elif ext == ".json":
            indicators = _parse_json(raw)
        else:
            log.error("ioc_parser: unsupported extension %r", ext)
            return []
    except Exception as exc:
        log.error("ioc_parser: unexpected error parsing %r: %s", filename, exc)
        return []

    log.info("ioc_parser: parsed %d indicator(s) from %r", len(indicators), filename)
    return indicators
