"""
Rule validation for detection-engineering output.

yara-python  — hard dependency (in requirements.txt); always present.
pySigma      — imported lazily; falls back to structural YAML check if absent.
Suricata     — no Python library available; structural regex check only.
"""
from __future__ import annotations

import re
import uuid


# ── YARA auto-repair ──────────────────────────────────────────────────────────

def repair_yara_rule(rule_text: str) -> str:
    """
    Rename defined-but-unreferenced YARA strings to have a leading underscore
    (e.g. $x → $_x) so the rule compiles without "unreferenced string" errors.

    YARA spec: every string defined in strings: MUST be referenced in
    condition:, EXCEPT identifiers starting with underscore, which are exempt.

    Handles all reference forms:
      - direct:   $name, #name (count), @name (offset), !name (length)
      - wildcard: all/any of ($prefix*)
      - keyword:  them  (references all strings — no repair needed)
    """
    strings_match = re.search(r'\bstrings\s*:(.*?)\bcondition\s*:', rule_text, re.DOTALL)
    cond_match    = re.search(r'\bcondition\s*:(.*?)(?=\s*\})', rule_text, re.DOTALL)
    if not strings_match or not cond_match:
        return rule_text

    strings_section = strings_match.group(1)
    condition_text  = cond_match.group(1)

    defined_bare = set(re.findall(r'^\s*\$(\w+)\s*=', strings_section, re.MULTILINE))

    # "them" keyword → every defined string is implicitly referenced
    if re.search(r'\bthem\b', condition_text):
        return rule_text

    directly_referenced = set(re.findall(r'[$#@!](\w+)', condition_text))
    wildcard_prefixes   = re.findall(r'\(\$(\w*)\*\)', condition_text)

    def _is_referenced(bare: str) -> bool:
        if bare in directly_referenced:
            return True
        return any(bare.startswith(pfx) for pfx in wildcard_prefixes)

    unreferenced = {b for b in defined_bare if not _is_referenced(b) and not b.startswith('_')}
    if not unreferenced:
        return rule_text

    repaired = strings_section
    for bare in unreferenced:
        repaired = re.sub(
            r'(\$)(' + re.escape(bare) + r')(\s*=)',
            r'$_\2\3',
            repaired,
        )

    return (
        rule_text[:strings_match.start(1)]
        + repaired
        + rule_text[strings_match.end(1):]
    )


# ── Sigma auto-repair ─────────────────────────────────────────────────────────

# Matches Field|modifier: value expressions — single-quoted, double-quoted, or
# unquoted (stops before whitespace and closing parenthesis).
_INLINE_MODIFIER_RE = re.compile(
    r"(\w+\|\w+)\s*:\s*('[^']*'|\"[^\"]*\"|[^\s),]+)"
)


def _to_single_quoted_yaml(value: str) -> str:
    """
    Normalize a free-text value to a safe single-quoted YAML scalar.

    In single-quoted YAML scalars, backslash is *never* an escape character —
    it is always literal.  This means Windows paths (C:\\Users\\Public) and
    colons are both safe without any special treatment.  The only character that
    needs escaping inside a single-quoted scalar is the single quote itself,
    which is represented by doubling it ('').

    Handles any input form:
      - unquoted          →  single-quote and escape embedded '
      - double-quoted     →  strip outer "", then single-quote
      - single-quoted     →  strip outer '', restore '', re-escape and re-wrap
    """
    v = value.strip()
    if len(v) >= 2:
        if v[0] == '"' and v[-1] == '"':
            # Strip double quotes without deep YAML-unescape — raw content is
            # what we want; any \" inside becomes a literal " which is fine.
            v = v[1:-1].replace('\\"', '"')
        elif v[0] == "'" and v[-1] == "'":
            # Restore '' → ' so we re-escape correctly below
            v = v[1:-1].replace("''", "'")
    # Escape embedded single quotes for single-quoted YAML
    v = v.replace("'", "''")
    return f"'{v}'"


def _repair_colon_scalars(rule_yaml: str) -> str:
    """
    Normalize title/description values to single-quoted YAML scalars.

    Single-quoted scalars treat backslash as literal (no escape processing at
    all), so Windows paths like C:\\Users\\Public and colon-containing text are
    both safe without any special escaping.  Replaces the previous approach of
    wrapping in double-quoted scalars, which broke for \\U \\S \\H etc.

    Handles values that are currently unquoted, double-quoted (the problem case),
    or already single-quoted — all are normalised uniformly.
    """
    def _normalize(m: re.Match) -> str:
        key   = m.group(1)
        value = m.group(2).strip()
        return f'{key}: {_to_single_quoted_yaml(value)}'

    return re.sub(
        r'^(title|description):\s+(.+)$',
        _normalize,
        rule_yaml,
        flags=re.MULTILINE,
    )


def _find_detection_indent(rule_yaml: str) -> str:
    """Return the indentation string used for direct children of 'detection:'."""
    in_detection = False
    for line in rule_yaml.splitlines():
        stripped = line.lstrip()
        if not stripped:
            continue
        if re.match(r'detection\s*:', stripped):
            in_detection = True
            continue
        if in_detection:
            return re.match(r'^(\s*)', line).group(1)
    return '    '


def _repair_inline_condition_modifiers(rule_yaml: str) -> str:
    """
    Repair Sigma rules where Field|modifier: value expressions appear inline
    in the condition: line.

    Sigma spec: the condition: line may ONLY contain named selection/filter
    identifiers and logical operators (and, or, not, 1 of, all of, |count…).
    Field modifier expressions belong EXCLUSIVELY in named detection blocks.

    This repair:
      1. Finds each Field|modifier: value expression in the condition: line.
      2. Creates a named filter_inline_N block for it inside detection:.
      3. Injects that block before the condition: line.
      4. Replaces the inline expression in the condition with the block name.

    Example — before:
      detection:
        selection_port:
          DestinationPort: 21
        condition: selection_port and not DestinationHostname|startswith: 'ftp.'

    After:
      detection:
        selection_port:
          DestinationPort: 21
        filter_inline_0:
          DestinationHostname|startswith: 'ftp.'
        condition: selection_port and not filter_inline_0
    """
    cond_m = re.search(r'^(\s*condition:\s*)(.+)$', rule_yaml, re.MULTILINE)
    if not cond_m:
        return rule_yaml

    condition_value = cond_m.group(2)
    if not _INLINE_MODIFIER_RE.search(condition_value):
        return rule_yaml  # nothing to repair

    indent       = _find_detection_indent(rule_yaml)
    field_indent = indent + '    '
    counter: list[int] = [0]
    new_blocks: dict[str, str] = {}

    def _extract(m: re.Match) -> str:
        name = f'filter_inline_{counter[0]}'
        counter[0] += 1
        new_blocks[name] = (
            f'{indent}{name}:\n'
            f'{field_indent}{m.group(1)}: {m.group(2)}'
        )
        return name

    new_condition = _INLINE_MODIFIER_RE.sub(_extract, condition_value)

    if not new_blocks:
        return rule_yaml

    injected     = '\n'.join(new_blocks.values()) + '\n'
    original_line = cond_m.group(0)
    new_line      = cond_m.group(1) + new_condition
    return rule_yaml.replace(original_line, injected + new_line)


_SIGMA_UUID_NS = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # NAMESPACE_DNS

_ID_LINE_RE    = re.compile(r"^([ \t]*id[ \t]*:[ \t]*)(.*)$", re.MULTILINE)
_TITLE_LINE_RE = re.compile(r"^[ \t]*title[ \t]*:[ \t]*(.+)$", re.MULTILINE)


def _ensure_sigma_uuid(rule_yaml: str) -> str:
    """Pass 3 — guarantee the Sigma `id:` field contains a valid UUID.

    If the existing value already parses as a UUID, it is kept unchanged.
    Otherwise (missing, placeholder, or malformed) a deterministic UUID is
    generated from the rule's `title:` field using uuid5 so the same rule
    always maps to the same id across pipeline runs (preserving Elastic dedup).
    """
    id_m = _ID_LINE_RE.search(rule_yaml)
    if id_m:
        candidate = id_m.group(2).strip().strip('"\'')
        try:
            uuid.UUID(candidate)
            return rule_yaml  # already valid — nothing to do
        except ValueError:
            pass  # fall through to replacement

    # Derive a stable seed from the title (or a fixed fallback).
    title_m = _TITLE_LINE_RE.search(rule_yaml)
    title   = title_m.group(1).strip().strip('"\'') if title_m else "unknown-sigma-rule"
    new_id  = str(uuid.uuid5(_SIGMA_UUID_NS, f"malware-pipeline:sigma:{title}"))

    if id_m:
        # Replace the existing (invalid) id: line.
        rule_yaml = rule_yaml[:id_m.start(2)] + new_id + rule_yaml[id_m.end(2):]
    else:
        # Inject id: after the title: line (or at the top if no title).
        inject = f"id: {new_id}\n"
        if title_m:
            insert_pos = title_m.end() + 1  # after the newline following title
            rule_yaml  = rule_yaml[:insert_pos] + inject + rule_yaml[insert_pos:]
        else:
            rule_yaml = inject + rule_yaml
    return rule_yaml


def repair_sigma_rule(rule_yaml: str) -> str:
    """
    Auto-repair common Sigma YAML generation errors before yaml.safe_load.

    Pass 1 — colon scalars:    quote title/description values containing ': '.
    Pass 2 — inline modifiers: move Field|modifier: value expressions out of the
                                condition: line and into named filter blocks.
    Pass 3 — UUID id field:    ensure id: contains a valid UUID; generate a
                                deterministic uuid5 from the title if not.
    """
    rule_yaml = _repair_colon_scalars(rule_yaml)
    rule_yaml = _repair_inline_condition_modifiers(rule_yaml)
    rule_yaml = _ensure_sigma_uuid(rule_yaml)
    return rule_yaml


# ── YARA ──────────────────────────────────────────────────────────────────────

def validate_yara(rule_text: str) -> dict:
    """
    Compile *rule_text* with yara-python.

    Returns
    -------
    {"valid": bool, "error": str | None}
    """
    try:
        import yara
        yara.compile(source=rule_text)
        return {"valid": True, "error": None}
    except Exception as exc:
        return {"valid": False, "error": str(exc)}


# ── Sigma ─────────────────────────────────────────────────────────────────────

def _validate_sigma_structural(rule_yaml: str) -> dict:
    """
    Fallback used when pySigma is not installed.
    Checks YAML parses and required top-level keys are present.
    """
    try:
        import yaml
        doc = yaml.safe_load(rule_yaml)
    except Exception as exc:
        return {"valid": False, "error": f"YAML parse error: {exc}", "method": "structural"}

    if not isinstance(doc, dict):
        return {"valid": False, "error": "Rule is not a YAML mapping", "method": "structural"}

    missing = [k for k in ("title", "logsource", "detection") if k not in doc]
    if missing:
        return {
            "valid": False,
            "error": f"Missing required fields: {', '.join(missing)}",
            "method": "structural",
        }
    return {"valid": True, "error": None, "method": "structural"}


def validate_sigma(rule_yaml: str) -> dict:
    """
    Parse *rule_yaml* with pySigma (SigmaCollection.from_yaml).

    Falls back to a structural YAML key-check if pySigma is not installed.

    Returns
    -------
    {"valid": bool, "error": str | None, "method": "pysigma" | "structural"}
    """
    try:
        from sigma.collection import SigmaCollection  # noqa: PLC0415
        SigmaCollection.from_yaml(rule_yaml)
        return {"valid": True, "error": None, "method": "pysigma"}
    except ImportError:
        return _validate_sigma_structural(rule_yaml)
    except Exception as exc:
        return {"valid": False, "error": str(exc), "method": "pysigma"}


# ── Suricata ──────────────────────────────────────────────────────────────────

# Matches the mandatory 7-token header: action proto src_addr src_port -> dst_addr dst_port (
_SURI_HEADER_RE = re.compile(
    r"^\s*(?:alert|pass|drop|reject(?:src|dst|both)?)"   # action
    r"\s+\w+"                                             # protocol
    r"\s+\S+\s+\S+"                                      # src addr  src port
    r"\s+(?:->|<>)\s+"                                   # direction
    r"\s*\S+\s+\S+"                                      # dst addr  dst port
    r"\s*\(",                                             # opening paren
    re.IGNORECASE,
)

_SURI_REQUIRED_OPTS = ("msg:", "sid:", "rev:")


def _check_one_suricata(line: str) -> dict:
    line = line.strip()
    if not line or line.startswith("#"):
        return {"valid": True, "error": None, "method": "structural"}

    if not _SURI_HEADER_RE.match(line):
        return {
            "valid": False,
            "error": (
                "Rule header malformed — expected: "
                "action proto src_addr src_port -> dst_addr dst_port (options)"
            ),
            "method": "structural",
        }

    missing = [kw for kw in _SURI_REQUIRED_OPTS if kw not in line]
    if missing:
        return {
            "valid": False,
            "error": f"Missing required option keywords: {', '.join(missing)}",
            "method": "structural",
        }

    if line.count("(") != line.count(")"):
        return {
            "valid": False,
            "error": "Unbalanced parentheses",
            "method": "structural",
        }

    return {"valid": True, "error": None, "method": "structural"}


def validate_suricata(rule_text: str) -> dict:
    """
    Structurally validate a Suricata rule string (no Python library available).

    Each non-blank non-comment line is treated as one rule; the first failure
    found is returned.  All passing → valid=True.

    Returns
    -------
    {"valid": bool, "error": str | None, "method": "structural"}
    """
    for line in rule_text.splitlines():
        result = _check_one_suricata(line)
        if not result["valid"]:
            return result
    return {"valid": True, "error": None, "method": "structural"}
