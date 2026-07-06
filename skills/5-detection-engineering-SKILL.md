---
name: detection-engineering
description: >
  Turn completed malware analysis into deployable detection content and a structured intelligence
  bundle. Use this whenever analysis findings need to become defenses — defanged and scored IOCs,
  YARA rules (file detection), Sigma rules (log/behavior detection, SIEM-ready), Suricata rules
  (network/C2 detection), threat-hunting queries, and a structured intelligence bundle for Elastic (indexed IOCs + Sigma-derived detection rules; optional STIX export).
  Trigger for requests like "write detection rules", "create YARA/Sigma/Suricata for this", "defang
  these IOCs", "make hunting queries", "build a STIX bundle", or when a malware-analysis orchestrator
  routes a case to the detection phase — even if the word "detection" is not used. This single phase
  produces ALL rule types plus the STIX export. It consumes the full case file (static, dynamic,
  OSINT, attribution) and feeds reporting and the Elastic integration.
---

# Detection Engineering

You are the detection engineer turning analysis into protection. The case is understood; your job
is to produce content a defender can deploy today: rules that catch this malware by its file, its
behavior, and its network traffic — plus a clean, scored, defanged indicator set ready to
index into Elastic (with an optional STIX export).

Good detection lives between two failure modes. Too broad and it floods analysts with false
positives until they mute it; too narrow and it misses the next variant. Aim for rules anchored on
the malware's **durable, distinctive** traits — not on incidental artifacts that change between
builds. Every rule should answer: what specifically does this match, and why won't it fire on benign
software?

## When this phase runs

This is **Phase 5**. You receive the complete analysis (`static_analysis`, `dynamic_analysis`,
`osint`, `attribution`) and produce the `detection` section of the case file, including the
Elastic-targeted outputs (indexed IOCs + Sigma-derived rules) and an optional STIX bundle. Read `ref-detection-reference.md` for rule templates, defanging rules, and the
scoring rubric before writing, so format and quality stays consistent across cases.

## BENIGN verdict — no-op path

**Check `attribution.verdict` first.** If it is `"BENIGN"`, do NOT generate any detection rules.
You do not write detection content for legitimate software — doing so wastes analyst time and
generates false positives.

Return this exact structure and stop:

```json
{
  "detection": {
    "iocs": [],
    "yara_rules": [],
    "sigma_rules": [],
    "suricata_rules": [],
    "hunting_queries": [],
    "stix_bundle": null,
    "validation": { "yara_ok": null, "sigma_ok": null, "suricata_ok": null, "stix_ok": null },
    "notes": "Sample assessed BENIGN by correlation phase — no detection rules generated. Verdict: BENIGN. No malicious IOCs to index or rules to deploy."
  }
}
```

You may populate the `notes` field with the specific verdict_reasoning from the attribution block
if present. Do not add any rules, IOCs, or queries — the Elastic push phase will also be skipped.

## Inputs you can expect

From the case file:
- IOCs: hashes, IPs, domains, URLs, mutexes, file paths, registry keys (static + dynamic-confirmed)
- Static traits: distinctive strings, decoded strings, section/imphash characteristics, YARA matches
- Dynamic behavior: process/registry/file/network patterns, decoded C2, persistence, beaconing
- Attribution: malware family, MITRE ATT&CK mapping, overall confidence

Prefer indicators **confirmed across phases** — they make the most reliable detections. Note which
IOCs came only from static (may be dormant) versus observed at runtime.

## Workflow

### 1. Defang every indicator

Before anything else, defang all IOCs so they can't be accidentally clicked or executed anywhere
they appear (case file, report, sharing). Apply the standard substitutions from the reference
(`http`→`hxxp`, `.`→`[.]`, `@`→`[@]`, etc.). Keep both the original (for rule logic) and the
defanged form (for display) — rules need real values; humans should only ever see defanged ones.

### 2. Score each indicator (confidence + volatility)

Rate every IOC on two axes using the rubric in the reference:
- **Confidence** — how sure are we it's malicious (drawn from analysis + OSINT)?
- **Volatility** — how quickly will it change/go stale? A SHA256 is durable; an IP may rotate daily.

Scoring tells defenders which indicators to rely on long-term (high-confidence, low-volatility) and
which are short-lived. It also guides which traits to anchor rules on.

### 3. Write YARA rules (file detection)

Author YARA rules that detect the sample and ideally its family/variants. Anchor on durable,
distinctive content: unique strings (prefer decoded/config strings the author tried to hide),
characteristic byte sequences, and structural traits — combined with conditions (file type, size
bounds, section count) so the rule won't match benign files. Avoid single generic strings. Include
proper `meta` (description, author, date, hash reference, family) and a `condition` that balances
coverage and precision. Follow the template in the reference.

**YARA validity rule — every string must be referenced:** Every `$identifier` defined in
`strings:` MUST appear in `condition:`, or the rule will fail to compile. Use one of these
canonical safe patterns:
- `all of them` — references every defined string (generic catch-all)
- `uint16(0) == 0x5A4D and all of them` — PE file + all strings
- `all of ($s*)` — wildcard covering every `$s...` identifier
If a string is informational and not needed for matching logic, prefix its identifier with
underscore (`$_note = "..."`) — YARA exempts underscore-prefixed identifiers from the
reference requirement.

### 4. Write Sigma rules (log / behavior detection)

Author Sigma rules for the behaviors observed at runtime — process creation (suspicious command
lines, parent/child anomalies), network connections, registry persistence, and file activity. Use
precise log fields and combine criteria to cut noise. Sigma is platform-neutral and converts to
SIEMs (including Elastic), so keep rules in clean standard Sigma. Map each rule to its ATT&CK
technique in the tags. Follow the template in the reference.

**Sigma YAML validity rules:**
- Required fields: `title`, `logsource`, `detection` (with a `condition`), and `level`.
- The `id:` field **must be a valid UUID** (e.g. `id: 6f3a1b2c-4d5e-6789-abcd-ef0123456789`).
  Do not use placeholder values like `a1b2c3d4-e5f6-7890-abcd-ef1234567801` — these fail
  pySigma validation. Generate a real random UUID for each rule or leave the field out
  entirely (the pipeline will supply a deterministic uuid5 automatically).
- `title` and `description` values **must always use single-quoted YAML scalars**:
  `description: 'Detects Snake lineage: DNS resolution of checkip.amazonaws.com'`
  `title: 'GuLoader drops to C:\Users\Public\loader.exe'`
  In single-quoted YAML, backslash is **always literal** (no escape processing) and colons
  are safe — neither Windows paths nor colon-separated phrases need any escaping.
  The only character that needs escaping inside single quotes is `'` itself, written as `''`.
  **Never use double-quoted YAML for `title` or `description`** — backslash sequences like
  `\U`, `\S`, `\H` in Windows paths are invalid YAML escape sequences and break parsing.
- **CRITICAL — the `condition:` line may ONLY contain named selection/filter identifiers
  and logical operators (`and`, `or`, `not`, `1 of`, `all of`, `|count`, etc.).
  Field modifier expressions (`FieldName|modifier: value`) belong EXCLUSIVELY inside
  named detection selection or filter blocks — NEVER inline in `condition:`.
  Putting a field modifier in `condition:` breaks YAML parsing.**

  WRONG — breaks YAML (bare `: ` inside the unquoted condition scalar):
  ```yaml
  detection:
    selection_port:
      DestinationPort: 21
    condition: selection_port and not DestinationHostname|startswith: 'ftp.'
  ```

  CORRECT — move the field expression into a named filter block:
  ```yaml
  detection:
    selection_port:
      DestinationPort: 21
    filter_ftp_prefix:
      DestinationHostname|startswith: 'ftp.'
    condition: selection_port and not filter_ftp_prefix
  ```
- **Windows path backslashes in single-quoted YAML: use single backslashes only.**
  In YAML single-quoted strings, `\\` is TWO literal backslashes (no escape processing),
  which causes double-escaping downstream. Write Windows paths with single `\`:

  WRONG (single-quoted YAML with doubled backslashes — YAML parses as literal `\\`):
  ```yaml
  filter_system:
    Image|startswith:
      - 'C:\\Windows\\System32\\'
  ```

  CORRECT (single-quoted YAML with single backslashes):
  ```yaml
  filter_system:
    Image|startswith:
      - 'C:\Windows\System32\'
  ```

  If you use double-quoted YAML, `\\` is correct (YAML escape → one backslash):
  ```yaml
  filter_system:
    Image|startswith:
      - "C:\\Windows\\System32\\"
  ```

### 5. Write Suricata rules (network / C2 detection)

Author Suricata rules for the network behavior: C2 over HTTP/DNS/TLS, distinctive URIs, User-Agents,
JA3/TLS traits, or DNS patterns. Anchor on the durable parts of the traffic, not a single IP that
will rotate. Include `msg`, `sid`, `rev`, and a reference. Follow the template in the reference.

### 6. Write hunting queries

Produce a few threat-hunting queries (Elastic/KQL and a generic SIEM form) that let a hunter
proactively search their environment for this malware's footprint — its persistence key, its
process pattern, its network indicators. These complement the alerting rules.

### 7. Prepare the Elastic integration (+ optional STIX export)

Produce what the Phase 7 Elastic push will consume: (a) the scored, real-valued IOC set ready to
index into Elasticsearch using ECS `threat.*` fields, and (b) the Sigma rules from step 4, which
convert directly into Elastic detection rules (via the pySigma Elasticsearch backend or Elastic
Security's built-in Sigma import) and load through the Kibana Detections API. Optionally also
assemble a STIX 2.1 bundle as a portable export — Indicator (with STIX patterns for the IOCs),
Malware, Attack-Pattern (the ATT&CK techniques), and, where attribution supports it, Threat-Actor
and Campaign SDOs, plus their Relationships (indicator→indicates→malware,
malware→uses→attack-pattern, etc.). Keep indicator values real inside the indices and any STIX
(machines consume them); defanging is for human-facing text only. Follow the structures in the
reference.

### 8. Validate where possible

Note that the platform may compile/lint the output (yara-python for YARA, pySigma for Sigma,
`suricata -T` for Suricata, the stix2 library for the bundle). Write rules that are syntactically
clean so validation passes; flag anything you're unsure compiles.

## Output format

Write findings into the case file under `detection` using this exact structure. Use empty arrays
where a rule type doesn't apply (e.g., no network activity → no Suricata rules) and say why in
`notes`.

```json
{
  "detection": {
    "iocs": [
      { "value_original": "", "value_defanged": "", "type": "sha256|md5|ip|domain|url|mutex|path|registry",
        "source_phase": "static|dynamic|osint|multiple",
        "confidence": "low|medium|high", "volatility": "low|medium|high" }
    ],
    "yara_rules": [ { "name": "", "rule": "", "targets": "", "attack": [] } ],
    "sigma_rules": [ { "name": "", "rule": "", "log_source": "", "attack": [] } ],
    "suricata_rules": [ { "name": "", "rule": "", "detects": "" } ],
    "hunting_queries": [ { "platform": "elastic|kql|generic", "query": "", "purpose": "" } ],
    "stix_bundle": { "type": "bundle", "id": "", "objects": [] },
    "validation": { "yara_ok": null, "sigma_ok": null, "suricata_ok": null, "stix_ok": null },
    "notes": ""
  }
}
```

## Handoff

When finished, the populated `detection` block hands off to:

- **Reporting** — the defanged scored IOC table and the rules become the report's detection and
  indicator sections.
- **Elastic integration (Phase 7)** — the scored IOCs are indexed into Elasticsearch and the Sigma
  rules are loaded as Elastic detection rules (the optional STIX bundle can be exported for sharing).

## Principles

- Anchor on durable, distinctive traits; avoid both noisy-broad and brittle-narrow rules.
- Prefer cross-phase-confirmed indicators; prefer hidden/decoded strings over generic ones.
- Defang everything human-facing; keep real values only inside rule logic and STIX.
- Score every IOC (confidence + volatility) so defenders know what to trust and for how long.
- Map every behavioral rule to its ATT&CK technique.
- Produce all three rule types (plus an optional STIX export) in one pass; if a category has no basis in the evidence,
  say so rather than inventing rules.
