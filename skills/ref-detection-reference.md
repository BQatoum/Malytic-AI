# Detection Engineering Reference

Templates and rubrics so detection output stays consistent and high-quality across cases. You know
the rule languages; use this to standardize format, scoring, and defanging.

## Table of contents
- Defanging rules
- Confidence + volatility rubric
- YARA template
- Sigma template
- Suricata template
- STIX 2.1 bundle structure

---

## Defanging rules
Apply to all human-facing indicators (case-file display fields, report, sharing). Keep the original
real value only for rule logic and STIX.

| Original | Defanged |
|---|---|
| http / https | hxxp / hxxps |
| . (in domain/IP) | [.] |
| @ | [@] |
| :// | [://] |
| Example: http://bad.com/x | hxxp://bad[.]com/x |
| Example: 192.168.1.10 | 192.168.1[.]10 |
| Example: user@evil.com | user[@]evil[.]com |

## Confidence + volatility rubric
Score every IOC on both axes.

**Confidence (is it malicious?):**
- High — multiple reliable sources/phases agree it's malicious (e.g., the sample's own SHA256;
  a C2 confirmed in dynamic + flagged in OSINT).
- Medium — supported but with gaps (e.g., a domain seen in strings, not yet confirmed live).
- Low — suggestive only (e.g., a shared-hosting IP that may also serve benign sites).

**Volatility (how fast does it go stale?):**
- Low (durable) — file hashes, unique mutex names, distinctive PDB paths.
- Medium — domains, URLs (can be re-registered or moved).
- High (ephemeral) — IPs (rotate frequently), ports, auto-generated/DGA artifacts.

Best detection anchors = high confidence + low volatility.

## YARA template
```yara
rule FamilyName_Variant_Descriptor
{
    meta:
        description = "Detects <family> based on <what>"
        author      = "<analyst/pipeline>"
        date        = "<YYYY-MM-DD>"
        hash        = "<sha256 reference>"
        family      = "<family>"
        reference   = "<internal case / report id>"
    strings:
        $s1 = "distinctive_string_1" ascii wide
        $s2 = "distinctive_string_2" ascii
        $hex1 = { 6A 40 68 00 30 00 00 }      // characteristic byte sequence
    condition:
        uint16(0) == 0x5A4D and              // PE file
        filesize < 2MB and
        2 of ($s*) and $hex1
}
```
Guidance: prefer decoded/config strings the author hid; combine string matches with structural
conditions (magic, filesize, sections) so the rule won't match benign files; avoid a single generic
string as the whole condition.
**String reference rule (YARA spec):** every `$identifier` defined in `strings:` MUST appear in
`condition:`, or the rule will not compile. Canonical safe patterns:
- `all of them` — references every defined string
- `uint16(0) == 0x5A4D and all of them` — PE + all strings (preferred for PE rules)
- `all of ($s*)` — wildcard covering every `$s...` identifier
To store an informational string without referencing it, prefix with underscore: `$_note = "..."` —
YARA exempts underscore-prefixed identifiers from the reference requirement.

## Sigma template
```yaml
title: <Behavior> by <Family>
id: <uuid>
status: experimental
description: Detects <behavior> observed in <family>
references:
    - <internal case / report id>
author: <analyst/pipeline>
date: <YYYY/MM/DD>
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\<process>.exe'
        CommandLine|contains:
            - '<distinctive arg 1>'
            - '<distinctive arg 2>'
    condition: selection
falsepositives:
    - <known benign cause, if any>
level: high
tags:
    - attack.<tactic>
    - attack.t<technique_id>
```
Guidance: use precise fields; combine criteria to cut noise; choose the right `logsource.category`
(process_creation, network_connection, registry_set, file_event); tag the ATT&CK technique.
**YAML safety:** `title` and `description` values that contain a colon-space (`: `) MUST be
quoted — e.g. `description: "Detects Snake/404-Keylogger lineage: DNS resolution of …"`.
An unquoted `: ` inside a plain scalar breaks YAML parsing.

## Suricata template
```
alert http any any -> any any (msg:"<FAMILY> C2 Check-in"; \
  flow:established,to_server; \
  http.method; content:"POST"; \
  http.uri; content:"<distinctive_uri>"; \
  http.user_agent; content:"<distinctive_ua>"; \
  classtype:trojan-activity; \
  reference:url,<internal>; \
  sid:<unique_sid>; rev:1;)
```
Guidance: anchor on durable traffic traits (URI pattern, User-Agent, TLS/JA3, DNS pattern), not a
single IP that rotates; always include msg, sid, rev, reference; pick a sid in your private range.

## STIX 2.1 bundle structure
> Integration note: **Elastic is the primary integration target.** In Phase 7 the scored IOCs are
> indexed into Elasticsearch (use ECS `threat.*` fields so Elastic's indicator-match detection can
> use them), and the Sigma rules from this phase convert directly into Elastic detection rules (via
> the pySigma Elasticsearch backend or Elastic Security's built-in Sigma import) loaded through the
> Kibana Detections API. The STIX bundle below is an **optional portable export** for sharing, not
> the integration mechanism — produce it when useful.

Real indicator values stay intact inside STIX (machines consume it). Minimal shape:
```json
{
  "type": "bundle",
  "id": "bundle--<uuid>",
  "objects": [
    { "type": "malware", "id": "malware--<uuid>", "spec_version": "2.1",
      "name": "<family>", "is_family": false,
      "created": "<ts>", "modified": "<ts>" },
    { "type": "indicator", "id": "indicator--<uuid>", "spec_version": "2.1",
      "name": "<ioc name>", "pattern_type": "stix",
      "pattern": "[file:hashes.'SHA-256' = '<sha256>']",
      "valid_from": "<ts>", "created": "<ts>", "modified": "<ts>" },
    { "type": "attack-pattern", "id": "attack-pattern--<uuid>", "spec_version": "2.1",
      "name": "<technique name>",
      "external_references": [
        { "source_name": "mitre-attack", "external_id": "T<id>" } ] },
    { "type": "relationship", "id": "relationship--<uuid>", "spec_version": "2.1",
      "relationship_type": "indicates",
      "source_ref": "indicator--<uuid>", "target_ref": "malware--<uuid>" },
    { "type": "relationship", "id": "relationship--<uuid>", "spec_version": "2.1",
      "relationship_type": "uses",
      "source_ref": "malware--<uuid>", "target_ref": "attack-pattern--<uuid>" }
  ]
}
```
Common STIX pattern examples:
- File hash:  `[file:hashes.'SHA-256' = '<sha256>']`
- IPv4:       `[ipv4-addr:value = '<ip>']`
- Domain:     `[domain-name:value = '<domain>']`
- URL:        `[url:value = '<url>']`
- Mutex:      `[mutex:name = '<mutex>']`

Add Threat-Actor and Campaign SDOs (and attributed-to / uses relationships) only when attribution
confidence supports it.
