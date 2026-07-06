# Malware Analysis Report — Template

Fill every placeholder from the case file. Keep all indicators defanged in prose and
tables. If a section has no data (phase failed or did not run), write one honest sentence
saying so — do NOT pad, invent content, or lorem-ipsum. Omit sub-sections only when their
specific data source is genuinely absent.

---

# Malware Analysis Report: {{attribution.family — or short sample file name. NEVER the SHA-256}}

*{{analysis_date}} · Version 1.0 · CONFIDENTIAL*

## 1. Executive Summary

| | |
|---|---|
| **Sample name** | {{file_name}} |
| **SHA-256** | {{sha256}} |
| **MD5** | {{md5}} |
| **SHA-1** | {{sha1}} |
| **File type** | {{true_type from static_analysis}} |
| **Platform** | {{target platform, e.g. Windows x64}} |
| **Analysis date** | {{analysis_date}} |
| **Overall confidence** | {{attribution.overall_confidence}} |

{{2–5 sentences, plain language. What the malware is; how severe; who is at risk; key
symptoms of infection; the single most important recommended action. Must stand alone —
readable by a non-technical manager without reading the rest of the report.}}

## 2. Sample Overview

- **File type:** {{true_type}} ({{size}})
- **First seen (OSINT):** {{osint.reputation.first_seen or "Not found in OSINT"}}
- **Detection rate:** {{osint.reputation.detection_rate or "Not queried"}}
- **Packer / compiler:** {{static_analysis packing finding, or "None detected"}}
- **Container / extraction:** {{if archive: what was inside; otherwise omit this bullet}}

{{One short paragraph describing what the sample is and its role — loader, dropper,
payload, tool, etc. — and the basic capability set at a glance.}}

## 3. Static Analysis Findings

{{Synthesise all static findings into a coherent narrative. Do NOT split into "Basic" and
"Advanced". Cover: file type confirmation and any mismatch with the extension; entropy and
packing indicators (raw vs virtual section sizes, overall entropy value); PE header and
section anomalies; high-risk API groups and what they imply about capability; notable
strings including any you decoded or defanged; the resulting behavior hypothesis. State
confidence and flag any gaps.}}

## 4. Dynamic Analysis Findings

{{Execution timeline narrative — what the sample did in order when run. Cover: process
tree and any injection technique (named precisely with evidence); network behavior
(contacted infrastructure, beaconing interval, decoded C2 content); persistence mechanism
(exact key, path, or service name); memory-recovered config or secrets. If the sandbox
captured little, say so — thin evidence can indicate evasion. If Claude's verdict differed
from the sandbox verdict, state both and explain why.}}

{{Only include the subsection below when screenshot_analysis.include_in_report is true.
Omit it entirely otherwise.}}

### Detonation Screenshots

{{For each frame in report_frames write: "Fig {{N}}: {{caption_text}}" — one line per
frame. The rendering pipeline embeds the actual images; write only the caption text.}}

## 5. OSINT Findings

{{File and hash reputation: VT score, public sandbox hits, first-seen date.
Family intelligence: known capabilities, typical TTPs, associated campaigns from threat
feeds and MITRE/Malpedia.
Infrastructure: WHOIS/ASN data for contacted IPs/domains, passive-DNS history,
co-hosted or related infrastructure.
Actor / campaign intelligence if any — attribute conservatively and with confidence level.
Cite key references in your own words; reproduce only short, attributed quotes if essential.
If OSINT did not run or returned no results, say so plainly.}}

## 6. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| {{tactic}} | {{Txxxx.xxx}} | {{name}} | {{what was observed and in which phase}} | {{low/medium/high}} |

{{Brief paragraph noting the dominant tactic clusters (e.g. heavy focus on Defense Evasion
+ Credential Access) and what that implies about the threat actor's objectives.}}

## 7. Indicators of Compromise

### Network Indicators

| Indicator (defanged) | Type | Source | Confidence | Volatility |
|---|---|---|---|---|
| {{defanged_value}} | ip / domain / url | {{static/dynamic/osint/multiple}} | {{conf}} | {{vol}} |

{{If no network IOCs: "No network indicators were identified in this analysis."}}

### Host-based Indicators

| Indicator (defanged) | Type | Source | Confidence | Volatility |
|---|---|---|---|---|
| {{defanged_value}} | sha256 / md5 / path / registry / mutex | {{source}} | {{conf}} | {{vol}} |

{{If no host-based IOCs: "No host-based indicators were identified in this analysis."}}

## 8. Attribution Assessment

- **Malware family:** {{family}} ({{confidence}}) — {{evidence summary}}
- **Threat actor:** {{actor or "No reliable attribution"}} ({{confidence}}) — {{reasoning;
  alternatives considered; why other actors were ruled out}}
- **Campaign:** {{campaign name or "None identified"}}

**Attack narrative:** {{Readable end-to-end story of how the malware operates, ordered by
kill-chain stage. Each step traceable to specific evidence. Source:
attribution.attack_narrative — expand and make readable rather than just quoting it.}}

## 9. Detection Rules

{{For each rule type, derive the heading label from detection.validation:
  - yara_ok  true  → "YARA — N rules (Validated)"
  - yara_ok  false → "YARA — N rules (Validation failed: M of N rules failed)"
  - yara_ok  null  → omit YARA subsection entirely (no rules were generated)
  - sigma_ok true  → "Sigma — N rules (Validated)"
  - sigma_ok false → "Sigma — N rules (Validation failed: M of N rules failed)"
  - sigma_ok null  → omit Sigma subsection entirely
  - suricata_ok true  → "Suricata — N rules (Structural check passed — no binary validator)"
  - suricata_ok false → "Suricata — N rules (Structural check: M failed — no binary validator)"
  - suricata_ok null  → omit Suricata subsection entirely
Never write "Unvalidated" — always derive the label from the real validation data.}}

### YARA — {{N}} rules ({{label}})

{{One sentence on what the YARA rules detect and why the chosen strings/conditions are
durable. Full text in Appendix.}}

```yara
{{most important YARA rule inline; note "See Appendix for all rules" if more than one}}
```

### Sigma — {{N}} rules ({{label}})

{{One sentence on the log sources and behaviors covered.}}

```yaml
{{all Sigma rules, each separated by ---}}
```

### Suricata — {{N}} rules ({{label}})

{{One sentence on what network behavior these rules detect.}}

```
{{all Suricata rules}}
```

### Threat-Hunting Queries

{{Only include if detection.hunting_queries is non-empty. List each query with its
platform (KQL/Elastic/generic) and purpose. Omit subsection if none.}}

## 10. Recommendations

{{Concrete, prioritised defensive actions tied directly to observed behaviors. Group by:
1. Immediate containment (isolation, credential resets, C2 block)
2. Remediation (remove persistence, clean dropped files, restore affected systems)
3. Detection deployment (deploy the YARA/Sigma/Suricata rules above to the SIEM/EDR)
4. Hardening (address the specific entry vector and exploit used)
Map each recommendation to the MITRE technique or IOC it addresses where possible.}}

## 11. Appendix

### Full IOC List

{{Complete defanged IOC table — all indicators from detection.iocs, grouped by type.}}

### Full YARA Rules

{{Complete YARA rule text for all rules — only include if YARA rules exist.}}

### Unresolved Questions

{{attribution.unresolved_questions, if any. Omit if empty.}}

### Methodology

Static analysis and interpretation performed by the AI-assisted analysis pipeline. The
sample was detonated in an isolated cloud sandbox for behavioral evidence. All indicators
are defanged throughout this document; real values appear only inside detection rules and
any structured exports. Analysis confidence ratings reflect the quality and completeness
of available evidence.
