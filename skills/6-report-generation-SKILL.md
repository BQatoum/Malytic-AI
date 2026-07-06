---
name: report-generation
description: >
  Assemble a completed malware-analysis case into a professional, dual-audience threat-intelligence
  report. Use this whenever the analysis is done and the task is to write up the findings — an
  executive summary, technical static/dynamic findings, OSINT, MITRE ATT&CK mapping, a defanged IOC
  table, detection rules, attribution, and recommendations — as a deliverable document (Markdown,
  Word, or PDF). Trigger for requests like "write the report", "generate the malware report",
  "create the writeup", "document these findings", or when a malware-analysis orchestrator routes a
  case to the reporting phase — even if the word "report" is not used. This phase consumes the full
  case file (static, dynamic, OSINT, attribution, detection) and produces the final report; it runs
  alongside the Elastic push.
---

# Report Generation

You are writing the deliverable — the artifact a manager, an incident responder, or a peer analyst
actually reads. Everything before this produced evidence and structured data; your job is to turn
the case file into a clear, professional, defensible document.

Write for two readers at once. An **executive** needs the bottom line fast: what is it, how bad is
it, what should we do — no jargon, 30 seconds. A **technical responder** needs everything: the
evidence, the IOCs, the ATT&CK mapping, the detection rules, enough detail to act and to verify
your conclusions. The structure below serves both by front-loading the summary and putting depth
in the body.

The quality of this report represents the whole pipeline. Be accurate, be honest about confidence,
and never let the writeup claim more than the analysis proved.

## When this phase runs

This is **Phase 6**. You receive the complete case file (`static_analysis`, `dynamic_analysis`,
`osint`, `attribution`, `detection`) and produce the final report. The platform renders your
content to the requested format (Markdown by default; Word via python-docx or PDF via weasyprint).
Read `asset-report-template.md` for the exact section structure and fill it from the case file.

## Inputs you can expect

The full case file. Every section maps to data already gathered:
- **Title** ← `attribution.family` or sample filename (never the SHA-256)
- **Executive Summary** ← sample metadata (hashes, type, platform) + `attribution.overall_confidence`
- **Sample Overview** ← `static_analysis` (type, size, packer) + `osint.reputation` (first-seen, detection rate)
- **Static Analysis** ← `static_analysis` (packing, PE, APIs, strings, hypothesis)
- **Dynamic Analysis** ← `dynamic_analysis` (timeline, network, persistence, memory) + `dynamic_analysis.screenshot_analysis`
- **OSINT Findings** ← `osint` (reputation, family intel, infrastructure, actor/campaign, references)
- **MITRE ATT&CK Mapping** ← `attribution.mitre_attack`
- **IOC table** ← `detection.iocs` (defanged), split Network / Host
- **Attribution** ← `attribution` (family, actor, campaign, attack narrative, alternatives)
- **Detection Rules** ← `detection.yara_rules`, `sigma_rules`, `suricata_rules`, `hunting_queries` + `detection.validation` for labels
- **Recommendations** ← derived from observed behaviors + MITRE techniques
- **Appendix** ← full IOC list, full YARA text, `attribution.unresolved_questions`, methodology

If a phase block is absent (`{}`) say so in one honest sentence — do not pad or lorem-ipsum.

## Writing standards

- **Lead with the answer.** The executive summary states the verdict first, then supports it.
- **Plain language up top, precision below.** No unexplained jargon in the summary; full technical
  terms in the body.
- **Defanged indicators everywhere in prose and tables.** Real values live only in the attached
  rules/STIX, never in readable text.
- **State confidence honestly.** Carry the analysis confidence through; don't upgrade a "medium"
  into certainty for a cleaner story. Flag unresolved questions.
- **Evidence-linked claims.** Every significant assertion should trace to a finding; avoid
  decoration that isn't supported.
- **Consistent, scannable formatting.** Tables for IOCs and ATT&CK; short paragraphs; clear headers.
- **No copied source text.** Summarize OSINT findings in your own words and cite the source;
  reproduce only short, attributed quotes if essential.

## Report structure

ALWAYS follow the section order in `asset-report-template.md`. The twelve sections are:

### 1. Title
- H1: **"Malware Analysis Report: {{family or short sample name}}"** — use
  `attribution.family` if available, otherwise the sample file name.
  **Never put the SHA-256 or any long hash in the title** — it overflows and clutters.
- Follow the H1 with one italic line: `*{{analysis_date}} · Version 1.0 · CONFIDENTIAL*`

### 2. Executive Summary
- **Lead with the SHA-256 metadata table** with these exact rows:

  | Field | Value |
  |---|---|
  | Sample name | ... |
  | SHA-256 | ... |
  | MD5 | ... |
  | SHA-1 | ... |
  | File type | ... |
  | Platform | ... |
  | Analysis date | ... |
  | **Verdict** | **MALICIOUS** / **SUSPICIOUS** / **BENIGN** (from `attribution.verdict`) |
  | Analysis confidence | low / medium / high (from `attribution.overall_confidence`) |

  **`Verdict` and `Analysis confidence` are two distinct rows.** Never merge them into a single
  "confidence" field. A reader must be able to see at a glance that the file is BENIGN or
  MALICIOUS — the confidence row tells them how sure the analysis is of that verdict.

- For **BENIGN** files: after the table, write 2–3 sentences stating clearly that the sample
  is legitimate software, no malicious activity was observed, and no detection rules or IOC
  indexes were generated. There is no "threat" to describe — say so plainly.

- For **MALICIOUS / SUSPICIOUS** files: write 2–5 plain-language sentences covering what it
  is, severity, who is at risk, symptoms, most important action. Readable by a non-technical
  manager.

### 3. Sample Overview
- Bullet list: file type + size, first-seen (from `osint.reputation`), detection rate,
  packer/compiler finding, container/extraction note if an archive.
- One paragraph: what the sample is, its role (loader/dropper/payload/tool), and the
  capability set at a glance.

### 4. Static Analysis Findings
- **One section** — do NOT split into "Basic" and "Advanced". Do NOT invent content.
- Cover: file type confirmation, entropy/packing, PE structure highlights, high-risk
  API groups and what they imply, notable/decoded strings, behavior hypothesis.
- If static analysis did not run, say so honestly in one sentence.

### 5. Dynamic Analysis Findings
- Execution timeline, process tree, injection technique (named precisely with evidence),
  network behavior (contacted infra, beaconing interval, decoded C2), persistence
  (exact key/path/method), memory-recovered config/secrets.
- If detonation screenshots were captured and `screenshot_analysis.include_in_report`
  is true: add a `### Detonation Screenshots` subsection. Write each frame caption as
  `Fig {{N}}: {{caption_text}}`. The rendering pipeline embeds the actual images; write
  only caption text.
- If dynamic analysis did not run, say so in one sentence.

### 6. OSINT Findings
- File and hash reputation (VT score, public sandbox hits, first-seen).
- Family intelligence: known capabilities, typical TTPs, associated campaigns.
- Infrastructure: WHOIS/ASN, passive-DNS history, co-hosted domains.
- Actor/campaign intel if any — attribute conservatively with confidence level.
- Cite references in your own words; short attributed quotes only if essential.
- If OSINT did not run, say so in one sentence.

### 7. MITRE ATT&CK Mapping
- Table: **Tactic | Technique ID | Technique Name | Evidence | Confidence**
  Source: `attribution.mitre_attack`. Include all techniques with evidence.
- Brief paragraph noting the dominant tactic clusters and what they imply about
  attacker objectives.
- If attribution did not run, say so in one sentence.

### 8. Indicators of Compromise
- Two subsections: **### Network Indicators** and **### Host-based Indicators**.
- Network: IPs, domains, URLs (all defanged). Host-based: file hashes, paths, registry
  keys, mutexes (all defanged). Source: `detection.iocs`.
- If a subsection has no IOCs, write one sentence saying so.

### 9. Attribution Assessment
- Family verdict with confidence and evidence.
- Threat actor: conservative attribution, confidence, reasoning, alternatives considered.
- Campaign name if identified.
- **Attack narrative**: readable end-to-end story of how the malware operates, ordered
  by kill-chain stage, each step traceable to specific evidence. Source:
  `attribution.attack_narrative` — expand into prose rather than quoting verbatim.
- If attribution did not run, say so in one sentence.

### 10. Detection Rules
For each rule type, derive the heading label from `detection.validation`:
- `yara_ok: true`  → `"YARA — N rules (Validated)"`
- `yara_ok: false` → `"YARA — N rules (Validation failed: M of N rules)"` where M is
  the count of rules where `valid == false` in `detection.validation.yara_rules`
- `yara_ok: null`  → **omit the YARA subsection** (no rules generated)
- Same logic for `sigma_ok` / `suricata_ok`.
- For Suricata always append `"(structural check only — no binary validator)"`.
- **Never write "Unvalidated"** — always derive from the real data.
- Include a Threat-Hunting Queries subsection only if `detection.hunting_queries` is
  non-empty.

### 11. Recommendations
- Concrete, prioritised actions tied to observed behaviors and MITRE techniques.
- Group by: Immediate containment → Remediation → Detection deployment → Hardening.
- Each item should reference the specific threat behavior it addresses.

### 12. Appendix
- **Full IOC List** — complete defanged table, all types.
- **Full YARA Rules** — complete rule text; only if rules exist.
- **Unresolved Questions** — from `attribution.unresolved_questions`; omit if empty.
- **Methodology** — standard note about pipeline + isolated sandbox detonation.

## Output format

Produce the report as a single document following the template. Default to Markdown; if Word or PDF
is requested, write the same content for the platform to render. Also write a short block into the
case file recording what was produced:

```json
{
  "report": {
    "format": "markdown|docx|pdf",
    "title": "",
    "sections_completed": [],
    "sections_with_no_data": [],
    "verdict": "MALICIOUS|SUSPICIOUS|BENIGN",
    "analysis_confidence": "low|medium|high",
    "file_path": ""
  }
}
```

## Handoff

This phase produces the user-facing deliverable. It runs in parallel with the Elastic integration
(Phase 7), which indexes the indicators and loads the detection rules. Together they are the
pipeline's final output: a human-readable report and machine-readable, searchable/alertable
intelligence in Elastic.

## Principles

- Serve both readers: bottom line first, full depth below.
- Honesty over polish — carry confidence faithfully and surface unresolved questions.
- Defang all human-facing indicators; keep real values only in attached rules/STIX.
- Every claim traces to evidence; summarize sources in your own words and cite them.
- A "no data" or "could not determine" section is more professional than padding or omission.
