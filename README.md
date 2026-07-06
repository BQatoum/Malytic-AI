# Malytic.AI

**An AI-powered malware analysis platform where AI acts as the analyst — not just a scanner.**

Malytic.AI takes a malware sample and runs it through a seven-phase analysis pipeline, using an AI reasoning engine to interpret evidence, correlate findings across phases, reach its own verdict, and produce a complete threat-intelligence package — a dual-audience report plus validated, SIEM-ready detection rules — automatically.

![Malytic.AI](screenshots/home.png)

---

## The Problem

Manual malware analysis doesn't scale. A skilled analyst can spend hours triaging a single sample, SOC teams face hundreds of alerts a day, and analysis quality varies with whoever is on shift. By the time a human writes a detection rule for a new threat, the attacker has already moved on.

Malytic.AI addresses this by putting an AI analyst at the center of the pipeline — giving every SOC team the analytical depth of a senior threat analyst, on every sample.

---

## Core Concept: AI as the Analyst

Most malware tools extract data and hand you raw output to interpret. Malytic.AI is different: the AI **reasons over the evidence** at every phase. Tools only extract facts; the sandbox only executes the sample; the AI interprets, correlates, and concludes.

The AI reaches its **own verdict** and cross-checks it against the tool and sandbox verdicts — so when an evasive sample produces a "clean" sandbox result, the platform can recognize that silence itself as suspicious, rather than blindly trusting it.

Each analysis phase is driven by a dedicated skill file (a structured system prompt), not hardcoded family logic — keeping the platform **file-type and family agnostic**. It has been validated across diverse real samples: infostealers, RATs, ransomware, malicious Office macro documents, and PDFs.

---

## Architecture: The Seven-Phase Pipeline

Every sample flows through a JSON "case file" that persists in a database — each phase reads the prior phases' results and writes its own, so nothing is lost and the pipeline survives restarts.

| # | Phase | What it does |
|---|-------|--------------|
| 1 | **Intake** | Inert byte handling, hashing, file-type detection, archive extraction, routing (PE / Office / PDF) |
| 2 | **Static Analysis** | Type-appropriate extraction (PE, Office macros, PDF structure) — the AI interprets the raw facts |
| 3 | **Dynamic Analysis** | Live sandbox detonation — process behavior, network/C2, PCAP, and screenshots read by AI vision |
| 4 | **OSINT** | Threat-intelligence enrichment (reputation, known-family intelligence) |
| 5 | **Correlation / Attribution** | The AI fuses all phases into a verdict, family identification, and MITRE ATT&CK mapping |
| 6 | **Detection Engineering** | Generates and validates YARA, Sigma, and Suricata rules (with auto-repair) |
| 7 | **Reporting + SIEM Push** | Produces a threat-intel report and pushes IOCs + detection rules into Elastic |

The pipeline fails gracefully — if one phase errors, the others continue and the report reflects what was recovered.

---

## Analyst-Augmented Analysis

Malytic.AI runs fully automated, but it's built to respect expert workflows. Analysts stay in control through an advanced-analysis mode:

- **Bring your own static findings** — provide your own static analysis; the platform skips its static phase and continues from yours.
- **Bring your own dynamic findings** — provide results from your own sandbox; the platform skips detonation and uses them.
- **Internal IOC database** — cross-reference a sample's indicators against your organization's known-attacker IOCs to detect repeat adversaries, then export an updated database with the new sample's indicators merged in.
- **OSINT pause & resume** — pause the pipeline before OSINT to run your own threat-intel research (private feeds, dark web, custom tooling), then upload your findings and resume. The paused state persists across restarts.

Provenance is tracked throughout — the report clearly notes which findings were analyst-provided versus platform-generated.

---

## Output

**Threat-intelligence report** — a dual-audience report (executive summary + technical detail) with a verdict, confidence rating, malware family, MITRE ATT&CK mapping, defanged IOCs, an attack narrative, and detonation screenshots embedded as proof.

**SIEM integration** — validated detection rules across three layers, pushed into Elastic:
- **YARA** for file/content detection
- **Sigma** for endpoint behavior detection (translated to the SIEM's query language)
- **Suricata** for network/C2 detection

IOCs and detection rules land directly in Kibana, ready for threat hunting and alerting.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Analysis engine | AI reasoning model (skills-based, one SKILL.md per phase) |
| Backend | FastAPI (async), background-task pipeline |
| Case storage | SQLite (persistent case files, restart-safe) |
| Frontend | React + Vite (single-page dashboard) |
| Sandbox | Cloud sandbox detonation |
| SIEM | Elasticsearch + Kibana |
| Detection | YARA, Sigma, Suricata (with real validation + auto-repair) |

---

## Key Design Principles

- **AI as analyst, not relay** — the AI reaches its own conclusions and cross-checks tool/sandbox verdicts.
- **Skills, not hardcoded logic** — each phase loads a structured skill, keeping the platform general across file types and families.
- **Honest confidence** — the platform reports how sure it is, and fails gracefully rather than fabricating.
- **Safety first** — samples are handled inert; detonation happens only in an isolated cloud sandbox; all indicators are defanged in reports.
- **Validated detection** — generated rules are actually compiled/parsed and auto-repaired before deployment, so broken rules never reach the SIEM.

---

## Author

**Belal Qatoum**

---

*Malytic.AI is a research/educational project. Malware samples are never included in this repository and must only be handled in isolated, controlled environments.*
