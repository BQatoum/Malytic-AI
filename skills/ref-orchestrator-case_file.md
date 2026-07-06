# Case File Reference

The case file is one JSON object that flows through every phase. Each phase reads earlier blocks and
writes its own. This file documents how the blocks connect so the orchestrator can verify clean
handoffs.

## Flow of data between blocks

```
sample + route
   │
   ▼
static_analysis ─────────────┐
   │ behavior_hypothesis      │
   │ to_confirm_dynamically   │
   ▼                          │
dynamic_analysis              │ (both feed OSINT)
   │ confirmed_iocs           │
   │ to_research_osint        │
   ▼                          ▼
osint ◄───────────────────────┘
   │ family_intel, actor_intel
   ▼
attribution  (fuses static + dynamic + osint)
   │ malware_family, mitre_attack, kill_chain, overall_confidence
   ▼
detection  (uses attribution + all IOCs)
   │ iocs (defanged+scored), yara/sigma/suricata, stix_bundle
   ├──────────────► report  (reads the ENTIRE case file)
   └──────────────► elastic (index IOCs + load Sigma detection rules)
```

## What each phase needs from earlier phases

| Phase | Reads | Writes |
|---|---|---|
| static-analysis | sample, route | static_analysis |
| dynamic-analysis | static_analysis (hypotheses) + raw sandbox evidence | dynamic_analysis |
| osint-research | static_analysis, dynamic_analysis (IOCs/artifacts) | osint |
| correlation-attribution | static + dynamic + osint | attribution |
| detection-engineering | all IOCs + attribution (ATT&CK) | detection |
| report-generation | entire case file | report |
| elastic push | detection.iocs + sigma rules (+ optional stix_bundle) | elastic |

## Handoff checks for the orchestrator
Before advancing, confirm the current phase wrote a non-null block. Specifically:
- After static: `static_analysis.hashes` and `static_verdict` present.
- After dynamic: `dynamic_analysis.detonation_quality` set (even if "failed").
- After osint: `osint` present (may legitimately contain mostly `not_found`).
- After attribution: `attribution.malware_family` and `overall_confidence` set.
- After detection: `detection.iocs` present and scored (`stix_bundle` optional).
- After report: `report.file_path` set.
- After elastic: `elastic` records success or a recorded failure.

A block being present with honest "unknown / not found / failed" values counts as complete. A block
being `null` after its phase ran means the phase did not finish — investigate before advancing.

## Confidence propagation
Confidence should only ever decrease or stay equal as it flows downstream unless a later phase adds
genuinely new corroborating evidence. The report's overall confidence must equal
`attribution.overall_confidence` unless detection/OSINT materially changed the picture — never
inflate it for a cleaner narrative.
