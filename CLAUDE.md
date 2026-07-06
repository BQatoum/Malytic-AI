# Malware Analysis & Threat Intelligence Pipeline

## What this project is
An AI-powered malware analysis platform. A user uploads a sample; the backend runs a 7-phase
pipeline with Claude as the analyst engine, then produces a dual-audience report and pushes
detection content + indicators into **Elastic** (Elasticsearch + Kibana). Built as a CyberKnight
TIA internship project.

## Core principle (do not violate)
Claude is the **analyst**, not a relay. External tools and the sandbox only **extract** data and
**execute** samples; Claude **interprets, correlates, concludes, and writes**. This matters most in
dynamic analysis: the platform pulls **raw** sandbox artifacts (process/network/registry/file/memory)
converted to text, and Claude analyzes them itself — reaching its own verdict before comparing to the
sandbox's. Disagreements are a feature, not a bug.

## Architecture
- **Backend:** Python + FastAPI (`backend/`)
- **Frontend:** upload page + results dashboard (`frontend/`)
- **Database:** SQLite via SQLAlchemy (swap to PostgreSQL by changing `DATABASE_URL` in `.env` — no ORM changes needed) — one case-file JSON per sample, keyed by `case_id`
- **Analysis engine:** Anthropic API (Claude), driven by the prompt library in `skills/`
- **Sandbox:** Triage cloud API (detonation; raw artifacts pulled and converted to text)
- **Integration target:** **Elastic** — index case findings + IOCs into Elasticsearch (use ECS
  `threat.*` fields), convert Sigma rules to Elastic detection rules (pySigma Elasticsearch backend
  or Elastic's Sigma import), load via the Kibana Detections API, and build Kibana dashboards.
  Library: `elasticsearch-py` (+ Kibana API). STIX 2.1 bundle is an OPTIONAL portable export, not
  the integration mechanism.

## The 7-phase pipeline (the case file is the spine)
One growing JSON object flows through every phase; each phase reads earlier blocks and writes its
own. **Never overwrite a prior phase's data.**
1. **orchestrator** — intake, route by *true* file type (not extension), own the case file, sequence phases, manage failures
2. **static-analysis** — analyze without executing; flag what to confirm dynamically
3. **dynamic-analysis** — interpret raw sandbox evidence; reach own verdict; cross-check vs sandbox
4. **osint-research** — research ALL findings externally (not just network IOCs)
5. **correlation-attribution** — fuse all phases, map MITRE ATT&CK, attribute conservatively
6. **detection-engineering** — defang + score IOCs; YARA + Sigma + Suricata; (optional STIX bundle)
7. **report-generation** — dual-audience report (executive + technical)
(The **Elastic push** is the closing step: index IOCs/findings + load Sigma-derived detection rules.)

## The prompt library (`skills/`)
`skills/` holds the 7 phase skills + their reference files + the report template. At runtime the
backend loads the relevant skill as the **system prompt** for that phase's Claude API call. These
files ARE the analyst instructions — treat them as the source of truth for each phase's behavior and
its exact JSON output schema. Do not duplicate or paraphrase their logic in code; load and use them.

## SAFETY RULES (non-negotiable)
- The platform **never executes malware samples locally.** Only the cloud sandbox detonates. The
  backend treats sample files as **inert bytes** (hash, store, submit) — never run them.
- During development and testing, use **safe text data** (sandbox reports / extracted tool output),
  **never live malware binaries** on this machine.
- Secrets (API keys, Elastic credentials) live in `.env`, never in code or git. `.env` is gitignored.
- Harden all file handling: validate filenames, prevent path traversal, store uploads outside the
  web root, enforce size/type limits.

## Conventions
- Python: type hints, async where it fits, idiomatic FastAPI.
- Each analysis phase's output must match the JSON schema defined in its skill file.
- Defang all human-facing indicators (`hxxp`, `[.]`, `[@]`); keep real values only in rule logic, the
  Elastic indices, and any STIX export.
- Confidence only decreases downstream unless a later phase adds genuinely new corroborating evidence.
- Commit after each working phase.

## Commands

### First-time setup
```bash
sudo apt-get install -y libmagic1          # required: system dep for python-magic
sudo apt-get install -y unrar              # optional: RAR extraction degrades gracefully without it
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# capa rules (required for capability detection in Phase 2):
#   Option A — download via capa's built-in updater:
capa --update
#   Option B — clone the rules repo beside the project root, or anywhere, then
#   point CAPA_RULES_PATH in .env at that directory:
#   git clone https://github.com/mandiant/capa-rules ./capa-rules
#   echo 'CAPA_RULES_PATH=./capa-rules' >> .env

# yara-python has pre-built wheels for Linux x86_64; no extra system deps needed.
# If building from source (e.g. on ARM) you may need: sudo apt-get install -y automake libtool

# flare-floss is enabled by default (ENABLE_FLOSS=true). It runs emulation and can
# be slow on large or heavily packed samples. Disable with ENABLE_FLOSS=false in .env.

# Detect-It-Easy (DIE) — diec is a system binary, not a pip package.
# Install from https://github.com/horsicq/DIE-engine/releases (grab the .deb):
#   sudo dpkg -i die_*.deb
# Verify with: diec --version
# Disable with ENABLE_DIE=false in .env.
```

### Dev
- `uvicorn backend.app.main:app --reload` — run the API (creates SQLite DB on first start)
- `pytest` — run tests

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
