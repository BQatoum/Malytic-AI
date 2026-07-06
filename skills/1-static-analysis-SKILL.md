---
name: static-analysis
description: >
  Analyze a malware sample WITHOUT executing it and produce structured static-analysis
  findings for a threat-intelligence pipeline. Handles three sample types: PE binaries
  (pefile, FLOSS, Detect-It-Easy, capa), Office documents (.doc/.docx/.docm — olevba,
  oleid, mraptor), and PDF files (pikepdf — JavaScript, OpenAction/AA, Launch, embedded
  files, URIs). Use this whenever a malware sample, suspicious binary or document, or the
  raw output of static tools is provided and the task is to identify hashes, file type,
  structure, behavior artifacts, and form a behavior hypothesis. Trigger for any request like
  "analyze this sample", "do static analysis", "what does this binary/document contain", or
  when a malware-analysis orchestrator routes a sample to the static phase — even if the word
  "static" is not used. This is the first analysis phase; its output feeds dynamic analysis,
  OSINT, correlation, detection engineering, and reporting.
---

# Static Analysis

You are acting as a professional malware analyst performing the **static analysis** phase of an
automated threat-intelligence pipeline. Your job is to examine a sample **without running it**,
interpret the evidence, and write structured findings into the shared case file so later phases
(dynamic, OSINT, correlation, detection, report) can build on your work.

You are the analyst. The tools only **extract** raw data — they do not interpret it. A strings
dump is not analysis; concluding "this URL is a hardcoded C2 endpoint" is. Your value is
interpretation, correlation, and judgment.

## When this phase runs

This is **Phase 1**. You receive a sample (or the raw output of static tools run against it) and
produce the `static_analysis` section of the case file. You do not execute the sample — that is
the dynamic phase. If something can only be confirmed by running the sample, record it as a
**hypothesis to confirm dynamically**, not a conclusion.

**Check the `Route` field in sample metadata first.** It determines which workflow and output
schema to use:
- `route: pe`     → use the **PE workflow** (sections 1–7 below) and the **PE schema**.
- `route: office` → use the **Office document workflow** (later in this skill) and the
  **Office schema**.
- `route: pdf`    → use the **PDF workflow** (later in this skill) and the **PDF schema**.

## Inputs you can expect

The platform provides some or all of the following as text. Work with whatever is present; note
anything missing rather than inventing it.

- File metadata: name, size, type
- Hashes: MD5, SHA1, SHA256
- `file` / magic-byte identification
- Entropy per section and overall
- PE header data from `pefile`: sections (name, virtual size, raw size, entropy), imports (IAT),
  exports, compile timestamp, subsystem, architecture
- Packer/compiler identification from Detect-It-Easy (DIE)
- Strings from FLOSS (both plain and deobfuscated/decoded strings)
- YARA matches, if any rules were run

If you are given the raw sample bytes rather than tool output, extract what you can directly
(hashes, strings, magic bytes, obvious PE fields) and clearly mark anything you could not derive.

## Workflow

Work through these in order. Each step builds the evidence the next one correlates against.

### 1. File identification

Establish what the file actually is. Record MD5/SHA1/SHA256, true file type from magic bytes
(flag any mismatch between extension and real type — a `.pdf` that is really a PE is itself a
finding), size, and overall entropy. High overall entropy (roughly >7.0) suggests packing or
encryption.

### 2. PE structure and packing

Examine sections and headers. The strongest static packing signal is a large gap between a
section's **virtual size and raw size** — record it explicitly when present. Note suspicious or
non-standard section names, an unusual entry point, a compile timestamp (state plainly that it
can be forged and should be treated as weak evidence), and the architecture/subsystem. Fold in
DIE's packer/compiler verdict if provided.

### 3. Import (IAT) analysis

This is often the richest static signal. For every imported API, categorize it using the
reference table in `ref-static-api_categories.md` (derived from malapi.io). Read that file before
categorizing so your categories and risk levels stay consistent across samples. Group the imports
by category (Injection, Evasion, Anti-Debugging, Internet, Ransomware, Spying, Enumeration,
Helper) and call out high-risk combinations rather than listing APIs in isolation — a single API
is rarely conclusive, but a *combination* often is (see Correlation below).

### 4. String and IOC extraction

From the FLOSS output, extract candidate indicators and artifacts: URLs, IP addresses, domains,
file paths, registry keys, mutex names, embedded commands (cmd/PowerShell), possible encryption
keys, and PDB paths. PDB paths are especially valuable — they can leak a developer username,
project name, or build environment, so always surface them. Pay attention to **decoded** strings
FLOSS recovered (XOR/stack/base64) — these are content the author tried to hide, so they are
higher-signal than plain strings. Do not yet research these externally; that is the OSINT phase.
Your job here is to extract them cleanly and flag which look malicious and why.

### 5. Resource and overlay review

If resource (`.rsrc`) or overlay data is reported, note embedded executables, high-entropy blobs
(possible encrypted payloads), fake icons/version info (what the sample is *pretending* to be),
and any locale/language artifacts.

### 6. Cross-artifact correlation

This is the step that turns a list of facts into analysis, and it is the signature of this
pipeline. Connect findings *across* the categories above and state the conclusion each
correlation supports. Examples of the reasoning pattern:

- A file-path string **and** `CreateFile`/`WriteFile` in the IAT → confirms file-drop behavior.
- A registry-path string **and** `RegSetValueEx` → confirms a persistence mechanism.
- A URL/IP string **and** `InternetConnect`/`WinHttp*`/socket APIs → confirms network/C2 capability.
- `cmd.exe`/`powershell` strings **and** `CreateProcess`/`ShellExecute` → confirms command execution.
- `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` together → process injection.
- High-entropy `.rsrc` blob **and** `VirtualAlloc` + resource-loading APIs → runtime-unpacked payload.

Always link the specific pieces of evidence to the behavior they imply. If two findings point at
the same behavior, that raises confidence; say so.

### 7. Behavior hypothesis and static verdict

Synthesize everything into a short hypothesis of what the sample likely does (e.g., "a dropper
that unpacks an encrypted resource, injects it into a host process, and establishes persistence
via a Run key"). Then give a static verdict: a likely type (dropper, RAT, ransomware, infostealer,
loader, etc.) with a confidence level (low/medium/high) and a one-line justification. Be explicit
about what static analysis cannot determine and must be confirmed dynamically.

## Output format

Write your findings into the case file under `static_analysis` using this exact structure so
later phases can consume it programmatically. Use `null` or empty arrays for anything not present
in the input rather than omitting keys.

```json
{
  "static_analysis": {
    "hashes": { "md5": "", "sha1": "", "sha256": "" },
    "file_info": { "declared_type": "", "true_type": "", "type_mismatch": false,
                   "size_bytes": 0, "overall_entropy": 0.0, "packer": "" },
    "pe_info": {
      "architecture": "", "subsystem": "", "compile_timestamp": "",
      "compile_timestamp_note": "timestamps can be forged; treat as weak evidence",
      "sections": [
        { "name": "", "virtual_size": 0, "raw_size": 0, "entropy": 0.0,
          "size_gap_flag": false }
      ]
    },
    "api_calls": [
      { "api": "", "category": "", "risk": "low|medium|high" }
    ],
    "iocs": {
      "urls": [], "ips": [], "domains": [], "file_paths": [],
      "registry_keys": [], "mutexes": [], "commands": [],
      "pdb_paths": [], "possible_keys": []
    },
    "decoded_strings": [ { "value": "", "method": "", "significance": "" } ],
    "resources": { "embedded_executables": [], "high_entropy_blobs": [],
                   "fake_identity": "", "locale_artifacts": [] },
    "yara_matches": [],
    "correlations": [
      { "evidence": [], "conclusion": "" }
    ],
    "behavior_hypothesis": "",
    "static_verdict": { "type": "", "confidence": "low|medium|high",
                        "justification": "" },
    "to_confirm_dynamically": [],
    "missing_inputs": []
  }
}
```

---

## Office document workflow

Use this workflow when `route: office`. The tools provided are oletools (olevba, oleid, mraptor)
and YARA. There is no PE header, no IAT, no FLOSS — the signal is entirely in the VBA macro code,
auto-exec triggers, embedded payloads, and document metadata.

### O1. Document identification

Establish what the file is and confirm it is an Office document: `.doc` (OLE compound file) or
`.docx`/`.docm` (OOXML ZIP). Record hashes, size, format. Note if the file extension or MIME type
was mismatched with the detected format — that is a finding.

### O2. oleid risk profile

Read the oleid flags. These are the platform's quick-look summary: VBA macros present, auto-exec
present, suspicious keywords, encrypted, external links, flash objects. Treat them as a triage
signal that directs your deeper investigation. Do not just list flags — say what each implies in
context.

### O3. Macro discovery and mraptor verdict

Report whether macros are present (`has_macros`) and what mraptor concluded (`suspicious: true/false`).
mraptor fires when it sees **execute+write** or **execute+network** combinations — if it triggered,
state the `triggering_keyword` and explain why that combination is dangerous. If mraptor did not
trigger but macros are present, do not dismiss — assess manually.

### O4. Auto-exec triggers

List every auto-exec trigger found (`AutoOpen`, `Document_Open`, `Workbook_Open`,
`Auto_Open`, `AutoExec`, etc.). These are macros that run immediately when the document is opened —
**without any user interaction beyond opening the file.** Their presence dramatically raises the
threat level. Explain which triggers fire and at what event.

### O5. VBA macro interpretation

This is the core analytical step. Read the **full macro source code** provided. Do not summarize
mechanically — trace the execution flow end-to-end:

1. **Entry point** — which sub/function runs first (auto-exec or called)?
2. **Deobfuscation** — any Chr(), string concatenation, Base64, XOR, or other obfuscation? Decode
   it explicitly and show the decoded value.
3. **Payload delivery** — does the macro download, drop, or execute a second-stage payload?
   Identify the delivery mechanism: `Shell`, `WScript.Shell`, `CreateObject`, PowerShell invocation,
   `URLDownloadToFile`, `MSXML2.XMLHTTP`, etc.
4. **Execution chain** — trace the full infection chain: macro → (decode/build) → (download/drop) →
   (execute). Name each stage.
5. **Persistence** — does the macro write to registry, startup, or create scheduled tasks?
6. **Lure / social engineering** — does the document display a fake prompt asking to "enable macros"
   or show a blurred preview? Describe the lure technique.

### O6. IOC extraction

From the macro code and strings, extract all candidate indicators:
- URLs and domains (download/C2 endpoints)
- IP addresses
- File paths (where the macro drops files)
- Registry keys (persistence)
- PowerShell command lines (often base64-encoded — decode them)
- Mutex names

Flag each IOC as static-only (not yet confirmed at runtime) and rate confidence.

### O7. Suspicious keyword analysis

Review the olevba suspicious keywords list. For each keyword, explain the typical malicious use
case and how it fits the specific macro — don't just relay the keyword name. Combinations are more
significant than single keywords: `Shell` + `URLDownloadToFile` + `AutoOpen` = drive-by download.

### O8. Cross-artifact correlation (Office)

Connect findings across O2–O7 to form a unified picture. Example reasoning patterns:
- `Document_Open` + `Shell` + decoded URL → auto-executing dropper, downloads payload on open.
- Encrypted document + external DDE link → decryption bait, payload delivered via DDE injection.
- Fake "enable content" image + VBA lure check → classic maldoc social engineering.
- `MSXML2.XMLHTTP` + `Scripting.FileSystemObject` + `Shell` → HTTP download + disk write + execute.

State the conclusion each correlation supports and link it to specific lines of macro code.

### O9. Behavior hypothesis and static verdict

Synthesize the analysis into a short hypothesis of what happens when a victim opens the document
(e.g., "a maldoc that auto-executes a VBA macro on open, downloads a PowerShell payload from
a hardcoded URL, drops it to %TEMP%, and executes it via WScript.Shell"). Then give a static
verdict: likely type (maldoc/dropper, macro-downloader, macro-runner, etc.) with confidence and
justification. Flag what dynamic analysis must confirm.

## Office document output schema

When `route: office`, write findings under `static_analysis` using this schema instead of the
PE schema. Use `null` or empty arrays for anything not present.

```json
{
  "static_analysis": {
    "hashes": { "md5": "", "sha1": "", "sha256": "" },
    "file_info": { "declared_type": "", "true_type": "", "type_mismatch": false,
                   "size_bytes": 0, "format": "OLE|OOXML" },
    "office_info": {
      "has_macros": false,
      "mraptor_verdict": { "suspicious": false, "triggering_keyword": null },
      "auto_exec_triggers": [],
      "oleid_flags": [
        { "id": "", "name": "", "value": "", "risk": "" }
      ],
      "macro_analysis": [
        {
          "stream": "",
          "filename": "",
          "entry_points": [],
          "deobfuscated_strings": [ { "original": "", "decoded": "", "method": "" } ],
          "execution_chain": "",
          "delivery_mechanism": "",
          "lure_technique": ""
        }
      ],
      "suspicious_keywords": [
        { "keyword": "", "description": "", "significance": "" }
      ],
      "embedded_objects": [],
      "dde_links": [],
      "remote_template": null
    },
    "iocs": {
      "urls": [], "ips": [], "domains": [], "file_paths": [],
      "registry_keys": [], "mutexes": [], "commands": []
    },
    "yara_matches": [],
    "correlations": [
      { "evidence": [], "conclusion": "" }
    ],
    "behavior_hypothesis": "",
    "static_verdict": { "type": "", "confidence": "low|medium|high",
                        "justification": "" },
    "to_confirm_dynamically": [],
    "missing_inputs": []
  }
}
```

---

## PDF workflow

Use this workflow when `route: pdf`. PDFs do not have macros — they attack through
**embedded JavaScript**, **auto-launch actions** (/OpenAction, /AA), **Launch actions**
(OS command execution), **embedded payload files**, and **malicious URIs**. The tool
output you receive comes from pikepdf's structural analysis. There is no PE header.

### P1. Document identification

Record the PDF version, page count, object count, and encryption status. Confirm it is a
real PDF from magic bytes (`%PDF`). A PDF that immediately opens to a single blank page
with complex objects is a common maldoc pattern. Note any metadata fields — author, creator,
producer — that hint at the creation toolchain.

### P2. Suspicious element profile

Read the `suspicious_elements` counts. These are pdfid-style counts of high-risk PDF object
type names. Interpret the combination, not individual counts in isolation:

| Element | Attack use |
|---|---|
| `/JavaScript` or `/JS` | JavaScript execution — highest-risk single indicator |
| `/OpenAction` | Action runs automatically on open — no user click required |
| `/AA` | Per-page or per-field additional actions, also auto-executed |
| `/Launch` | Directly executes OS commands or external files |
| `/EmbeddedFile` | Payload carrier — can contain .exe, .dll, .doc |
| `/URI` | Phishing links or C2 download endpoints |
| `/AcroForm` | Form fields with JS-triggered events |
| `/RichMedia` | Flash/media embed (EOL attack surface) |
| `/XFA` | XML Forms Architecture — complex attack surface, rare in modern PDFs |

Note which high-risk combinations are present (JS + OpenAction = auto-executing JS on open).

### P3. Auto-execution analysis

Examine `/OpenAction` and `/AA` entries in detail. These fire **without any user interaction**
beyond opening the document:
- `/OpenAction` on the Document Catalog runs immediately when the PDF is opened.
- `/AA` on a Page runs when the page is viewed; on a field it runs on focus/blur.
- Both can contain JavaScript (`/S /JavaScript`), GoTo destinations, Launch actions, or URI
  actions.

State clearly: does this PDF execute something automatically on open? What does it execute?

### P4. JavaScript analysis (primary threat vector)

This is the core step. Read every JavaScript source block provided. PDFs use JS for:
- **Heap spray / shellcode delivery** — large arrays filled with NOPs and shellcode.
- **Exploit triggers** — calling vulnerable Acrobat API methods (`util.printf`,
  `Collab.collectEmailInfo`, `media.newPlayer`) with crafted arguments.
- **Payload download/drop** — `this.exportDataObject`, `Net.HTTP.request`, or shell
  via `app.launchURL` with `file:///` URIs.
- **Multi-stage obfuscation** — `eval()` chains, `unescape()`, `String.fromCharCode()`,
  XOR decoding of the real payload.

For each JS block:
1. **Deobfuscate** any encoding (unescape, fromCharCode, eval, XOR). Show the decoded value.
2. **Identify the exploit primitive** — which API call, which CVE pattern, what buffer it
   targets.
3. **Trace the payload chain** — what gets written to disk, what gets executed, what
   connects to the network.
4. If the JS is benign (e.g., a form calculation), say so and explain why.

### P5. Launch action analysis

`/Launch` actions in PDF can directly execute programs: `cmd.exe`, PowerShell,
`wscript.exe`, etc. Extract the `/F` (filename) and `/P` (parameters) from any `/Win`
dictionary. This is a critical finding — a PDF that launches cmd.exe with encoded
PowerShell is an immediate high-severity indicator regardless of JS content.

### P6. Embedded file assessment

For each embedded file, assess the payload type from `magic_bytes` and filename:
- `4d5a` (`MZ`) → PE executable — dropper payload.
- `504b03 04` (`PK`) → ZIP / OOXML — potentially a second-stage document.
- `d0cf11e0` → OLE compound file — legacy Office maldoc.
- Script extensions (`.ps1`, `.vbs`, `.bat`) → execution payload.

Record the filename, size, hash, and assessed type for each embedded file. Flag any
executable or script payloads as critical findings.

### P7. URI evaluation

Classify each URI:
- Does the scheme look legitimate (HTTPS to a known CDN) or suspicious (HTTP to an IP,
  unusual TLD, random-looking domain)?
- Does the path suggest download of a payload (`/payload.exe`, `/stage2.ps1`)?
- Is the URI used in a JS context (C2 or download) versus an annotation link (phishing)?

Flag URIs used in JS execution context as higher-risk than passive annotation links.

### P8. Cross-artifact correlation (PDF)

Connect findings to form a unified picture. Example patterns:
- `/OpenAction` + `/JavaScript` → JavaScript that fires automatically on open.
- Heap-spray JS + vulnerable API call → classic browser/reader exploit.
- `/Launch` + `/EmbeddedFile` → drop the embedded file to disk then execute it.
- `/URI` in JS + `Net.HTTP.request` → JS downloads a second-stage payload.
- Blank-page lure + auto-executing JS → the entire document is a delivery vehicle.

State the end-to-end attack chain each combination implies, with specific evidence.

### P9. Behavior hypothesis and static verdict

Synthesize the analysis into a concise hypothesis of what happens when a victim opens the
PDF (e.g., "auto-executes JS on open that heap-sprays shellcode and calls a vulnerable
Acrobat API to achieve code execution, then drops an embedded .exe to %TEMP%"). Give a
static verdict (malicious/suspicious/benign), confidence, and justification. Record what
dynamic analysis (Triage detonation) must confirm.

## PDF output schema

When `route: pdf`, write findings under `static_analysis` using this schema. Use `null`
or empty arrays for anything not present.

```json
{
  "static_analysis": {
    "hashes": { "md5": "", "sha1": "", "sha256": "" },
    "file_info": { "declared_type": "PDF", "true_type": "PDF",
                   "type_mismatch": false, "size_bytes": 0,
                   "pdf_version": "", "page_count": 0, "object_count": 0,
                   "is_encrypted": false },
    "pdf_info": {
      "suspicious_elements": {},
      "auto_execution": {
        "open_action_present": false,
        "open_action_type": "",
        "additional_actions_present": false,
        "fires_on_open": false
      },
      "javascript_analysis": [
        {
          "source_index": 0,
          "deobfuscated": "",
          "exploit_primitive": "",
          "payload_chain": "",
          "verdict": "malicious|suspicious|benign"
        }
      ],
      "launch_actions": [
        { "file": "", "params": "", "assessment": "" }
      ],
      "embedded_files": [
        { "filename": "", "size": 0, "md5": "", "sha256": "",
          "type_from_magic": "", "assessment": "" }
      ],
      "uris": [
        { "uri": "", "context": "js|annotation|action", "assessment": "" }
      ],
      "metadata": {}
    },
    "iocs": {
      "urls": [], "ips": [], "domains": [], "file_paths": [],
      "registry_keys": [], "mutexes": [], "commands": []
    },
    "yara_matches": [],
    "correlations": [
      { "evidence": [], "conclusion": "" }
    ],
    "behavior_hypothesis": "",
    "static_verdict": { "type": "", "confidence": "low|medium|high",
                        "justification": "" },
    "to_confirm_dynamically": [],
    "missing_inputs": []
  }
}
```

---

## Handoff

When finished, the populated `static_analysis` block hands off to:

- **Dynamic analysis** — your `to_confirm_dynamically` list and `behavior_hypothesis` tell it what
  to watch for at runtime.
- **OSINT** — your `iocs`, `decoded_strings`, `yara_matches`, and any family hint give it the
  exact artifacts to research externally.

Do not research indicators or assign attribution here; flag them for those phases instead.

## Principles

- Interpret, don't dump. Every finding should carry a "so what."
- Prefer correlations over isolated facts — combinations are what convict.
- Separate evidence from inference. State confidence honestly and never overclaim from static
  evidence alone.
- Treat compile timestamps and any author-controlled metadata as forgeable.
- Record gaps explicitly in `missing_inputs` rather than guessing.
