---
name: dynamic-analysis
description: >
  Analyze the RUNTIME behavior of a malware sample from raw sandbox evidence and produce
  structured dynamic-analysis findings for a threat-intelligence pipeline. Use this whenever
  behavioral evidence from a detonation is provided — process events, a converted PCAP/network
  log, registry and file activity, Sysmon events, dropped files, or memory strings — and the task
  is to reconstruct what the sample did when executed. Trigger for requests like "analyze the
  behavior", "do dynamic analysis", "what did it do at runtime", "review the sandbox results", or
  when a malware-analysis orchestrator routes a sample to the dynamic phase — even if the word
  "dynamic" is not used. Critically: you INTERPRET raw evidence and reach your own verdict; you do
  NOT simply restate the sandbox's conclusions. This phase consumes the static-analysis output and
  feeds OSINT, correlation, detection engineering, and reporting.
---

# Dynamic Analysis

You are acting as a professional malware analyst performing the **dynamic analysis** phase of an
automated threat-intelligence pipeline. A sandbox safely **detonates** the sample and records what
happened; your job is to **interpret that raw evidence yourself** and write structured findings
into the shared case file.

The sandbox is the execution engine, not the analyst. Its automated verdict ("this is a RAT") is
one opinion to verify — never your source of truth. Reconstruct the behavior from the raw events,
reach your **own** verdict, and then compare the two. Where you and the sandbox disagree, that
disagreement is itself a finding worth surfacing (it can reveal VM-aware evasion, misclassification,
or behavior the automated engine missed).

## When this phase runs

This is **Phase 2**. You receive raw behavioral evidence (plus the `static_analysis` block from
Phase 1) and produce the `dynamic_analysis` section of the case file. You never execute the sample
yourself — you reason over the recorded evidence.

## Inputs you can expect

The platform detonates the sample in a cloud sandbox (e.g., Triage), pulls the **raw** artifacts,
converts binary formats to text, filters obvious system noise, and hands you some or all of:

- Process events: process tree, parent/child relationships, command lines, integrity levels
- Network: DNS queries, HTTP(S) requests with headers/URIs/bodies, TCP/UDP connections,
  destination IPs/ports, connection timing (PCAP already converted to text via tshark/pyshark)
- Registry events: keys/values created, modified, deleted
- File events: files created, modified, deleted, renamed; dropped files with hashes
- Sysmon events (if available): see `ref-dynamic-reference.md` for Event ID meanings
- Memory: strings recovered from process memory after execution; extracted configs if available
- The sandbox's own verdict / signatures / family guess
- The `static_analysis` block, including `behavior_hypothesis` and `to_confirm_dynamically`

Work with whatever is present. If the evidence is thin (common with VM-aware malware that refused
to detonate), say so plainly and lower your confidence rather than inventing behavior. Read
`ref-dynamic-reference.md` before interpreting Sysmon Event IDs, persistence locations, or
beaconing thresholds so your reasoning stays consistent across samples.

## Workflow

Reach your own conclusions from the raw evidence first. Only compare against the sandbox verdict at
the end (step 8).

### 1. Confirm or refute static hypotheses

Start from the static phase's `to_confirm_dynamically` list and `behavior_hypothesis`. For each
item, look for runtime evidence that confirms or refutes it, and record which. A static finding
confirmed at runtime is a high-confidence IOC; e.g., a URL seen in static strings that now appears
in network traffic is a **confirmed** C2 endpoint.

### 2. Reconstruct the execution chain

Build the ordered timeline of what happened: initial process → children → injected processes →
network → persistence → cleanup. Decode any encoded command lines yourself (e.g., a
`powershell -enc <base64>` argument — decode it and report what it actually runs). Unusual
parent/child trees (e.g., a document opening `cmd.exe` opening `powershell`) are findings.

### 3. Identify process injection / manipulation

From the evidence, determine whether and how the sample injected into or manipulated other
processes. Name the technique from the observed sequence rather than just saying "injection
detected" — distinguish classic remote-thread injection from process hollowing from APC injection,
and state the target process and the evidence that supports your call. Cross-reference the
injection-related APIs from the static IAT if present.

### 4. Analyze network behavior

This is often the most valuable runtime evidence. From the converted network logs:

- Extract every contacted domain, IP, port, and URL as IOCs.
- Detect **beaconing** from connection *timing* — regular intervals (e.g., callbacks every ~60s)
  with consistent sizes indicate C2. State the interval you observed.
- **Decode encoded C2 traffic yourself** — if request/response bodies are base64/XOR/hex, decode
  them and report the plaintext (commands, config, check-in data). This is exactly the kind of
  manual decoding a human analyst does.
- Fingerprint from User-Agent strings, URI patterns, and headers — these can identify a family.
- Identify exfiltration: large outbound POSTs, DNS tunneling (oversized/odd TXT queries),
  non-standard protocols.

### 5. Map persistence and system changes

From registry and file events, identify the exact persistence mechanism (which Run/RunOnce key,
service, scheduled task, or startup-folder entry, pointing to what). Note configuration stored in
the registry, dropped payloads (with paths and hashes), and any self-deletion/anti-forensic
cleanup.

### 6. Recover runtime secrets from memory

Memory strings reveal what was encrypted on disk. Look for the **decrypted C2 configuration**,
plaintext commands, campaign IDs, keys, or strings that static analysis could not see. These are
high-value findings unique to dynamic analysis — surface them prominently.

### 7. Form your own verdict

Synthesize the above into your independent assessment: malware type (RAT, ransomware, dropper,
infostealer, loader, banker, etc.), its capabilities, persistence, and C2 mechanism, with a
confidence level and justification grounded in the specific evidence you cited.

### 8. Cross-check against the sandbox verdict

Now — and only now — compare your verdict to the sandbox's. Record agreement or disagreement and
explain any difference. If the sandbox says "RAT" and you concur from the evidence, that strengthens
confidence. If the sandbox detected little but you found clear malicious behavior (or vice versa),
flag it — thin sandbox output often means VM-aware evasion, which is itself an important finding.

### 9. Analyze detonation screenshots (ALWAYS — for every sample)

If detonation replay screenshots are embedded in this message (as images after the text prompt),
examine every frame regardless of malware family. This is not ransomware-specific — **always do
this step**. For every frame:

- Look for visible malware impact: ransom note or countdown dialog, wallpaper defacement, desktop
  encryption (icons changed to `.WNCRY` / similar), fake alert pop-up, UAC prompt, unusual window
  or process visible, browser hijack, locked screen, any behavioral indicator visible on-screen.
- Compare frames to each other — a change between frame 1 (start) and frame 3 (end) is the key
  signal. A desktop that looks identical across all frames means nothing visible happened.

Fill `screenshot_analysis` based on what you actually observe:

- **visible impact found** → `visible_impact: true`, `include_in_report: true`, list the frame
  indices that show the most compelling evidence in `report_frames` (0=start, 1=mid, 2=end),
  write a specific factual caption describing exactly what the image proves.
- **no visible change** (quiet RAT, stealer, loader that runs silently) → `visible_impact: false`,
  `include_in_report: false`, write an observation stating that the desktop appeared unchanged
  across all frames (this confirms the malware operates without visible UI impact).
- **no screenshots provided** → `visible_impact: false`, `include_in_report: false`,
  `observations: "No detonation screenshots were provided."`.

The caption must be specific — not "screenshot shows malware activity" but "Frame 3 (01:33):
ransom note dialog 'Wana Decrypt0r 2.0' visible with countdown timer; desktop wallpaper changed
to WannaCry ransom image; encrypted file icons visible in taskbar."

## Output format

Write findings into the case file under `dynamic_analysis` using this exact structure. Use `null`
or empty arrays for anything not present rather than omitting keys.

```json
{
  "dynamic_analysis": {
    "detonation_quality": "good|partial|failed",
    "static_hypotheses_checked": [
      { "hypothesis": "", "result": "confirmed|refuted|inconclusive", "evidence": "" }
    ],
    "execution_timeline": [
      { "order": 0, "event": "", "detail": "" }
    ],
    "process_tree": [
      { "process": "", "parent": "", "command_line": "", "decoded_command": "", "suspicious": false }
    ],
    "injection": { "observed": false, "technique": "", "target_process": "", "evidence": "" },
    "network": {
      "dns": [], "ips": [], "domains": [], "urls": [],
      "beaconing": { "observed": false, "interval_seconds": null, "evidence": "" },
      "decoded_c2": [ { "raw": "", "decoded": "", "method": "", "meaning": "" } ],
      "user_agents": [], "exfiltration": { "observed": false, "method": "", "evidence": "" }
    },
    "persistence": { "mechanism": "", "location": "", "target": "", "evidence": "" },
    "file_changes": { "created": [], "modified": [], "deleted": [],
                      "dropped": [ { "path": "", "sha256": "" } ] },
    "registry_changes": [ { "operation": "", "key": "", "value": "" } ],
    "memory_findings": { "decrypted_config": "", "recovered_strings": [], "keys": [] },
    "confirmed_iocs": [],
    "claude_verdict": { "type": "", "capabilities": [], "confidence": "low|medium|high",
                        "justification": "" },
    "sandbox_verdict": { "type": "", "family_guess": "", "source": "" },
    "verdict_comparison": { "agreement": "agree|partial|disagree", "explanation": "" },
    "to_research_osint": [],
    "missing_inputs": [],
    "screenshot_analysis": {
      "visible_impact": false,
      "observations": "",
      "include_in_report": false,
      "report_frames": [],
      "caption": ""
    }
  }
}
```

## Handoff

When finished, the populated `dynamic_analysis` block hands off to:

- **OSINT** — `confirmed_iocs`, `network` indicators, `decoded_c2`, `memory_findings`, and
  `to_research_osint` give it concrete runtime artifacts (live C2s, configs, family hints) to
  research externally.
- **Correlation & attribution** — your verdict, timeline, injection/persistence findings, and the
  static↔dynamic confirmations become the backbone of the attack narrative and ATT&CK mapping.

Do not perform external research or assign actor attribution here; flag those for the later phases.

## Principles

- Interpret raw evidence; never relay the sandbox's verdict as your own.
- Decode what the malware tried to hide (encoded commands, C2 traffic, memory config) yourself.
- Confirmed-by-both (static + dynamic) findings are your highest-confidence IOCs — mark them.
- Name techniques precisely from observed behavior, not generic labels.
- Thin or empty detonation evidence is a finding (likely evasion), not a reason to guess.
- State confidence honestly and ground every verdict in cited evidence.
