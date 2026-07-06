# Dynamic Analysis Reference

Lookup tables for interpreting runtime evidence consistently. Read the relevant section when you
need it; you already know most of this, so use it to stay consistent, not to relearn the basics.

## Table of contents
- Sysmon Event IDs
- Persistence locations to check
- Beaconing / C2 timing guidance
- Per-malware-type behavior playbooks

---

## Sysmon Event IDs
When Sysmon events are provided, these IDs map to the behaviors that matter most:

| Event ID | Meaning | Why it matters |
|---|---|---|
| 1 | Process creation | Execution chain, command lines, parent/child anomalies |
| 3 | Network connection | C2, exfiltration, destination IP/port |
| 5 | Process terminated | Self-deletion, killing security tools |
| 7 | Image (DLL) loaded | DLL side-loading, unusual module loads |
| 8 | CreateRemoteThread | **Process injection** — strong signal |
| 10 | Process access | LSASS access = possible credential dumping |
| 11 | File created | Dropped payloads, staged data |
| 12/13/14 | Registry events | Persistence, configuration storage |
| 15 | FileCreateStreamHash | Alternate data streams (hiding data) |
| 17/18 | Pipe created/connected | Named-pipe C2 or inter-process comms |
| 22 | DNS query | C2 domain resolution, DGA patterns |
| 23/26 | File delete | Anti-forensic cleanup |

## Persistence locations to check
When reviewing registry/file events, these are the high-value persistence sites:

Registry Run keys:
- HKCU\Software\Microsoft\Windows\CurrentVersion\Run
- HKLM\Software\Microsoft\Windows\CurrentVersion\Run
- ...\CurrentVersion\RunOnce (HKCU and HKLM)

Other registry persistence:
- ...\CurrentVersion\Winlogon (Shell, Userinit)
- ...\Image File Execution Options (debugger hijack)
- COM hijacking via HKCU\Software\Classes\CLSID

Services:
- HKLM\System\CurrentControlSet\Services (new/modified service)

Scheduled tasks:
- C:\Windows\System32\Tasks\ (new task files)

Startup folders:
- %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
- %PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup

WMI event subscriptions (fileless persistence):
- root\Subscription: __EventFilter, __EventConsumer, __FilterToConsumerBinding

## Beaconing / C2 timing guidance
- Regular intervals (e.g., every 30s/60s/300s plus small jitter) with consistent packet sizes →
  classic C2 beaconing. Report the observed interval.
- Jittered intervals (random delay around a base) are common in modern C2 (e.g., Cobalt Strike) —
  still beaconing; note the approximate base and jitter.
- A single connection then a long-lived stream → interactive session / reverse shell rather than
  beaconing.
- Bursts of DNS with long/odd subdomains → possible DNS tunneling / DGA.

## Per-malware-type behavior playbooks
What to look for once you suspect a given type. Use these to make sure you didn't miss the
defining behavior of that class.

**Ransomware:** mass file modification with extension changes; ransom-note files dropped across
directories; `vssadmin delete shadows` / WMI shadow-copy deletion; CryptEncrypt activity; desktop
wallpaper change; often a mutex to avoid double-encryption.

**RAT / backdoor:** persistence + C2 beacon or listening port; command-execution capability
(spawning cmd/powershell on command); keylogging/screen-capture; encoded C2 channel (decode it).

**Dropper / loader:** writes and executes a second-stage payload (capture its path + hash);
downloads from a URL then runs it; often self-deletes after dropping.

**Infostealer:** reads browser profile / credential stores; accesses crypto-wallet files; stages
data into an archive; exfiltrates via HTTP POST or to a Telegram/Discord endpoint.

**Banker:** web-inject / browser hooking; targets banking URLs; form-grabbing; often combined with
infostealer behavior.

**Worm:** local network scanning; SMB activity / exploitation; copies itself to shares or removable
drives; lateral movement via PsExec/WMI/scheduled tasks.

**Cryptominer:** sustained high CPU/GPU; connection to mining-pool domains/ports (e.g., 3333/4444/
5555/7777/8888/14444); persistence via scheduled task; process-priority manipulation to hide load.
