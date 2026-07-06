# MITRE ATT&CK Reference (for correlation & mapping)

A compact lookup so technique mapping stays consistent across cases. You know ATT&CK well; use this
to standardize IDs and tactic ordering, not to relearn it. This is not exhaustive — if a behavior
maps to a technique not listed, use the correct ID from attack.mitre.org and note it.

## Tactic ordering (Enterprise)
Order kill-chain stages using this sequence:

1. Reconnaissance (TA0043)
2. Resource Development (TA0042)
3. Initial Access (TA0001)
4. Execution (TA0002)
5. Persistence (TA0003)
6. Privilege Escalation (TA0004)
7. Defense Evasion (TA0005)
8. Credential Access (TA0006)
9. Discovery (TA0007)
10. Lateral Movement (TA0008)
11. Collection (TA0009)
12. Command and Control (TA0011)
13. Exfiltration (TA0010)
14. Impact (TA0040)

## Common techniques by behavior
Map the behaviors your analysis observed to these IDs.

### Execution
- T1059 Command and Scripting Interpreter (.001 PowerShell, .003 Windows Cmd, .005 VBScript,
  .007 JavaScript)
- T1106 Native API
- T1053.005 Scheduled Task
- T1204 User Execution (malicious file/link)

### Persistence
- T1547.001 Registry Run Keys / Startup Folder
- T1543.003 Windows Service
- T1053.005 Scheduled Task
- T1546 Event-Triggered Execution (.003 WMI subscription, .015 COM hijack)
- T1574 Hijack Execution Flow (.002 DLL side-loading)

### Privilege Escalation
- T1055 Process Injection (.001 DLL, .012 process hollowing)
- T1134 Access Token Manipulation
- T1548 Abuse Elevation Control Mechanism (.002 UAC bypass)

### Defense Evasion
- T1027 Obfuscated/Compressed Files or Information (.002 software packing)
- T1055 Process Injection
- T1070 Indicator Removal (.004 file deletion / self-delete)
- T1497 Virtualization/Sandbox Evasion
- T1562 Impair Defenses (.001 disable tools)
- T1140 Deobfuscate/Decode Files or Information
- T1036 Masquerading

### Credential Access
- T1003 OS Credential Dumping (.001 LSASS memory)
- T1056.001 Keylogging
- T1555 Credentials from Password Stores (.003 browsers)

### Discovery
- T1057 Process Discovery
- T1082 System Information Discovery
- T1083 File and Directory Discovery
- T1518 Software Discovery (.001 security software)
- T1614 System Location Discovery (victim-locale checks)

### Lateral Movement
- T1021 Remote Services (.002 SMB)
- T1570 Lateral Tool Transfer

### Collection
- T1113 Screen Capture
- T1115 Clipboard Data
- T1005 Data from Local System
- T1560 Archive Collected Data

### Command and Control
- T1071 Application Layer Protocol (.001 web, .004 DNS)
- T1095 Non-Application Layer Protocol
- T1571 Non-Standard Port
- T1573 Encrypted Channel
- T1568 Dynamic Resolution (.002 DGA)
- T1105 Ingress Tool Transfer (download second stage)

### Exfiltration
- T1041 Exfiltration Over C2 Channel
- T1048 Exfiltration Over Alternative Protocol

### Impact
- T1486 Data Encrypted for Impact (ransomware)
- T1490 Inhibit System Recovery (shadow-copy deletion)
- T1489 Service Stop
- T1496 Resource Hijacking (cryptomining)

## Mapping discipline
- Map a technique only when analysis evidence supports it; put suspected-but-unproven ones in
  `possible_techniques`, not the main map.
- Prefer the most specific sub-technique the evidence justifies (e.g., T1547.001 over T1547).
- Record which phase observed each technique (static / dynamic / osint) so confidence is traceable.
