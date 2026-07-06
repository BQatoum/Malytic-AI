# Windows API Categories (reference for IAT analysis)

Derived from the categories used by malapi.io. When analyzing the import address table (IAT),
match each imported API to a category below and assign a risk level. A single API is rarely
conclusive on its own — the value is in **combinations** (see "High-signal combinations" at the
end). Use this table to keep categorization consistent across every sample.

This is not exhaustive. If you encounter an API not listed here, reason about its documented
purpose and assign the closest category; note that you inferred it.

## Table of contents
- Injection
- Evasion
- Anti-Debugging
- Internet / C2
- Spying
- Ransomware / Crypto
- Enumeration / Discovery
- Helper (file / registry / process / persistence)
- High-signal combinations

---

## Injection
Writing code into another process and executing it. **Risk: high.**

VirtualAllocEx, VirtualAlloc, VirtualProtect, VirtualProtectEx, WriteProcessMemory,
ReadProcessMemory, CreateRemoteThread, CreateRemoteThreadEx, NtCreateThreadEx, RtlCreateUserThread,
QueueUserAPC, NtQueueApcThread, SetThreadContext, GetThreadContext, Wow64SetThreadContext,
SuspendThread, ResumeThread, NtMapViewOfSection, NtUnmapViewOfSection, MapViewOfFile,
NtCreateSection, OpenProcess, NtWriteVirtualMemory, NtAllocateVirtualMemory,
NtProtectVirtualMemory, RtlMoveMemory, LdrLoadDll, GetProcAddress, LoadLibraryA/W/Ex.

(Process **hollowing** = CreateProcess in a suspended state + NtUnmapViewOfSection +
WriteProcessMemory + SetThreadContext + ResumeThread.)

## Evasion
Hiding activity or tampering with defenses. **Risk: medium–high.**

VirtualProtect (making memory RWX), SetEnvironmentVariable, NtSetInformationProcess,
NtSetInformationThread (e.g., hiding threads from debuggers), Wow64DisableWow64FsRedirection,
DeleteFile (self-deletion of dropper), SetFileAttributes (hiding files),
CreateProcess with legitimate-looking names.

## Anti-Debugging
Detecting analysis/debugging environments. **Risk: medium–high.**

IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess (ProcessDebugPort/Flags),
OutputDebugString, GetTickCount, GetTickCount64, QueryPerformanceCounter,
QueryPerformanceFrequency, GetSystemTimeAsFileTime (timing checks), NtSetInformationThread
(ThreadHideFromDebugger), FindWindow (looking for analysis tools), Sleep / NtDelayExecution
(sandbox-timeout evasion).

## Internet / C2
Network communication, downloads, exfiltration. **Risk: high.**

InternetOpen, InternetOpenUrl, InternetConnect, InternetReadFile, InternetWriteFile,
HttpOpenRequest, HttpSendRequest, HttpAddRequestHeaders, WinHttpOpen, WinHttpConnect,
WinHttpSendRequest, URLDownloadToFile, URLDownloadToCacheFile, URLOpenStream, FtpPutFile,
WSAStartup, socket, connect, send, recv, bind, listen, accept, gethostbyname, WSASocket,
closesocket, DnsQuery, InternetSetOption.

## Spying
Keylogging, screen/clipboard/audio capture. **Risk: high.**

SetWindowsHookEx, CallNextHookEx, GetAsyncKeyState, GetKeyState, GetKeyboardState,
GetForegroundWindow, GetRawInputData, RegisterRawInputDevices, GetClipboardData, OpenClipboard,
GetDC, GetWindowDC, BitBlt, StretchBlt (screen capture), GetKeyNameText, MapVirtualKey.

## Ransomware / Crypto
Cryptographic functions used to encrypt victim files. **Risk: high (critical in context).**

CryptAcquireContext, CryptGenKey, CryptDeriveKey, CryptEncrypt, CryptDecrypt, CryptHashData,
CryptCreateHash, CryptGenRandom, EncryptFile, CryptSetKeyParam, CryptDestroyKey,
BCryptEncrypt, BCryptGenRandom. Combined with file enumeration (below) and shadow-copy deletion
(`vssadmin`/WMI), this strongly indicates ransomware.

## Enumeration / Discovery
Learning about the system, processes, files, network. **Risk: low–medium.**

CreateToolhelp32Snapshot, Process32First/Next, Module32First/Next, Thread32First/Next,
EnumProcesses, EnumProcessModules, GetComputerName, GetUserName, GetSystemInfo,
GetNativeSystemInfo, GetVersionEx, RtlGetVersion, FindFirstFile, FindNextFile, GetLogicalDrives,
GetDriveType, NetShareEnum, GetAdaptersInfo, RegEnumKey, RegEnumValue, IsWoW64Process,
GetSystemDefaultLangId, GetThreadLocale (often used for victim-locale checks / evasion).

## Helper (file / registry / process / persistence)
Not malicious alone, but the machinery malware relies on. **Risk: low (context-dependent).**

File: CreateFile, ReadFile, WriteFile, CopyFile, MoveFile, DeleteFile, GetTempPath,
GetTempFileName, SetFileTime.

Registry: RegOpenKey, RegCreateKey, RegSetValueEx, RegSetKeyValue, RegGetValue, RegDeleteKey,
RegDeleteValue. **Persistence** when targeting Run/RunOnce keys, Services, or Winlogon.

Process/service: CreateProcess, ShellExecute, WinExec, CreateService, OpenSCManager,
StartService, CreateMutex (campaign "only run once" markers — mutex *names* are great IOCs).

Privilege: OpenProcessToken, AdjustTokenPrivileges, LookupPrivilegeValue, ImpersonateLoggedOnUser,
DuplicateToken (privilege escalation / token theft).

---

## High-signal combinations
Call these out explicitly when you see them — they convict where single APIs cannot.

| Combination | Implies |
|---|---|
| VirtualAllocEx + WriteProcessMemory + CreateRemoteThread | Classic process injection (T1055) |
| CreateProcess(suspended) + NtUnmapViewOfSection + SetThreadContext + ResumeThread | Process hollowing (T1055.012) |
| CryptEncrypt + FindFirstFile/FindNextFile + GetLogicalDrives | File-encrypting ransomware (T1486) |
| RegSetValueEx targeting a Run key | Registry persistence (T1547.001) |
| CreateService + StartService | Service persistence (T1543.003) |
| SetWindowsHookEx(WH_KEYBOARD) + GetAsyncKeyState | Keylogging (T1056.001) |
| GetDC + BitBlt | Screen capture (T1113) |
| InternetConnect/WinHttp* + regular timing | C2 / beaconing (T1071) |
| URLDownloadToFile + ShellExecute/CreateProcess | Downloader/dropper executing a second stage (T1105) |
| OpenProcess("lsass") + ReadProcessMemory | Credential dumping from LSASS (T1003.001) |
| IsDebuggerPresent / NtQueryInformationProcess + timing checks | Anti-analysis / debugger evasion (T1622) |
