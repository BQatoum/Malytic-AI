"""
Static analysis extractor layer.

Runs raw-fact extraction tools on a sample file and returns a structured dict.
No interpretation, no verdicts — that is Claude's job downstream.

Each extractor is isolated: a failure records {"error": "..."} under that tool's
key and in extraction_errors while all other extractors continue.

CLI usage:
    python -m backend.app.services.static_extractors <file>
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_STRINGS_CAP = 500  # max strings returned per type (ASCII / Unicode)

_ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
_WIDE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

_MACHINE_TYPES: dict[int, str] = {
    0x014C: "x86",
    0x0200: "IA64",
    0x8664: "x64",
    0x01C0: "ARM",
    0xAA64: "ARM64",
    0x01C4: "ARMv7",
}

_SUBSYSTEMS: dict[int, str] = {
    0: "UNKNOWN",
    1: "NATIVE",
    2: "WINDOWS_GUI",
    3: "WINDOWS_CUI",
    5: "OS2_CUI",
    7: "POSIX_CUI",
    9: "WINDOWS_CE_GUI",
    10: "EFI_APPLICATION",
    11: "EFI_BOOT_SERVICE_DRIVER",
    12: "EFI_RUNTIME_DRIVER",
    13: "EFI_ROM",
    14: "XBOX",
    16: "WINDOWS_BOOT_APPLICATION",
}

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_RULES_DIR = _PROJECT_ROOT / "rules"
_DEFAULT_CAPA_RULES = _PROJECT_ROOT / "capa-rules"


# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------

def _entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0–8.0)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# ---------------------------------------------------------------------------
# Extractor 1 — Hashes
# ---------------------------------------------------------------------------

def _run_hashes(data: bytes) -> dict:
    # Inline rather than importing sample_intake to avoid its top-level
    # `import magic` pulling in the libmagic system dependency here.
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


# ---------------------------------------------------------------------------
# Extractor 2 — pefile (PE structure)
# ---------------------------------------------------------------------------

def _run_pe_info(data: bytes) -> dict:
    try:
        import pefile  # noqa: PLC0415
    except ImportError:
        return {
            "is_pe": False,
            "overall_entropy": round(_entropy(data), 4),
            "sections": [], "imports": {}, "exports": [], "overlay": None,
            "error": "pefile not installed",
        }

    result: dict = {
        "is_pe": False,
        "architecture": None,
        "subsystem": None,
        "compile_timestamp": None,
        "overall_entropy": round(_entropy(data), 4),
        "sections": [],
        "imports": {},
        "exports": [],
        "overlay": None,
    }

    # pefile.PE raises PEFormatError for non-PE files — let it propagate to the
    # per-tool except block in extract_static.
    pe = pefile.PE(data=data)

    result["is_pe"] = True

    # Architecture
    machine = pe.FILE_HEADER.Machine
    result["architecture"] = _MACHINE_TYPES.get(machine, f"0x{machine:04x}")

    # Subsystem
    if hasattr(pe, "OPTIONAL_HEADER"):
        sub = pe.OPTIONAL_HEADER.Subsystem
        result["subsystem"] = _SUBSYSTEMS.get(sub, f"0x{sub:04x}")

    # Compile timestamp → ISO-8601 UTC
    ts_raw = pe.FILE_HEADER.TimeDateStamp
    try:
        if ts_raw:
            result["compile_timestamp"] = datetime.fromtimestamp(
                ts_raw, tz=timezone.utc
            ).isoformat()
    except (ValueError, OSError, OverflowError):
        result["compile_timestamp"] = f"0x{ts_raw:08x} (out of range)"

    # Sections
    for sec in pe.sections:
        name = sec.Name.rstrip(b"\x00").decode("latin-1", errors="replace")
        result["sections"].append({
            "name": name,
            "virtual_size": sec.Misc_VirtualSize,
            "raw_size": sec.SizeOfRawData,
            "entropy": round(sec.get_entropy(), 4),
        })

    # Imports — full IAT grouped by DLL name
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = (
                entry.dll.decode("latin-1", errors="replace")
                if entry.dll else "unknown"
            )
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode("latin-1", errors="replace"))
                else:
                    funcs.append(f"#{imp.ordinal}")
            result["imports"][dll] = funcs

    # Exports
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                result["exports"].append(
                    exp.name.decode("latin-1", errors="replace")
                )
            else:
                result["exports"].append(f"#{exp.ordinal}")

    # Overlay — data appended after the last section's raw bytes
    if pe.sections:
        last_end = max(
            s.PointerToRawData + s.SizeOfRawData for s in pe.sections
        )
        if 0 < last_end < len(data):
            ov = data[last_end:]
            result["overlay"] = {
                "offset": last_end,
                "size": len(ov),
                "entropy": round(_entropy(ov), 4),
            }

    pe.close()
    return result


# ---------------------------------------------------------------------------
# Extractor 3 — capa (capability detection → ATT&CK / MBC)
# ---------------------------------------------------------------------------

def _run_capabilities(file_path: str) -> dict:
    from ..config import settings  # noqa: PLC0415
    if not settings.enable_capa:
        return {"enabled": False, "matches": [], "note": "capa disabled"}

    rules_path = os.getenv("CAPA_RULES_PATH", str(_DEFAULT_CAPA_RULES))
    result: dict = {
        "rules_path": rules_path,
        "rules_found": Path(rules_path).is_dir(),
        "matches": [],
    }

    if not result["rules_found"]:
        result["error"] = (
            f"capa rules directory not found at '{rules_path}'. "
            "Run `capa --update` to download rules, or clone "
            "https://github.com/mandiant/capa-rules into ./capa-rules, "
            "or point CAPA_RULES_PATH at an existing rules directory."
        )
        return result

    if not shutil.which("capa"):
        result["error"] = (
            "capa binary not found in PATH. "
            "Install with: pip install flare-capa"
        )
        return result

    proc = subprocess.run(
        ["capa", "--json", "--rules", rules_path, file_path],
        capture_output=True,
        text=True,
        timeout=180,
    )

    # Exit 0 = capabilities found; 1 = no capabilities matched; others = error
    if proc.returncode not in (0, 1):
        result["error"] = (
            f"capa exited {proc.returncode}. "
            f"stderr: {proc.stderr[:500]}"
        )
        return result

    if not proc.stdout.strip():
        return result  # empty output with exit 0/1 = no matches

    try:
        capa_data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        result["error"] = f"capa produced invalid JSON: {exc}"
        return result

    for rule_name, rule_info in capa_data.get("rules", {}).items():
        meta = rule_info.get("meta", {})

        # ATT&CK — capa has emitted both dict-of-fields and list formats
        attack: list[dict] = []
        for att in meta.get("attack", []):
            if isinstance(att, dict):
                attack.append({
                    "tactic": att.get("tactic", ""),
                    "technique": att.get("technique", ""),
                    "technique_id": att.get("technique-id", att.get("id", "")),
                })

        # MBC — handle dict, list/tuple, or plain string entries
        mbc: list[str] = []
        for m in meta.get("mbc", []):
            if isinstance(m, dict):
                obj = m.get("objective", m.get("category", ""))
                beh = m.get("behavior", m.get("name", ""))
                bid = m.get("id", "")
                mbc.append(f"{obj}::{beh}" + (f" [{bid}]" if bid else ""))
            elif isinstance(m, (list, tuple)):
                mbc.append("::".join(str(x) for x in m))
            else:
                mbc.append(str(m))

        result["matches"].append({
            "name": rule_name,
            "namespace": meta.get("namespace", ""),
            "attack": attack,
            "mbc": mbc,
        })

    return result


# ---------------------------------------------------------------------------
# Extractor 4 — YARA
# ---------------------------------------------------------------------------

def _run_yara(file_path: str) -> list:
    try:
        import yara  # noqa: PLC0415
    except ImportError:
        raise RuntimeError("yara-python not installed")

    rule_files = sorted(
        list(_RULES_DIR.glob("*.yar")) + list(_RULES_DIR.glob("*.yara"))
    )
    if not rule_files:
        return []  # empty rules dir is valid — not an error

    compiled = yara.compile(
        filepaths={f.stem: str(f) for f in rule_files}
    )
    raw_matches = compiled.match(file_path)

    output = []
    for m in raw_matches:
        strings_out: list[dict] = []
        for s in m.strings:
            if hasattr(s, "instances"):
                # yara-python 4.x: StringMatch object with .instances list
                for inst in s.instances:
                    strings_out.append({
                        "identifier": s.identifier,
                        "offset": inst.offset,
                        "data": inst.matched_data.hex(),
                    })
            else:
                # yara-python 3.x: (offset, identifier, data) tuple
                off, ident, dat = s
                strings_out.append({
                    "identifier": ident,
                    "offset": off,
                    "data": dat.hex() if isinstance(dat, bytes) else str(dat),
                })
        output.append({
            "rule": m.rule,
            "namespace": m.namespace,
            "tags": list(m.tags),
            "meta": dict(m.meta),
            "strings": strings_out,
        })
    return output


# ---------------------------------------------------------------------------
# Extractor 5 — DIE (Detect-It-Easy: packer / compiler / linker identification)
# ---------------------------------------------------------------------------

# Types that indicate the sample is packed, protected, or obfuscated — the
# highest-priority finding in static packing analysis.
_DIE_PACKER_TYPES: frozenset[str] = frozenset({
    "packer", "protector", "crypter", "cryptor",
    "obfuscator", ".net obfuscator", ".net compressor",
    "virtual machine", "sfx", "compressor", "dongle protection",
})

_DIE_TOOL_TYPES: frozenset[str] = frozenset({"tool", "pe tool", "sign tool"})


def _run_die(file_path: str) -> dict:
    from ..config import settings  # noqa: PLC0415
    if not settings.enable_die:
        return {"enabled": False, "note": "DIE disabled"}

    if not shutil.which("diec"):
        return {
            "enabled": True,
            "error": (
                "diec not found in PATH. "
                "Install from https://github.com/horsicq/DIE-engine/releases"
            ),
        }

    try:
        proc = subprocess.run(
            ["diec", "-j", file_path],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return {"enabled": True, "error": "DIE timed out after 60s"}

    if proc.returncode != 0:
        return {
            "enabled": True,
            "error": f"diec exited {proc.returncode}: {proc.stderr[:500]}",
        }

    if not proc.stdout.strip():
        return {"enabled": True, "error": "diec produced no output"}

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return {"enabled": True, "error": f"diec produced invalid JSON: {exc}"}

    # Aggregate across all detects entries (DIE may emit multiple for
    # container formats or multi-arch files).
    filetypes: list[str] = []
    all_detections: list[dict] = []

    for det in data.get("detects", []):
        ft = det.get("filetype", "")
        if ft and ft not in filetypes:
            filetypes.append(ft)
        for val in det.get("values", []):
            if isinstance(val, dict):
                all_detections.append({
                    "type":    val.get("type", ""),
                    "name":    val.get("name", ""),
                    "version": val.get("version", ""),
                    "info":    val.get("info", ""),
                })

    # Group by type so packers are immediately visible.
    packers:   list[dict] = []
    compilers: list[dict] = []
    linkers:   list[dict] = []
    tools:     list[dict] = []
    other:     list[dict] = []

    for det in all_detections:
        t = det["type"].lower()
        if t in _DIE_PACKER_TYPES:
            packers.append(det)
        elif t == "compiler":
            compilers.append(det)
        elif t == "linker":
            linkers.append(det)
        elif t in _DIE_TOOL_TYPES:
            tools.append(det)
        else:
            other.append(det)

    return {
        "enabled":   True,
        "filetype":  ", ".join(filetypes) if filetypes else "unknown",
        "packers":   packers,
        "compilers": compilers,
        "linkers":   linkers,
        "tools":     tools,
        "other":     other,
    }


# ---------------------------------------------------------------------------
# Extractor 6 — FLOSS (deobfuscated / hidden strings via emulation)
# ---------------------------------------------------------------------------

_FLOSS_CAP = 200  # max strings stored per category (extractor 6)


def _run_floss(file_path: str) -> dict:
    from ..config import settings  # noqa: PLC0415
    if not settings.enable_floss:
        return {"enabled": False, "note": "FLOSS disabled"}

    if not shutil.which("floss"):
        return {
            "enabled": True,
            "error": "floss binary not found in PATH; install with: pip install flare-floss",
        }

    try:
        proc = subprocess.run(
            ["floss", "--json", file_path],
            capture_output=True,
            text=True,
            timeout=settings.floss_timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "enabled": True,
            "error": f"FLOSS timed out after {settings.floss_timeout}s",
        }

    if proc.returncode != 0:
        return {
            "enabled": True,
            "error": f"floss exited {proc.returncode}: {proc.stderr[:500]}",
        }

    if not proc.stdout.strip():
        return {"enabled": True, "error": "floss produced no output"}

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return {"enabled": True, "error": f"floss produced invalid JSON: {exc}"}

    strings_block = data.get("strings", {})

    def _pluck(lst: list) -> list[str]:
        """Extract the string value from each FLOSS result object."""
        return [
            entry["string"]
            for entry in lst
            if isinstance(entry, dict) and entry.get("string")
        ]

    stack    = _pluck(strings_block.get("stack_strings",   []))
    tight    = _pluck(strings_block.get("tight_strings",   []))
    decoded  = _pluck(strings_block.get("decoded_strings", []))
    language = _pluck(strings_block.get("language_strings",[]))
    static   = strings_block.get("static_strings", [])  # count only — already in "strings"

    truncated = any(
        len(x) > _FLOSS_CAP for x in (stack, tight, decoded, language)
    )

    return {
        "enabled": True,
        "stack_strings":      stack[:_FLOSS_CAP],
        "tight_strings":      tight[:_FLOSS_CAP],
        "decoded_strings":    decoded[:_FLOSS_CAP],
        "language_strings":   language[:_FLOSS_CAP],
        "static_strings_count": len(static),
        "total_stack":    len(stack),
        "total_tight":    len(tight),
        "total_decoded":  len(decoded),
        "total_language": len(language),
        "truncated":      truncated,
        "cap_per_category": _FLOSS_CAP,
    }


# ---------------------------------------------------------------------------
# Extractor 6 — Strings (ASCII + Unicode, stdlib only)
# ---------------------------------------------------------------------------

def _run_strings(data: bytes) -> dict:
    ascii_all = [
        m.group().decode("ascii", errors="replace")
        for m in _ASCII_RE.finditer(data)
    ]

    unicode_all: list[str] = []
    for m in _WIDE_RE.finditer(data):
        decoded = m.group().decode("utf-16-le", errors="ignore").rstrip("\x00")
        if decoded:
            unicode_all.append(decoded)

    truncated = len(ascii_all) > _STRINGS_CAP or len(unicode_all) > _STRINGS_CAP
    return {
        "ascii": ascii_all[:_STRINGS_CAP],
        "unicode": unicode_all[:_STRINGS_CAP],
        "total_ascii_found": len(ascii_all),
        "total_unicode_found": len(unicode_all),
        "truncated": truncated,
        "cap_per_type": _STRINGS_CAP,
    }


# ---------------------------------------------------------------------------
# Extractor — Office documents (olevba + oleid + mraptor)
# ---------------------------------------------------------------------------

def _run_office_info(file_path: str) -> dict:
    """
    Run oletools against an Office document and return structured macro analysis.
    olevba  — VBA source, auto-exec triggers, suspicious keywords, IOCs.
    oleid   — high-level risk indicators.
    mraptor — macro maliciousness heuristic.
    """
    from oletools.olevba import VBA_Parser  # lazy: keeps startup fast on PE-only runs
    from oletools.oleid import OleID
    from oletools.mraptor import MacroRaptor

    result: dict = {
        "has_macros": False,
        "macros": [],
        "auto_exec_triggers": [],
        "suspicious_keywords": [],
        "iocs": {"urls": [], "ips": [], "other": []},
        "oleid_flags": [],
        "mraptor_verdict": {"suspicious": False, "triggering_keyword": None},
        "embedded_objects": [],
        "dde_links": [],
        "remote_template": None,
    }

    data = Path(file_path).read_bytes()

    # ── olevba ───────────────────────────────────────────────────────────────
    try:
        vba = VBA_Parser(file_path, data=data)
        result["has_macros"] = vba.detect_vba_macros()

        if result["has_macros"]:
            macros = []
            all_code_parts: list[str] = []
            for (_, stream_path, vba_filename, vba_code) in vba.extract_macros():
                macros.append({
                    "stream": stream_path,
                    "filename": vba_filename,
                    "code": vba_code,
                })
                all_code_parts.append(vba_code)
            result["macros"] = macros

            auto_exec: set[str] = set()
            suspicious_kw: list[dict] = []
            urls: list[str] = []
            ips: list[str] = []
            other_iocs: list[str] = []

            for (kw_type, keyword, description) in vba.analyze_macros():
                kw_type_str = str(kw_type)
                if "AutoExec" in kw_type_str:
                    auto_exec.add(keyword)
                elif "Suspicious" in kw_type_str:
                    suspicious_kw.append({"keyword": keyword, "description": description})
                elif "IOC" in kw_type_str or "Url" in kw_type_str:
                    kl = keyword.lower()
                    if kl.startswith("http"):
                        urls.append(keyword)
                    elif re.match(r"\d{1,3}(?:\.\d{1,3}){3}", keyword):
                        ips.append(keyword)
                    else:
                        other_iocs.append(keyword)

            result["auto_exec_triggers"] = sorted(auto_exec)
            result["suspicious_keywords"] = suspicious_kw
            result["iocs"]["urls"] = list(dict.fromkeys(urls))
            result["iocs"]["ips"] = list(dict.fromkeys(ips))
            result["iocs"]["other"] = list(dict.fromkeys(other_iocs))

            # mraptor on combined code
            combined = "\n".join(all_code_parts)
            mr = MacroRaptor(combined)
            mr.scan()
            result["mraptor_verdict"] = {
                "suspicious": bool(mr.suspicious),
                "triggering_keyword": getattr(mr, "triggering_keyword", None),
            }

        vba.close()
    except Exception as exc:
        result["olevba_error"] = f"{type(exc).__name__}: {exc}"

    # ── oleid ────────────────────────────────────────────────────────────────
    try:
        oid = OleID(file_path)
        indicators = oid.check()
        flags = []
        for ind in indicators:
            val = ind.value
            if val not in (False, None, 0, "", "N/A"):
                risk_str = ""
                try:
                    risk_str = str(ind.risk.name) if hasattr(ind.risk, "name") else str(ind.risk)
                except Exception:
                    pass
                flags.append({
                    "id": str(ind.id),
                    "name": str(ind.name),
                    "value": str(val),
                    "risk": risk_str,
                })
        result["oleid_flags"] = flags
    except Exception as exc:
        result["oleid_error"] = f"{type(exc).__name__}: {exc}"

    return result


# ---------------------------------------------------------------------------
# Extractor — PDF documents (pikepdf structural analysis)
# ---------------------------------------------------------------------------

#: PDF element names that signal potential malicious functionality.
_PDF_SUSPICIOUS_NAMES: frozenset[str] = frozenset({
    "/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch",
    "/EmbeddedFile", "/EmbeddedFiles", "/URI", "/AcroForm",
    "/RichMedia", "/XFA", "/SubmitForm", "/ImportData",
    "/GoToR", "/GoToE",
})


def _run_pdf_info(file_path: str) -> dict:
    """
    Extract PDF structural analysis using pikepdf.

    Surfaces: JavaScript source, OpenAction/AA auto-execution, Launch actions,
    embedded files (with hashes), URIs, and pdfid-style element counts.
    These are the primary attack vectors in malicious PDFs.
    """
    result: dict = {
        "pdf_version": "",
        "page_count": 0,
        "object_count": 0,
        "is_encrypted": False,
        "metadata": {},
        "suspicious_elements": {},
        "javascript": [],
        "open_actions": [],
        "additional_actions": [],
        "launch_actions": [],
        "embedded_files": [],
        "uris": [],
        "errors": [],
    }

    try:
        import pikepdf  # noqa: PLC0415
        from pikepdf import Array, Dictionary, Stream  # noqa: PLC0415
    except ImportError:
        result["errors"].append("pikepdf not installed; install with: pip install pikepdf")
        return result

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _read_stream(obj) -> str:
        try:
            return obj.read_bytes().decode("utf-8", errors="replace")
        except Exception:
            return "<unreadable stream>"

    def _str_val(d, key: str) -> str:
        try:
            v = d[key]
            return _read_stream(v) if isinstance(v, Stream) else str(v)
        except Exception:
            return ""

    # ── Recursive object walker ────────────────────────────────────────────────
    seen: set[tuple[int, int]] = set()

    def _walk(obj, depth: int = 0) -> None:  # noqa: C901 (complexity is inherent)
        if depth > 80:
            return

        # Deduplicate real indirect objects (objnum > 0) to break circular refs.
        # Direct objects report objgen=(0,0) — do NOT dedup them; multiple direct
        # dicts can legitimately share that sentinel and would be wrongly skipped.
        try:
            og: tuple[int, int] = obj.objgen  # type: ignore[attr-defined]
            if og[0] > 0:
                if og in seen:
                    return
                seen.add(og)
        except AttributeError:
            pass  # no objgen attribute — definitely direct, no dedup needed

        if isinstance(obj, Dictionary):
            # Check the dict's action type from /S first so we can tag this dict.
            action_type = _str_val(obj, "/S")

            for key in list(obj.keys()):
                key_str = str(key)

                # Suspicious element counting.
                if key_str in _PDF_SUSPICIOUS_NAMES:
                    result["suspicious_elements"][key_str] = (
                        result["suspicious_elements"].get(key_str, 0) + 1
                    )

                try:
                    val = obj[key]
                except Exception:
                    continue

                # ── JavaScript extraction ──────────────────────────────────────
                if key_str in ("/JS", "/JavaScript"):
                    src = _read_stream(val) if isinstance(val, Stream) else str(val)
                    if src and src not in result["javascript"]:
                        result["javascript"].append(src)

                # ── /OpenAction (runs on document open, no user click) ─────────
                elif key_str == "/OpenAction":
                    entry: dict = {"trigger": "OpenAction"}
                    try:
                        if isinstance(val, Dictionary):
                            a_type = _str_val(val, "/S")
                            entry["action_type"] = a_type
                            if a_type in ("/JavaScript", "/JS"):
                                js = _str_val(val, "/JS") or _str_val(val, "/JavaScript")
                                if js:
                                    entry["javascript"] = js
                        elif isinstance(val, Array):
                            entry["destinations"] = [str(v) for v in val]
                    except Exception:
                        pass
                    result["open_actions"].append(entry)

                # ── /AA — Additional Actions (event-triggered per page/field) ──
                elif key_str == "/AA":
                    aa_entry: dict = {}
                    try:
                        if isinstance(val, Dictionary):
                            for aa_k in list(val.keys()):
                                aa_k_str = str(aa_k)
                                try:
                                    aa_v = val[aa_k]
                                    if isinstance(aa_v, Dictionary):
                                        aa_type = _str_val(aa_v, "/S")
                                        sub: dict = {"action_type": aa_type}
                                        if aa_type in ("/JavaScript", "/JS"):
                                            js2 = _str_val(aa_v, "/JS") or _str_val(aa_v, "/JavaScript")
                                            if js2:
                                                sub["javascript"] = js2
                                        aa_entry[aa_k_str] = sub
                                except Exception:
                                    pass
                    except Exception:
                        pass
                    if aa_entry:
                        result["additional_actions"].append(aa_entry)

                # ── /URI (links, C2, phishing) ─────────────────────────────────
                elif key_str == "/URI":
                    try:
                        uri = str(val)
                        if uri and uri not in result["uris"]:
                            result["uris"].append(uri)
                    except Exception:
                        pass

                # ── /EmbeddedFile (payload carrier) ───────────────────────────
                elif key_str == "/EmbeddedFile":
                    try:
                        ef: dict = {}
                        for fn_key in ("/F", "/UF", "/Name"):
                            fn = _str_val(obj, fn_key)
                            if fn:
                                ef["filename"] = fn
                                break
                        if isinstance(val, Stream):
                            raw = val.read_bytes()
                            ef["size"] = len(raw)
                            ef["sha256"] = hashlib.sha256(raw).hexdigest()
                            ef["md5"] = hashlib.md5(raw).hexdigest()
                            ef["magic_bytes"] = raw[:4].hex()
                        result["embedded_files"].append(ef)
                    except Exception:
                        pass

                # Recurse into every value.
                try:
                    _walk(val, depth + 1)
                except Exception:
                    pass

            # ── Launch action: dict whose /S == /Launch ────────────────────────
            if action_type == "/Launch":
                la: dict = {}
                try:
                    win = obj.get("/Win")
                    if win and isinstance(win, Dictionary):
                        la["file"] = _str_val(win, "/F")
                        la["params"] = _str_val(win, "/P")
                    la["raw"] = str(obj)[:400]
                except Exception:
                    pass
                if la and la not in result["launch_actions"]:
                    result["launch_actions"].append(la)

        elif isinstance(obj, Array):
            for item in obj:
                try:
                    _walk(item, depth + 1)
                except Exception:
                    pass

        elif isinstance(obj, Stream):
            try:
                _walk(obj.stream_dict, depth + 1)
            except Exception:
                pass

    # ── Open PDF ───────────────────────────────────────────────────────────────
    try:
        pdf = pikepdf.open(file_path, suppress_warnings=True)
    except pikepdf.PasswordError:
        result["is_encrypted"] = True
        result["errors"].append(
            "PDF is password-protected; structural analysis limited to header metadata"
        )
        return result
    except Exception as exc:
        result["errors"].append(f"pikepdf open failed: {type(exc).__name__}: {exc}")
        return result

    with pdf:
        try:
            result["pdf_version"] = str(pdf.pdf_version)
        except Exception:
            pass
        try:
            result["is_encrypted"] = bool(pdf.is_encrypted)
        except Exception:
            pass
        try:
            result["page_count"] = len(pdf.pages)
        except Exception:
            pass
        try:
            result["object_count"] = len(list(pdf.objects))
        except Exception:
            pass
        try:
            if pdf.docinfo:
                result["metadata"] = {
                    str(k): str(v) for k, v in pdf.docinfo.items() if v is not None
                }
        except Exception:
            pass

        # Walk document catalog (Root) — catches named JS trees, AcroForm, etc.
        try:
            _walk(pdf.Root)
        except Exception as exc:
            result["errors"].append(f"Root walk error: {exc}")

        # Walk each page — per-page /AA and /Annots (link annotations with URIs).
        try:
            for page in pdf.pages:
                try:
                    _walk(page.obj)
                except Exception:
                    pass
        except Exception as exc:
            result["errors"].append(f"Page walk error: {exc}")

    return result


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def extract_static(file_path: str, route: str = "pe") -> dict:
    """
    Run static extractors on *file_path* and return structured raw facts.

    route="pe"     → hashes, pe_info, capabilities, yara_matches, die, floss, strings.
    route="office" → hashes, office_info (olevba/oleid/mraptor), yara_matches, strings.

    A failing extractor records its error and does not affect the others.
    """
    data = Path(file_path).read_bytes()

    # ── PDF route ─────────────────────────────────────────────────────────────
    if route == "pdf":
        errors_pdf: dict[str, str | None] = {
            "hashes": None, "pdf_info": None, "yara": None, "strings": None,
        }

        try:
            hashes_pdf = _run_hashes(data)
        except Exception as exc:
            hashes_pdf = {"md5": "", "sha1": "", "sha256": "", "error": str(exc)}
            errors_pdf["hashes"] = f"{type(exc).__name__}: {exc}"

        try:
            pdf_info = _run_pdf_info(file_path)
        except Exception as exc:
            pdf_info = {"errors": [str(exc)]}
            errors_pdf["pdf_info"] = f"{type(exc).__name__}: {exc}"

        try:
            yara_pdf = _run_yara(file_path)
        except Exception as exc:
            yara_pdf = []
            errors_pdf["yara"] = f"{type(exc).__name__}: {exc}"

        try:
            strings_pdf = _run_strings(data)
        except Exception as exc:
            strings_pdf = {
                "ascii": [], "unicode": [],
                "total_ascii_found": 0, "total_unicode_found": 0,
                "truncated": False, "cap_per_type": _STRINGS_CAP,
                "error": str(exc),
            }
            errors_pdf["strings"] = f"{type(exc).__name__}: {exc}"

        return {
            "hashes": hashes_pdf,
            "pdf_info": pdf_info,
            "yara_matches": yara_pdf,
            "strings": strings_pdf,
            "extraction_errors": errors_pdf,
        }

    # ── Office route ──────────────────────────────────────────────────────────
    if route == "office":
        errors_off: dict[str, str | None] = {
            "hashes": None, "office_info": None, "yara": None, "strings": None,
        }

        try:
            hashes_off = _run_hashes(data)
        except Exception as exc:
            hashes_off = {"md5": "", "sha1": "", "sha256": "", "error": str(exc)}
            errors_off["hashes"] = f"{type(exc).__name__}: {exc}"

        try:
            office_info = _run_office_info(file_path)
        except Exception as exc:
            office_info = {"error": str(exc)}
            errors_off["office_info"] = f"{type(exc).__name__}: {exc}"

        try:
            yara_off = _run_yara(file_path)
        except Exception as exc:
            yara_off = []
            errors_off["yara"] = f"{type(exc).__name__}: {exc}"

        try:
            strings_off = _run_strings(data)
        except Exception as exc:
            strings_off = {
                "ascii": [], "unicode": [],
                "total_ascii_found": 0, "total_unicode_found": 0,
                "truncated": False, "cap_per_type": _STRINGS_CAP,
                "error": str(exc),
            }
            errors_off["strings"] = f"{type(exc).__name__}: {exc}"

        return {
            "hashes": hashes_off,
            "office_info": office_info,
            "yara_matches": yara_off,
            "strings": strings_off,
            "extraction_errors": errors_off,
        }

    # ── PE route (original) ───────────────────────────────────────────────────
    errors: dict[str, str | None] = {
        "hashes": None,
        "pe_info": None,
        "capabilities": None,
        "yara": None,
        "die": None,
        "floss": None,
        "strings": None,
    }

    # 1. Hashes
    try:
        hashes: dict = _run_hashes(data)
    except Exception as exc:
        hashes = {"md5": "", "sha1": "", "sha256": "", "error": str(exc)}
        errors["hashes"] = f"{type(exc).__name__}: {exc}"

    # 2. pefile — PE structure, IAT, exports, overlay
    try:
        pe_info: dict = _run_pe_info(data)
    except Exception as exc:
        pe_info = {
            "is_pe": False,
            "overall_entropy": round(_entropy(data), 4),
            "sections": [], "imports": {}, "exports": [], "overlay": None,
            "error": str(exc),
        }
        errors["pe_info"] = f"{type(exc).__name__}: {exc}"

    # 3. capa — capability detection mapped to ATT&CK / MBC
    try:
        capabilities: dict = _run_capabilities(file_path)
    except Exception as exc:
        capabilities = {
            "rules_path": "", "rules_found": False, "matches": [],
            "error": str(exc),
        }
        errors["capabilities"] = f"{type(exc).__name__}: {exc}"

    # 4. YARA — rules from rules/ directory
    try:
        yara_matches: list = _run_yara(file_path)
    except Exception as exc:
        yara_matches = []
        errors["yara"] = f"{type(exc).__name__}: {exc}"

    # 5. DIE — packer / compiler / linker identification
    try:
        die: dict = _run_die(file_path)
    except Exception as exc:
        die = {"enabled": True, "error": str(exc)}
        errors["die"] = f"{type(exc).__name__}: {exc}"

    # 6. FLOSS — deobfuscated strings via emulation (stack, tight, decoded)
    try:
        floss: dict = _run_floss(file_path)
    except Exception as exc:
        floss = {"enabled": True, "error": str(exc)}
        errors["floss"] = f"{type(exc).__name__}: {exc}"

    # 7. Strings — printable ASCII and Unicode, capped
    try:
        strings: dict = _run_strings(data)
    except Exception as exc:
        strings = {
            "ascii": [], "unicode": [],
            "total_ascii_found": 0, "total_unicode_found": 0,
            "truncated": False, "cap_per_type": _STRINGS_CAP,
            "error": str(exc),
        }
        errors["strings"] = f"{type(exc).__name__}: {exc}"

    return {
        "hashes": hashes,
        "pe_info": pe_info,
        "capabilities": capabilities,
        "yara_matches": yara_matches,
        "die": die,
        "floss": floss,
        "strings": strings,
        "extraction_errors": errors,
    }


# ---------------------------------------------------------------------------
# CLI — python -m backend.app.services.static_extractors <file>
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print(
            "Usage: python -m backend.app.services.static_extractors <file>",
            file=sys.stderr,
        )
        sys.exit(1)

    result = extract_static(sys.argv[1])
    print(json.dumps(result, indent=2, default=str))
