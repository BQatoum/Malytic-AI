"""
Safe sample intake: store, hash, detect true type, route, handle archives.
Samples are treated as inert bytes — never executed.
"""
from __future__ import annotations

import hashlib
import io
import re
import shutil
import unicodedata
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import magic

from ..config import settings

# Lower number = higher priority when picking the primary file from an archive.
_ROUTE_PRIORITY: dict[str, int] = {
    "pe": 0,
    "office": 1,
    "pdf": 2,
    "script": 3,
    "archive": 4,
    "other": 5,
}

# Ordered: first prefix match wins.
_MIME_ROUTES: list[tuple[str, str]] = [
    ("application/x-dosexec", "pe"),
    ("application/x-msdownload", "pe"),
    ("application/x-executable", "pe"),
    ("application/x-pe-app", "pe"),
    ("application/pdf", "pdf"),
    ("application/zip", "archive"),
    ("application/x-zip", "archive"),
    ("application/x-rar", "archive"),
    ("application/vnd.rar", "archive"),
    ("application/x-7z-compressed", "archive"),
    ("application/x-iso9660-image", "archive"),
    ("application/x-ms-shortcut", "archive"),
    ("application/msword", "office"),
    ("application/vnd.openxmlformats-officedocument", "office"),
    ("application/vnd.ms-excel", "office"),
    ("application/vnd.ms-powerpoint", "office"),
    ("application/vnd.ms-office", "office"),
    ("application/vnd.oasis.opendocument", "office"),
    ("text/x-powershell", "script"),
    ("text/x-script", "script"),
    ("text/x-msdos-batch", "script"),
    ("application/javascript", "script"),
    ("text/javascript", "script"),
    ("application/x-javascript", "script"),
    ("text/vbscript", "script"),
    ("text/x-vbscript", "script"),
    ("text/html", "script"),  # covers HTA
]

_EXT_ROUTES: dict[str, str] = {
    ".exe": "pe",  ".dll": "pe",  ".sys": "pe",  ".scr": "pe",  ".cpl": "pe",
    ".doc": "office", ".docx": "office", ".docm": "office",
    ".xls": "office", ".xlsx": "office", ".xlsm": "office",
    ".ppt": "office", ".pptx": "office", ".pptm": "office",
    ".rtf": "office",
    ".pdf": "pdf",
    ".ps1": "script", ".psm1": "script", ".psd1": "script",
    ".vbs": "script", ".vbe": "script",
    ".js": "script",  ".jse": "script",
    ".hta": "script",
    ".bat": "script", ".cmd": "script",
    ".zip": "archive", ".rar": "archive", ".7z": "archive",
    ".iso": "archive", ".lnk": "archive",
}

# Tried in order when an archive is encrypted and no user password is provided.
_ANALYST_PASSWORDS: list[bytes | None] = [
    b"infected", b"malware", b"virus", b"password", b"", None
]


@dataclass
class SampleInfo:
    original_name: str
    stored_name: str
    stored_path: Path
    size: int
    md5: str
    sha1: str
    sha256: str
    mime_type: str
    magic_description: str
    route: str
    early_findings: list[str] = field(default_factory=list)
    archive_contents: list[str] = field(default_factory=list)
    archive_primary: str | None = None
    archive_password_used: str | None = None
    extracted_primary_stored_name: str | None = None   # relative to upload_dir, e.g. "extracted_{case_id}/AgentTesla.exe"
    extracted_primary_hashes: dict | None = None        # {md5, sha1, sha256} of the extracted primary file


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def sanitize_filename(name: str) -> str:
    """Return a filesystem-safe basename; strips all path components."""
    name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii")
    name = Path(name).name                    # drop any directory prefix
    name = re.sub(r"[^\w.\-]", "_", name)     # keep only word chars, dots, dashes
    name = re.sub(r"\.{2,}", ".", name)        # collapse consecutive dots
    name = name.lstrip(".")                    # no hidden-file names
    return name[:200] or "unnamed"


def compute_hashes(data: bytes) -> dict[str, str]:
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def detect_mime(data: bytes) -> tuple[str, str]:
    """Return (mime_type, human_description) from the first 8 KB of data."""
    sample = data[:8192]
    return magic.from_buffer(sample, mime=True), magic.from_buffer(sample)


def mime_to_route(mime: str) -> str:
    for prefix, route in _MIME_ROUTES:
        if mime.startswith(prefix):
            return route
    return "other"


# Office Open XML magic: ZIP (PK\x03\x04) with word/, xl/, or ppt/ entries.
# libmagic reports these as application/zip, so we must probe the contents.
_OOXML_PREFIXES = ("word/", "xl/", "ppt/", "[Content_Types].xml")

def _is_ooxml_office(data: bytes) -> bool:
    """Return True if data is an Office Open XML document (.docx/.docm/.xlsx etc.)."""
    if not data[:4] == b"PK\x03\x04":
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
        return any(
            any(n.startswith(p) for p in _OOXML_PREFIXES)
            for n in names
        )
    except Exception:
        return False


def ext_to_route(filename: str) -> str | None:
    return _EXT_ROUTES.get(Path(filename).suffix.lower())


# ---------------------------------------------------------------------------
# Shared archive extraction engine
# ---------------------------------------------------------------------------

@dataclass
class _Member:
    name: str
    declared_size: int  # uncompressed, from archive headers


class _UnrarMissingError(Exception):
    """unrar binary absent; caller degrades gracefully instead of raising."""


# Alias for the 4-tuple every format handler returns.
_ArchiveResult = tuple[str, list[str], str | None, str | None]
# (inner_route, contents_list, primary_filename, password_used_str)


def _build_password_candidates(user_password: str | None) -> list[bytes | None]:
    candidates: list[bytes | None] = []
    if user_password:
        candidates.append(user_password.encode())
    candidates.extend(_ANALYST_PASSWORDS)
    return candidates


def _extract_archive(
    members: list[_Member],
    read_member_fn: Callable[[str], bytes],
    dest_dir: Path,
) -> tuple[list[str], list[tuple[Path, str]]]:
    """
    Single source of truth for all extraction safety.
    Guards applied: file-count limit, declared-size bomb check, path-traversal
    rejection, runtime bytes-written abort (catches spoofed headers).
    Never executes anything it writes.

    Returns (contents_list, extracted_pairs).
    Raises ValueError on any limit violation.
    """
    if len(members) > settings.max_extract_files:
        raise ValueError(
            f"Archive has {len(members)} files; limit is {settings.max_extract_files}"
        )

    total_declared = sum(m.declared_size for m in members)
    if total_declared > settings.max_extract_bytes:
        raise ValueError(
            f"Declared uncompressed size {total_declared:,} B exceeds "
            f"limit {settings.max_extract_bytes:,} B (possible archive bomb)"
        )

    dest_dir.mkdir(parents=True, exist_ok=True)

    bytes_written = 0
    contents: list[str] = []
    extracted: list[tuple[Path, str]] = []

    for member in members:
        safe_name = Path(member.name).name
        if not safe_name or safe_name in (".", ".."):
            continue

        dest_path = dest_dir / safe_name
        # Path-traversal guard: resolved path must remain inside dest_dir.
        if not str(dest_path.resolve()).startswith(str(dest_dir.resolve()) + "/"):
            continue

        member_data = read_member_fn(member.name)
        bytes_written += len(member_data)
        if bytes_written > settings.max_extract_bytes:
            raise ValueError(
                f"Extracted content exceeded {settings.max_extract_bytes:,} B "
                "during extraction (archive bomb suspected)"
            )

        dest_path.write_bytes(member_data)
        contents.append(member.name)
        extracted.append((dest_path, member.name))

    return contents, extracted


def _pick_primary(extracted: list[tuple[Path, str]]) -> tuple[str, str | None]:
    """Return (best_route, best_filename) by re-detecting MIME of extracted files."""
    best_route = "other"
    best_name: str | None = None
    for path, name in extracted:
        try:
            file_mime, _ = detect_mime(path.read_bytes())
            file_route = mime_to_route(file_mime)
        except Exception:
            file_route = "other"
        if _ROUTE_PRIORITY.get(file_route, 99) < _ROUTE_PRIORITY.get(best_route, 99):
            best_route = file_route
            best_name = name
    return best_route, best_name


# ---------------------------------------------------------------------------
# ZIP handler
# ---------------------------------------------------------------------------

def _handle_zip(
    data: bytes,
    case_id: str,
    user_password: str | None,
) -> _ArchiveResult:
    try:
        import pyzipper  # noqa: PLC0415
        zf = pyzipper.AESZipFile(io.BytesIO(data))
    except ImportError:
        raise ValueError("pyzipper is not installed; AES-encrypted ZIP support is unavailable")
    except zipfile.BadZipFile as exc:
        raise ValueError(f"Invalid ZIP archive: {exc}") from exc

    with zf:
        all_members = zf.infolist()
        files = [m for m in all_members if not m.is_dir()]
        members = [_Member(m.filename, m.file_size) for m in files]

        encrypted = any(m.flag_bits & 0x1 for m in files)
        working_pwd: bytes | None = None

        if encrypted:
            for pwd in _build_password_candidates(user_password):
                try:
                    zf.read(files[0], pwd=pwd)
                    working_pwd = pwd
                    break
                except RuntimeError:
                    continue
            else:
                raise ValueError("Archive is encrypted and no working password was found")

        def read_member_fn(name: str) -> bytes:
            return zf.read(name, pwd=working_pwd)

        dest_dir = Path(settings.upload_dir) / f"extracted_{case_id}"
        contents, extracted = _extract_archive(members, read_member_fn, dest_dir)

    best_route, best_name = _pick_primary(extracted)
    pwd_str = working_pwd.decode("utf-8", errors="replace") if working_pwd else None
    return best_route, contents, best_name, pwd_str


# ---------------------------------------------------------------------------
# 7z handler
# ---------------------------------------------------------------------------

def _handle_7z(
    data: bytes,
    case_id: str,
    user_password: str | None,
) -> _ArchiveResult:
    import lzma
    import tempfile

    try:
        import py7zr  # noqa: PLC0415
    except ImportError:
        raise ValueError("py7zr is not installed; 7z extraction is unavailable")

    # Open without password to list members and detect encryption.
    # Standard 7z archives encrypt data but not headers, so listing always works.
    try:
        with py7zr.SevenZipFile(io.BytesIO(data), mode="r") as sz:
            needs_pwd = sz.needs_password()
            ami_list = sz.list()
    except Exception as exc:
        raise ValueError(f"Invalid 7z archive: {exc}") from exc

    files = [a for a in ami_list if not a.is_directory]
    members = [_Member(a.filename, getattr(a, "uncompressed", 0) or 0) for a in files]

    # Determine working password.
    # py7zr 1.x has no per-member read(); use extractall() to a throw-away temp dir
    # as the password oracle — a wrong password raises lzma.LZMAError on decompression.
    # Each attempt opens a FRESH SevenZipFile from a fresh BytesIO.
    working_pwd_str: str | None = None
    if needs_pwd and files:
        for pwd in _build_password_candidates(user_password):
            candidate = pwd.decode("utf-8", errors="replace") if pwd else None
            try:
                with tempfile.TemporaryDirectory() as tmp:
                    with py7zr.SevenZipFile(
                        io.BytesIO(data), mode="r", password=candidate
                    ) as sz_test:
                        sz_test.extractall(path=tmp)
                working_pwd_str = candidate
                break
            except (lzma.LZMAError, Exception):
                continue
        else:
            raise ValueError("Archive is encrypted and no working password was found")

    # Real extraction: re-open fresh with confirmed password, extract to a temp dir,
    # read bytes into memory, then feed through the shared _extract_archive engine
    # (count limit, declared-size bomb check, path-traversal, runtime bytes counter).
    try:
        file_map: dict[str, bytes] = {}
        with tempfile.TemporaryDirectory() as tmp_ext:
            with py7zr.SevenZipFile(
                io.BytesIO(data), mode="r", password=working_pwd_str
            ) as sz_ext:
                sz_ext.extractall(path=tmp_ext)
            # Key by basename so read_member_fn can look up by Path(member.name).name.
            for f in Path(tmp_ext).rglob("*"):
                if f.is_file():
                    file_map[f.name] = f.read_bytes()
    except (lzma.LZMAError, Exception) as exc:
        raise ValueError(f"7z extraction failed: {exc}") from exc

    def read_member_fn(name: str) -> bytes:
        return file_map.get(Path(name).name, b"")

    dest_dir = Path(settings.upload_dir) / f"extracted_{case_id}"
    contents, extracted = _extract_archive(members, read_member_fn, dest_dir)

    best_route, best_name = _pick_primary(extracted)
    return best_route, contents, best_name, working_pwd_str


# ---------------------------------------------------------------------------
# RAR handler
# ---------------------------------------------------------------------------

def _handle_rar(
    data: bytes,
    case_id: str,
    user_password: str | None,
) -> _ArchiveResult:
    try:
        import rarfile  # noqa: PLC0415
    except ImportError:
        raise ValueError("rarfile is not installed; RAR extraction is unavailable")

    # Fail fast and gracefully if the unrar binary is absent.
    tool = getattr(rarfile, "UNRAR_TOOL", "unrar")
    if not shutil.which(tool):
        raise _UnrarMissingError(
            f"'{tool}' binary not found; install it for RAR support "
            "(apt-get install unrar). Submitting the inner file directly is an alternative."
        )

    try:
        rf = rarfile.RarFile(io.BytesIO(data))
    except rarfile.BadRarFile as exc:
        raise ValueError(f"Invalid RAR archive: {exc}") from exc
    except (rarfile.RarCannotExec, rarfile.RarExecError) as exc:
        # Binary disappeared between the which() check and open — treat as missing.
        raise _UnrarMissingError(str(exc)) from exc

    with rf:
        all_members = rf.infolist()
        files = [m for m in all_members if not m.is_dir()]
        members = [_Member(m.filename, m.file_size) for m in files]

        encrypted = rf.needs_password()
        working_pwd: bytes | None = None

        if encrypted and files:
            for pwd in _build_password_candidates(user_password):
                try:
                    if pwd is not None:
                        rf.setpassword(pwd)
                    rf.read(files[0].filename)
                    working_pwd = pwd
                    break
                except Exception:
                    continue
            else:
                raise ValueError("Archive is encrypted and no working password was found")

            if working_pwd is not None:
                rf.setpassword(working_pwd)

        def read_member_fn(name: str) -> bytes:
            return rf.read(name)

        dest_dir = Path(settings.upload_dir) / f"extracted_{case_id}"
        contents, extracted = _extract_archive(members, read_member_fn, dest_dir)

    best_route, best_name = _pick_primary(extracted)
    pwd_str = working_pwd.decode("utf-8", errors="replace") if working_pwd else None
    return best_route, contents, best_name, pwd_str


# ---------------------------------------------------------------------------
# Archive dispatcher
# ---------------------------------------------------------------------------

def _dispatch_archive(
    data: bytes,
    mime: str,
    case_id: str,
    user_password: str | None,
) -> tuple[_ArchiveResult | None, str | None]:
    """
    Route to the correct format handler.
    Returns (result, soft_error_message).
      result=None   → unsupported format (no extraction attempted)
      soft_error≠None → graceful degradation (e.g. unrar missing); result is also None
    Extraction failures (bad password, bomb) propagate as ValueError so the caller
    can record them as early findings.
    """
    mime_lower = mime.lower()
    try:
        if "zip" in mime_lower:
            return _handle_zip(data, case_id, user_password), None
        if "x-rar" in mime_lower or "vnd.rar" in mime_lower:
            return _handle_rar(data, case_id, user_password), None
        if "x-7z" in mime_lower:
            return _handle_7z(data, case_id, user_password), None
        return None, None
    except _UnrarMissingError as exc:
        return None, str(exc)
    except ValueError:
        raise  # propagate to process_sample's existing handler
    except Exception as exc:
        return None, f"Archive extraction failed unexpectedly ({type(exc).__name__}): {exc}"


def _archive_format_label(mime: str) -> str:
    m = mime.lower()
    if "zip" in m:
        return "ZIP"
    if "rar" in m:
        return "RAR"
    if "7z" in m:
        return "7z"
    return "archive"


# ---------------------------------------------------------------------------
# Main entry point (blocking — call via asyncio.to_thread from async context)
# ---------------------------------------------------------------------------

def process_sample(
    file_bytes: bytes,
    original_name: str,
    user_password: str | None,
    case_id: str,
) -> SampleInfo:
    """
    Store, hash, type-detect, and route a sample. Never executes it.
    Blocking file I/O: must be called via asyncio.to_thread in async context.
    """
    upload_dir = Path(settings.upload_dir)
    upload_dir.mkdir(parents=True, exist_ok=True)

    safe_name = sanitize_filename(original_name)
    stored_name = f"{case_id}_{safe_name}"
    stored_path = upload_dir / stored_name
    stored_path.write_bytes(file_bytes)

    hashes = compute_hashes(file_bytes)
    mime, description = detect_mime(file_bytes)
    route = mime_to_route(mime)
    ext_route = ext_to_route(original_name)

    early_findings: list[str] = []
    if ext_route and ext_route != route:
        ext = Path(original_name).suffix.lower()
        early_findings.append(
            f"Extension mismatch: '{ext}' implies route '{ext_route}' but "
            f"true MIME is '{mime}' (routing as '{route}')"
        )

    archive_contents: list[str] = []
    archive_primary: str | None = None
    archive_password_used: str | None = None

    # OOXML (.docx/.docm/.xlsx etc.) are ZIP files — libmagic returns application/zip.
    # Detect by structure before the archive dispatcher tries to extract them.
    if route == "archive" and _is_ooxml_office(file_bytes):
        route = "office"
        early_findings.append(
            "Office Open XML detected inside ZIP (OOXML magic): re-routed as 'office'"
        )

    if route == "archive":
        try:
            result, soft_error = _dispatch_archive(file_bytes, mime, case_id, user_password)
        except ValueError as exc:
            early_findings.append(f"Archive extraction failed: {exc}")
            result, soft_error = None, None

        if soft_error:
            # Graceful degradation (e.g. unrar not installed).
            early_findings.append(soft_error)
        elif result is None:
            # Format recognised as archive but not extractable (ISO, LNK, etc.).
            early_findings.append(
                f"Archive type '{mime}' cannot be extracted by this platform; "
                "submit the inner file directly for deeper analysis"
            )
        else:
            inner_route, contents, primary, pwd_used = result
            route = inner_route
            archive_contents = contents
            archive_primary = primary
            archive_password_used = pwd_used
            fmt = _archive_format_label(mime)
            pwd_note = f"; password='{pwd_used}'" if pwd_used else ""
            early_findings.append(
                f"{fmt} extracted: {len(contents)} file(s); "
                f"primary='{primary}' re-routed as '{inner_route}'{pwd_note}"
            )

    extracted_primary_stored_name: str | None = None
    extracted_primary_hashes: dict | None = None
    if archive_primary:
        primary_path = Path(settings.upload_dir) / f"extracted_{case_id}" / archive_primary
        if primary_path.exists():
            extracted_primary_stored_name = f"extracted_{case_id}/{archive_primary}"
            extracted_primary_hashes = compute_hashes(primary_path.read_bytes())

    return SampleInfo(
        original_name=original_name,
        stored_name=stored_name,
        stored_path=stored_path,
        size=len(file_bytes),
        md5=hashes["md5"],
        sha1=hashes["sha1"],
        sha256=hashes["sha256"],
        mime_type=mime,
        magic_description=description,
        route=route,
        early_findings=early_findings,
        archive_contents=archive_contents,
        archive_primary=archive_primary,
        archive_password_used=archive_password_used,
        extracted_primary_stored_name=extracted_primary_stored_name,
        extracted_primary_hashes=extracted_primary_hashes,
    )
