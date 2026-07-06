"""
Hybrid Analysis Falcon Sandbox API v2 client.

Handles sample submission, status polling, and report retrieval. Returns raw
JSON only — no interpretation. All interpretation is Claude's job downstream.

Environment IDs (for SANDBOX_ENVIRONMENT_ID in .env):
    160 — Windows 10 64-bit (default)
    140 — Windows 11 64-bit
    120 — Windows 7 64-bit
    110 — Windows 7 32-bit (HWP Support)
    100 — Windows 7 32-bit
    330 — Linux Ubuntu 24.04 64-bit
    430 — macOS ARM64

CLI:
    python -m backend.app.services.sandbox_client <file>
    python -m backend.app.services.sandbox_client --hash <sha256>
"""
from __future__ import annotations

import gzip
import json
import time
from pathlib import Path

import httpx

from ..config import settings

_BASE_URL = "https://hybrid-analysis.com/api/v2"

# Terminal states — polling stops on either of these.
_TERMINAL_SUCCESS = "SUCCESS"
_TERMINAL_ERROR   = "ERROR"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class SandboxError(Exception):
    """Base class for all sandbox errors."""


class SandboxAPIError(SandboxError):
    """Non-2xx response from the Hybrid Analysis API."""

    def __init__(self, status_code: int, body: str, message: str = "") -> None:
        self.status_code = status_code
        self.body = body
        super().__init__(message or f"Hybrid Analysis API error {status_code}: {body[:300]}")


class SandboxQuotaError(SandboxAPIError):
    """Free-tier quota exhausted (HTTP 429 or Submission-Limits header)."""


class SandboxTimeoutError(SandboxError):
    """Polling exceeded the configured sandbox_timeout."""


class SandboxAnalysisError(SandboxError):
    """The sandbox detonated the sample but reported an ERROR state."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _client() -> httpx.Client:
    """
    Return a configured httpx.Client with the two mandatory headers.

    Instantiated per call so the API key is always read from current settings
    (important for tests that override settings).
    """
    if not settings.sandbox_api_key:
        raise SandboxError(
            "SANDBOX_API_KEY is not set. Add it to your .env file."
        )
    return httpx.Client(
        base_url=_BASE_URL,
        headers={
            "api-key":    settings.sandbox_api_key,
            "User-Agent": "Falcon Sandbox",
        },
        timeout=30.0,
        follow_redirects=True,
    )


def _raise_for_status(response: httpx.Response) -> None:
    """
    Check an httpx response and raise the appropriate exception.

    Handles quota errors before generic API errors so the caller always gets
    the most specific exception type.
    """
    if response.status_code == 429:
        raise SandboxQuotaError(
            status_code=429,
            body=response.text,
            message=(
                "Hybrid Analysis rate limit exceeded (HTTP 429). "
                "Free tier allows 30 submissions/month. "
                f"Api-Limits header: {response.headers.get('Api-Limits', 'not present')}"
            ),
        )
    if not response.is_success:
        raise SandboxAPIError(
            status_code=response.status_code,
            body=response.text,
        )


def _check_submission_quota(response: httpx.Response) -> None:
    """
    Inspect the Submission-Limits response header on a successful submission.

    Hybrid Analysis returns a JSON object in this header; if remaining == 0,
    raise SandboxQuotaError so the caller knows this was the last allowed
    submission before it's too late.
    """
    raw = response.headers.get("Submission-Limits", "")
    if not raw:
        return
    try:
        limits = json.loads(raw)
        remaining = limits.get("submissions_remaining", limits.get("remaining", None))
        if remaining is not None and int(remaining) == 0:
            raise SandboxQuotaError(
                status_code=response.status_code,
                body=raw,
                message=(
                    "Hybrid Analysis submission quota exhausted "
                    f"(Submission-Limits: {raw}). "
                    "This was your last allowed submission this month."
                ),
            )
    except (ValueError, KeyError):
        pass  # header present but unparseable — not a hard error


def _decode_report_body(response: httpx.Response) -> dict:
    """
    Parse the report response body.

    The /report/{id}/file/json endpoint returns gzip-compressed JSON.
    httpx auto-decompresses when the server sets Content-Encoding: gzip;
    fall back to manual gzip.decompress if the content is still compressed.
    """
    content_type = response.headers.get("Content-Type", "")
    body = response.content

    # If httpx didn't auto-decompress (no Content-Encoding header from server),
    # detect and decompress manually.
    if body[:2] == b"\x1f\x8b":
        body = gzip.decompress(body)

    if "application/json" in content_type or body.lstrip(b" \t\r\n").startswith(b"{"):
        return json.loads(body)

    raise SandboxAPIError(
        status_code=response.status_code,
        body=body[:200].decode("utf-8", errors="replace"),
        message=f"Unexpected Content-Type from report endpoint: {content_type!r}",
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def submit_sample(
    file_path: str,
    environment_id: int | None = None,
) -> str:
    """
    Submit a file to Hybrid Analysis for dynamic analysis.

    Parameters
    ----------
    file_path:
        Path to the sample file. Treated as inert bytes — never executed locally.
    environment_id:
        Sandbox VM to use. Defaults to settings.sandbox_environment_id
        (Windows 10 64-bit / ID 160).

    Returns
    -------
    str
        The job_id to use for polling and report retrieval.

    Raises
    ------
    SandboxQuotaError   if the monthly submission quota is exhausted
    SandboxAPIError     on any other non-2xx response
    SandboxError        if the API key is missing or the network is unreachable
    """
    env_id = environment_id or settings.sandbox_environment_id
    path = Path(file_path)

    try:
        with _client() as client:
            with path.open("rb") as fh:
                response = client.post(
                    "/submit/file",
                    files={"file": (path.name, fh, "application/octet-stream")},
                    data={"environment_id": str(env_id)},
                )
    except httpx.ConnectError as exc:
        raise SandboxError(f"Could not connect to Hybrid Analysis: {exc}") from exc
    except httpx.TimeoutException as exc:
        raise SandboxError(f"Request to Hybrid Analysis timed out: {exc}") from exc

    _raise_for_status(response)
    _check_submission_quota(response)

    data = response.json()
    job_id: str | None = data.get("job_id")
    if not job_id:
        raise SandboxAPIError(
            status_code=response.status_code,
            body=response.text,
            message=f"Submit response missing 'job_id'. Full response: {data}",
        )
    return job_id


def poll_status(job_id: str) -> str:
    """
    Return the current analysis state for *job_id*.

    Known states: IN_QUEUE, IN_PROGRESS, SUCCESS, ERROR.
    Unknown states are returned as-is so the caller can decide.

    Raises
    ------
    SandboxAPIError  on non-2xx response
    SandboxError     on network error
    """
    try:
        with _client() as client:
            response = client.get(f"/report/{job_id}/state")
    except httpx.ConnectError as exc:
        raise SandboxError(f"Could not connect to Hybrid Analysis: {exc}") from exc
    except httpx.TimeoutException as exc:
        raise SandboxError(f"Request to Hybrid Analysis timed out: {exc}") from exc

    _raise_for_status(response)
    return response.json().get("state", "UNKNOWN")


def get_report(job_id: str) -> dict:
    """
    Fetch the full analysis report JSON for a completed job.

    Returns the raw report dict — no parsing or interpretation.

    Raises
    ------
    SandboxAPIError  if the report is not available or the request fails
    SandboxError     on network error
    """
    try:
        with _client() as client:
            response = client.get(f"/report/{job_id}/file/json")
    except httpx.ConnectError as exc:
        raise SandboxError(f"Could not connect to Hybrid Analysis: {exc}") from exc
    except httpx.TimeoutException as exc:
        raise SandboxError(f"Request to Hybrid Analysis timed out: {exc}") from exc

    _raise_for_status(response)
    return _decode_report_body(response)


def get_report_by_hash(sha256: str) -> dict:
    """
    Fetch an existing public report overview by SHA-256 hash.

    Does NOT submit anything. Use this to pull a real, already-analyzed
    report for testing interpretation without uploading a sample.

    Returns
    -------
    dict
        The overview JSON from GET /overview/{sha256}.

    Raises
    ------
    SandboxAPIError  if the hash is not found (404) or the request fails
    SandboxError     on network error
    """
    try:
        with _client() as client:
            response = client.get(f"/overview/{sha256}")
    except httpx.ConnectError as exc:
        raise SandboxError(f"Could not connect to Hybrid Analysis: {exc}") from exc
    except httpx.TimeoutException as exc:
        raise SandboxError(f"Request to Hybrid Analysis timed out: {exc}") from exc

    if response.status_code == 404:
        raise SandboxAPIError(
            status_code=404,
            body=response.text,
            message=(
                f"SHA-256 {sha256!r} not found in the Hybrid Analysis database. "
                "The sample may not have been submitted publicly, or the hash may be incorrect."
            ),
        )
    _raise_for_status(response)
    return response.json()


def analyze_and_wait(file_path: str) -> dict:
    """
    Submit a sample and block until analysis completes, then return the report.

    Polls every settings.sandbox_poll_interval seconds up to
    settings.sandbox_timeout seconds total.

    This is synchronous (uses time.sleep). Call via asyncio.to_thread in
    async contexts.

    Returns
    -------
    dict
        Raw report JSON from get_report().

    Raises
    ------
    SandboxQuotaError      if the submission quota is exhausted
    SandboxAnalysisError   if the sandbox reports an ERROR state
    SandboxTimeoutError    if analysis does not complete within sandbox_timeout
    SandboxAPIError        on other API errors
    SandboxError           on network errors
    """
    job_id = submit_sample(file_path)

    deadline = time.monotonic() + settings.sandbox_timeout
    interval = settings.sandbox_poll_interval

    while True:
        state = poll_status(job_id)

        if state == _TERMINAL_SUCCESS:
            return get_report(job_id)

        if state == _TERMINAL_ERROR:
            raise SandboxAnalysisError(
                f"Hybrid Analysis reported ERROR state for job {job_id!r}. "
                "The sandbox may have failed to execute the sample."
            )

        if time.monotonic() >= deadline:
            raise SandboxTimeoutError(
                f"Analysis of job {job_id!r} did not complete within "
                f"{settings.sandbox_timeout}s (last state: {state!r}). "
                "Increase SANDBOX_TIMEOUT in .env or check the Hybrid Analysis dashboard."
            )

        time.sleep(interval)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Hybrid Analysis sandbox client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m backend.app.services.sandbox_client sample.exe\n"
            "  python -m backend.app.services.sandbox_client --hash <sha256>\n"
        ),
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("file", nargs="?", help="Sample file to submit and analyze")
    group.add_argument("--hash", metavar="SHA256", help="Fetch existing report by SHA-256")
    args = parser.parse_args()

    try:
        if args.hash:
            print(f"[*] Fetching existing report for {args.hash} …", file=sys.stderr)
            report = get_report_by_hash(args.hash)
        else:
            print(f"[*] Submitting {args.file} …", file=sys.stderr)
            print(
                f"[*] Polling every {settings.sandbox_poll_interval}s "
                f"(timeout {settings.sandbox_timeout}s) …",
                file=sys.stderr,
            )
            report = analyze_and_wait(args.file)
            print("[+] Analysis complete.", file=sys.stderr)

        print(json.dumps(report, indent=2, default=str))

    except SandboxQuotaError as exc:
        print(f"[!] QUOTA ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
    except SandboxTimeoutError as exc:
        print(f"[!] TIMEOUT: {exc}", file=sys.stderr)
        sys.exit(3)
    except SandboxError as exc:
        print(f"[!] ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
