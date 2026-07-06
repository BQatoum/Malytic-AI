"""
VirusTotal API v3 client.

Handles file hash, domain, and IP reputation lookups. Returns raw API data
only — no interpretation. All interpretation is Claude's job downstream.

Free-tier limits: 4 requests/minute, 500/day. The caller (osint_analyzer)
inserts delays between calls; this client is stateless.

CLI:
    python -m backend.app.services.virustotal_client <sha256>
    python -m backend.app.services.virustotal_client --domain <domain>
    python -m backend.app.services.virustotal_client --ip <ip>
"""
from __future__ import annotations

import json

import httpx

from ..config import settings

_BASE_URL = "https://www.virustotal.com"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class VTError(Exception):
    """Base class for all VirusTotal client errors."""


class VTRateLimitError(VTError):
    """HTTP 429 — free tier quota exceeded (4 req/min or 500/day)."""


class VTNotFoundError(VTError):
    """HTTP 404 — hash/domain/IP not found in VirusTotal database."""


class VTAPIError(VTError):
    """Non-2xx response other than 404/429."""

    def __init__(self, status_code: int, body: str) -> None:
        self.status_code = status_code
        super().__init__(f"VirusTotal API error {status_code}: {body[:300]}")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _client() -> httpx.Client:
    if not settings.virustotal_api_key:
        raise VTError(
            "VIRUSTOTAL_API_KEY is not set. Add it to your .env file."
        )
    return httpx.Client(
        base_url=_BASE_URL,
        headers={"x-apikey": settings.virustotal_api_key},
        timeout=30.0,
        follow_redirects=True,
    )


def _raise_for_status(response: httpx.Response, indicator: str = "") -> None:
    if response.status_code == 404:
        raise VTNotFoundError(
            f"{indicator!r} not found in VirusTotal."
            if indicator
            else "Indicator not found in VirusTotal."
        )
    if response.status_code == 429:
        raise VTRateLimitError(
            "VirusTotal rate limit exceeded (HTTP 429). "
            "Free tier allows 4 requests/minute and 500/day. "
            "Increase VT_REQUEST_DELAY in .env or wait before retrying."
        )
    if not response.is_success:
        raise VTAPIError(status_code=response.status_code, body=response.text)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_file_report(sha256: str) -> dict:
    """
    Fetch a file report by SHA-256 hash.

    Returns the full ``data`` object from the API response (includes
    ``data.attributes.*`` with last_analysis_stats, last_analysis_results,
    names, meaningful_name, first_submission_date, last_analysis_date,
    reputation, tags, sandbox_verdicts, etc.).

    Raises
    ------
    VTNotFoundError   if the hash is not in the VirusTotal database
    VTRateLimitError  if the per-minute or daily quota is exceeded
    VTAPIError        on other non-2xx responses
    VTError           if the API key is missing or the network is unreachable
    """
    try:
        with _client() as client:
            response = client.get(f"/api/v3/files/{sha256}")
    except httpx.ConnectError as exc:
        raise VTError(f"Could not connect to VirusTotal: {exc}") from exc
    except httpx.TimeoutException as exc:
        raise VTError(f"VirusTotal request timed out: {exc}") from exc

    _raise_for_status(response, sha256)
    return response.json()["data"]


def get_domain_report(domain: str) -> dict:
    """
    Fetch a domain reputation report.

    Returns the full ``data`` object (attributes include last_analysis_stats,
    reputation, categories, whois, last_dns_records, popularity_ranks, etc.).

    Raises
    ------
    VTNotFoundError   if the domain is not in the VirusTotal database
    VTRateLimitError  on quota exhaustion
    VTAPIError        on other non-2xx responses
    VTError           on connection / key issues
    """
    try:
        with _client() as client:
            response = client.get(f"/api/v3/domains/{domain}")
    except httpx.ConnectError as exc:
        raise VTError(f"Could not connect to VirusTotal: {exc}") from exc
    except httpx.TimeoutException as exc:
        raise VTError(f"VirusTotal request timed out: {exc}") from exc

    _raise_for_status(response, domain)
    return response.json()["data"]


def get_ip_report(ip: str) -> dict:
    """
    Fetch an IP address reputation report.

    Returns the full ``data`` object (attributes include last_analysis_stats,
    reputation, country, as_owner, whois, last_analysis_date, etc.).

    Raises
    ------
    VTNotFoundError   if the IP is not in the VirusTotal database
    VTRateLimitError  on quota exhaustion
    VTAPIError        on other non-2xx responses
    VTError           on connection / key issues
    """
    try:
        with _client() as client:
            response = client.get(f"/api/v3/ip_addresses/{ip}")
    except httpx.ConnectError as exc:
        raise VTError(f"Could not connect to VirusTotal: {exc}") from exc
    except httpx.TimeoutException as exc:
        raise VTError(f"VirusTotal request timed out: {exc}") from exc

    _raise_for_status(response, ip)
    return response.json()["data"]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="VirusTotal API v3 client — standalone lookup",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m backend.app.services.virustotal_client <sha256>\n"
            "  python -m backend.app.services.virustotal_client --domain evil.com\n"
            "  python -m backend.app.services.virustotal_client --ip 1.2.3.4\n"
        ),
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("hash", nargs="?", metavar="SHA256", help="File SHA-256 hash")
    group.add_argument("--domain", metavar="DOMAIN", help="Domain to look up")
    group.add_argument("--ip", metavar="IP", help="IP address to look up")
    args = parser.parse_args()

    try:
        if args.hash:
            print(f"[*] Looking up file hash: {args.hash}", file=sys.stderr)
            data = get_file_report(args.hash)
        elif args.domain:
            print(f"[*] Looking up domain: {args.domain}", file=sys.stderr)
            data = get_domain_report(args.domain)
        else:
            print(f"[*] Looking up IP: {args.ip}", file=sys.stderr)
            data = get_ip_report(args.ip)
    except VTNotFoundError as exc:
        print(f"[!] NOT FOUND: {exc}", file=sys.stderr)
        sys.exit(2)
    except VTRateLimitError as exc:
        print(f"[!] RATE LIMITED: {exc}", file=sys.stderr)
        sys.exit(3)
    except VTError as exc:
        print(f"[!] ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(data, indent=2, default=str))
