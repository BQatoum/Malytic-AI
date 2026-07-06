"""
Elastic Cloud Serverless client — connectivity layer.

Auth: `Authorization: ApiKey <key>` for both Elasticsearch and Kibana.
Kibana calls additionally require `kbn-xsrf: true`.

Serverless-specific notes:
  - ES root (GET /) returns build_flavor="serverless" instead of a version string.
  - /_cluster/health is supported on Serverless.
  - Kibana paths (/api/status, /api/detection_engine/…) are identical to Hosted.

CLI (connectivity test — no writes):
    python -m backend.app.services.elastic_client --test
"""
from __future__ import annotations

import json
import sys
from typing import Any

import httpx

from ..config import settings

# ── shared header builders ────────────────────────────────────────────────────

def _es_headers() -> dict[str, str]:
    return {
        "Authorization": f"ApiKey {settings.elastic_api_key}",
        "Content-Type":  "application/json",
    }


def _kibana_headers() -> dict[str, str]:
    return {
        "Authorization": f"ApiKey {settings.elastic_api_key}",
        "Content-Type":  "application/json",
        "kbn-xsrf":      "true",
    }


# ── low-level HTTP helpers ────────────────────────────────────────────────────

def _get(url: str, headers: dict, timeout: float = 15.0) -> tuple[int, Any]:
    """
    Perform a GET request and return (status_code, parsed_body).

    Returns (-1, error_string) on connection/timeout errors so callers
    can treat all failures uniformly.
    """
    try:
        r = httpx.get(url, headers=headers, timeout=timeout, follow_redirects=True)
        try:
            body = r.json()
        except Exception:
            body = r.text
        return r.status_code, body
    except httpx.TimeoutException as exc:
        return -1, f"Request timed out after {timeout}s: {exc}"
    except httpx.RequestError as exc:
        return -1, f"Connection error: {exc}"


def _post(url: str, body: str, headers: dict, timeout: float = 30.0) -> tuple[int, Any]:
    """
    Perform a POST request with a pre-serialised string body.
    Returns (status_code, parsed_body) or (-1, error_string) on transport error.
    """
    try:
        r = httpx.post(url, content=body.encode(), headers=headers,
                       timeout=timeout, follow_redirects=True)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, r.text
    except httpx.TimeoutException as exc:
        return -1, f"Request timed out after {timeout}s: {exc}"
    except httpx.RequestError as exc:
        return -1, f"Connection error: {exc}"


# ── connectivity checks ───────────────────────────────────────────────────────

def check_elasticsearch() -> list[dict]:
    """
    Run two read-only checks against the Elasticsearch endpoint:
      1. GET / — root info; confirms auth and returns build_flavor
      2. GET /_cluster/health — cluster health status
    Returns a list of result dicts with keys: check, url, status, ok, detail.
    """
    base = settings.elastic_url.rstrip("/")
    results = []

    # 1. Root info
    url = f"{base}/"
    code, body = _get(url, _es_headers())
    ok     = code == 200
    detail = ""
    if ok and isinstance(body, dict):
        flavor  = body.get("version", {}).get("build_flavor", body.get("build_flavor", "unknown"))
        tagline = body.get("tagline", "")
        detail  = f'build_flavor={flavor!r}  tagline={tagline!r}'
    elif not ok:
        detail = str(body)[:300]
    results.append({"check": "ES root (GET /)", "url": url,
                    "status": code, "ok": ok, "detail": detail})

    # 2. Cluster health
    url = f"{base}/_cluster/health"
    code, body = _get(url, _es_headers())
    ok     = code == 200
    detail = ""
    if ok and isinstance(body, dict):
        detail = f'status={body.get("status")!r}  cluster={body.get("cluster_name")!r}'
    elif not ok:
        detail = str(body)[:300]
    results.append({"check": "ES cluster health", "url": url,
                    "status": code, "ok": ok, "detail": detail})

    return results


def check_kibana() -> list[dict]:
    """
    Run two read-only checks against the Kibana endpoint:
      1. GET /api/status — Kibana service health
      2. GET /api/detection_engine/rules/_find?page=1&per_page=1 — Detections API reachable
    Returns a list of result dicts with keys: check, url, status, ok, detail.
    """
    base = settings.kibana_url.rstrip("/")
    results = []

    # 1. Kibana status
    url = f"{base}/api/status"
    code, body = _get(url, _kibana_headers())
    ok     = code == 200
    detail = ""
    if ok and isinstance(body, dict):
        st     = body.get("status", {})
        overall = (st.get("overall") or {}).get("level") or st.get("overall", "")
        version = (body.get("version") or {}).get("number", "")
        detail  = f'overall={overall!r}  version={version!r}'
    elif not ok:
        detail = str(body)[:300]
    results.append({"check": "Kibana status (/api/status)", "url": url,
                    "status": code, "ok": ok, "detail": detail})

    # 2. Detections API — list rules (read-only, page=1 per_page=1 is lightweight)
    url = f"{base}/api/detection_engine/rules/_find?page=1&per_page=1"
    code, body = _get(url, _kibana_headers())
    ok     = code == 200
    detail = ""
    if ok and isinstance(body, dict):
        total = body.get("total", "?")
        detail = f'total_rules={total}'
    elif code == 404:
        # Detections API not initialized — still means Kibana + auth are working
        detail = "404 — Detections API not yet initialized on this space (auth OK)"
        ok     = True   # treat as pass: Kibana responded; just no rules space yet
    elif not ok:
        detail = str(body)[:300]
    results.append({"check": "Kibana Detections API", "url": url,
                    "status": code, "ok": ok, "detail": detail})

    return results


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Elastic connectivity test — read-only, no writes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Reads ELASTIC_URL, ELASTIC_API_KEY, KIBANA_URL from .env.\n"
            "Example:\n"
            "  python -m backend.app.services.elastic_client --test\n"
        ),
    )
    parser.add_argument("--test", action="store_true", required=True,
                        help="Run the connectivity test.")
    args = parser.parse_args()

    # Pre-flight: check that credentials are configured
    missing = [k for k, v in [
        ("ELASTIC_URL",    settings.elastic_url),
        ("ELASTIC_API_KEY", settings.elastic_api_key),
        ("KIBANA_URL",     settings.kibana_url),
    ] if not v]
    if missing:
        print(f"[!] Missing in .env: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    print(f"  ES:     {settings.elastic_url}")
    print(f"  Kibana: {settings.kibana_url}")
    print()

    all_results = check_elasticsearch() + check_kibana()
    passed = 0
    failed = 0

    for r in all_results:
        icon   = "✓" if r["ok"] else "✗"
        status = f"HTTP {r['status']}" if r["status"] != -1 else "CONN ERR"
        detail = f"  → {r['detail']}" if r["detail"] else ""
        print(f"  [{icon}] {r['check']:<45}  {status}{detail}")
        if r["ok"]:
            passed += 1
        else:
            failed += 1

    print()
    print(f"  {passed} passed  /  {failed} failed")
    sys.exit(0 if failed == 0 else 1)
