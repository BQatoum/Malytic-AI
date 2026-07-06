# TEMPORARY Playwright bridge — replace with official Triage API once research account is approved.
"""
Playwright-based browser automation bridge for Triage (tria.ge).

Used while awaiting Triage API research account approval.  The free account
has no API token, so we drive the website with a logged-in Chromium session
and hit the /api/v0 JSON endpoints using the same session cookies.

Credentials are read from .env:
    TRIAGE_EMAIL=...
    TRIAGE_PASSWORD=...

CLI:
    python -m backend.app.services.triage_playwright --login-test
    python -m backend.app.services.triage_playwright --submit <file> [--password infected]
"""
from __future__ import annotations

import base64
import json
import re
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright, BrowserContext, Page, TimeoutError as PWTimeout

from ..config import settings

_BASE        = "https://tria.ge"
_LOGIN_URL   = f"{_BASE}/login"
_DASH_URL    = f"{_BASE}/dashboard"
_API         = f"{_BASE}/api/v0"

_POLL_INTERVAL   = 15   # seconds between status polls
_POLL_TIMEOUT    = 600  # seconds max wait for "reported"
_POST_RUN_PAUSE  = 4    # seconds to observe browser in --login-test


# ---------------------------------------------------------------------------
# Shared login helper
# ---------------------------------------------------------------------------

def _login(page: Page) -> bool:
    """
    Drive the two-step Triage login (email → Enter → password → Enter).
    Returns True on success (URL leaves /login), False otherwise.
    """
    email    = settings.triage_email
    password = settings.triage_password

    if not email or not password:
        raise RuntimeError("TRIAGE_EMAIL or TRIAGE_PASSWORD not set in .env")

    print(f"[*] Navigating to {_LOGIN_URL} …", flush=True)
    page.goto(_LOGIN_URL, wait_until="networkidle", timeout=30_000)

    # Step 1 — email
    email_input = page.wait_for_selector(
        "input[name='email'], input[type='email']", timeout=10_000
    )
    email_input.fill(email)
    print("[*] Email filled.", flush=True)
    email_input.press("Enter")

    # Step 2 — password appears after Enter on email
    try:
        pw_input = page.wait_for_selector(
            "input[name='password'], input[type='password']",
            state="visible",
            timeout=8_000,
        )
    except PWTimeout:
        print("[!] Password field never appeared after email Enter.", flush=True)
        return False

    pw_input.fill(password)
    print("[*] Password filled.", flush=True)
    pw_input.press("Enter")

    # Wait for URL to leave /login
    try:
        page.wait_for_url(lambda url: "/login" not in url, timeout=15_000)
    except PWTimeout:
        print(f"[!] Still on login page after submit. URL: {page.url}", flush=True)
        return False

    time.sleep(1)  # let JS settle
    print(f"[*] Logged in — landed on {page.url}", flush=True)
    return True


# ---------------------------------------------------------------------------
# Failure-detection helpers  (used only by --login-test)
# ---------------------------------------------------------------------------

def _detect_captcha(page: Page) -> bool:
    for sel in ("iframe[src*='hcaptcha']", "iframe[src*='recaptcha']",
                ".h-captcha", ".g-recaptcha", "[data-sitekey]", "#captcha"):
        if page.query_selector(sel):
            return True
    return False


def _detect_error_message(page: Page) -> str:
    for sel in ("[class*='error']", "[class*='alert']", "[role='alert']",
                ".flash", ".notification"):
        el = page.query_selector(sel)
        if el:
            txt = (el.inner_text() or "").strip()
            if txt:
                return txt
    return ""


# ---------------------------------------------------------------------------
# Page-structure diagnostic dump  (used only by --login-test)
# ---------------------------------------------------------------------------

_DUMP_JS = """() => {
    const fmt = el => ({
        tag:         el.tagName.toLowerCase(),
        type:        el.getAttribute('type')        || '',
        name:        el.getAttribute('name')        || '',
        id:          el.getAttribute('id')          || '',
        placeholder: el.getAttribute('placeholder') || '',
        class:       el.getAttribute('class')       || '',
        text:        (el.innerText || el.value || '').trim().slice(0, 120),
        visible:     el.offsetParent !== null
                     && getComputedStyle(el).display !== 'none'
                     && getComputedStyle(el).visibility !== 'hidden',
    });
    const inputs  = Array.from(document.querySelectorAll('input')).map(fmt);
    const buttons = Array.from(document.querySelectorAll('button')).map(fmt);
    const links   = Array.from(document.querySelectorAll('a')).filter(a =>
        /login|sign.?in|next|submit|continue/i.test(a.innerText || a.href)
    ).map(fmt);
    return { inputs, buttons, links };
}"""


def _dump_page_structure(page: Page, label: str) -> None:
    print(f"\n{'='*60}", flush=True)
    print(f"PAGE STRUCTURE — {label}", flush=True)
    print(f"URL: {page.url}", flush=True)
    print(f"{'='*60}", flush=True)
    try:
        d = page.evaluate(_DUMP_JS)
        print("\n--- INPUTS ---", flush=True)
        for el in d["inputs"]:
            print(f"  <input type={el['type']!r:12} name={el['name']!r:20} "
                  f"id={el['id']!r:20} placeholder={el['placeholder']!r:30} "
                  f"visible={el['visible']}>", flush=True)
        print("\n--- BUTTONS ---", flush=True)
        for el in d["buttons"]:
            print(f"  <button type={el['type']!r:10} id={el['id']!r:20} "
                  f"class={el['class']!r:40} text={el['text']!r:40} "
                  f"visible={el['visible']}>", flush=True)
        print("\n--- LOGIN-LIKE LINKS ---", flush=True)
        for el in d["links"]:
            print(f"  <a id={el['id']!r:20} class={el['class']!r:40} "
                  f"text={el['text']!r:40} visible={el['visible']}>", flush=True)
    except Exception as exc:
        print(f"  [!] JS evaluate failed: {exc}", flush=True)
    print(f"{'='*60}\n", flush=True)


# ---------------------------------------------------------------------------
# Login diagnostic  (--login-test)
# ---------------------------------------------------------------------------

def _run_login_test(headless: bool = False) -> None:
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=headless)
        ctx  = browser.new_context(viewport={"width": 1280, "height": 900})
        page = ctx.new_page()

        # Pre-fill diagnostic
        page.goto(_LOGIN_URL, wait_until="networkidle", timeout=30_000)
        email_input = page.query_selector("input[name='email'], input[type='email']")
        if email_input:
            email_input.fill(settings.triage_email or "test@example.com")
        page.screenshot(path="/tmp/triage_login_page.png")
        print("[*] Pre-click screenshot: /tmp/triage_login_page.png", flush=True)
        _dump_page_structure(page, "after email fill, before any click")

        try:
            ok = _login(page)
        except Exception as exc:
            print(f"[!] _login raised: {exc}", flush=True)
            ok = False

        page.screenshot(path="/tmp/triage_login.png")
        print(f"[*] Final screenshot: /tmp/triage_login.png", flush=True)
        final_url = page.url

        if _detect_captcha(page):
            print(f"LOGIN BLOCKED: captcha  (url={final_url})", flush=True)
        elif "/login" in final_url:
            err = _detect_error_message(page)
            reason = f"wrong-creds — {err}" if err else "unknown — still on login page"
            print(f"LOGIN BLOCKED: {reason}  (url={final_url})", flush=True)
        elif ok:
            print(f"LOGIN SUCCESS  (url={final_url})", flush=True)
        else:
            print(f"LOGIN BLOCKED: unknown  (url={final_url})", flush=True)

        time.sleep(_POST_RUN_PAUSE)
        browser.close()


# ---------------------------------------------------------------------------
# Submit-page diagnostic dump
# ---------------------------------------------------------------------------

_SUBMIT_DUMP_JS = """() => {
    const vis = el => el.offsetParent !== null
                   && getComputedStyle(el).display !== 'none'
                   && getComputedStyle(el).visibility !== 'hidden';
    const attr = (el, a) => el.getAttribute(a) || '';

    const buttons = Array.from(document.querySelectorAll('button, input[type="submit"], input[type="button"], a[role="button"]')).map(el => ({
        tag:     el.tagName.toLowerCase(),
        type:    attr(el, 'type'),
        id:      attr(el, 'id'),
        class:   attr(el, 'class').slice(0, 80),
        text:    (el.innerText || el.value || attr(el, 'aria-label') || '').trim().slice(0, 100),
        visible: vis(el),
    }));

    const selects = Array.from(document.querySelectorAll('select')).map(el => ({
        id:      attr(el, 'id'),
        name:    attr(el, 'name'),
        class:   attr(el, 'class').slice(0, 60),
        visible: vis(el),
        options: Array.from(el.options).map(o => ({ value: o.value, text: o.text.trim() })),
    }));

    // Anything that looks like a profile/environment card or radio option
    const radios = Array.from(document.querySelectorAll('input[type="radio"], input[type="checkbox"]')).map(el => ({
        type:    attr(el, 'type'),
        id:      attr(el, 'id'),
        name:    attr(el, 'name'),
        value:   attr(el, 'value'),
        checked: el.checked,
        visible: vis(el),
        label:   (document.querySelector('label[for="' + attr(el,'id') + '"]') || {innerText:''}).innerText.trim().slice(0, 100),
    }));

    // Clickable divs/labels that might be environment cards
    const cards = Array.from(document.querySelectorAll('[class*="profile"], [class*="environment"], [class*="platform"], [class*="card"], [class*="option"], [class*="target"]')).map(el => ({
        tag:     el.tagName.toLowerCase(),
        id:      attr(el, 'id'),
        class:   attr(el, 'class').slice(0, 80),
        text:    (el.innerText || '').trim().slice(0, 120),
        visible: vis(el),
    }));

    return { buttons, selects, radios, cards };
}"""


def _dump_submit_page(page: Page) -> None:
    print(f"\n{'='*64}", flush=True)
    print(f"SUBMIT PAGE STRUCTURE DUMP", flush=True)
    print(f"URL: {page.url}", flush=True)
    print(f"{'='*64}", flush=True)
    try:
        d = page.evaluate(_SUBMIT_DUMP_JS)

        print("\n--- BUTTONS / SUBMIT CONTROLS ---", flush=True)
        for el in d["buttons"]:
            print(f"  <{el['tag']} type={el['type']!r:10} id={el['id']!r:24} "
                  f"text={el['text']!r:50} visible={el['visible']}>", flush=True)

        print("\n--- SELECT DROPDOWNS ---", flush=True)
        for el in d["selects"]:
            print(f"  <select id={el['id']!r:20} name={el['name']!r:20} visible={el['visible']}>",
                  flush=True)
            for o in el["options"]:
                print(f"      option value={o['value']!r:30} text={o['text']!r}", flush=True)

        print("\n--- RADIO / CHECKBOX INPUTS ---", flush=True)
        for el in d["radios"]:
            print(f"  <input type={el['type']!r:10} id={el['id']!r:24} "
                  f"name={el['name']!r:20} value={el['value']!r:20} "
                  f"checked={el['checked']} visible={el['visible']} label={el['label']!r}>",
                  flush=True)

        print("\n--- PROFILE / ENVIRONMENT CARDS ---", flush=True)
        for el in d["cards"]:
            print(f"  <{el['tag']} id={el['id']!r:20} class={el['class']!r:60} "
                  f"text={el['text']!r:60} visible={el['visible']}>", flush=True)

    except Exception as exc:
        print(f"  [!] JS evaluate failed: {exc}", flush=True)
    print(f"{'='*64}\n", flush=True)


# ---------------------------------------------------------------------------
# API helpers — use authenticated browser-context requests
# ---------------------------------------------------------------------------

def _api_get(ctx: BrowserContext, path: str) -> dict:
    """GET {_API}/{path} using the browser session cookies. Returns parsed JSON."""
    url = f"{_API}/{path}"
    resp = ctx.request.get(url)
    if not resp.ok:
        raise RuntimeError(f"API GET {url} → HTTP {resp.status}")
    return resp.json()


def _poll_until_reported(ctx: BrowserContext, sample_id: str) -> str:
    """
    Poll /api/v0/samples/{id} until status is 'reported' or 'failed'.
    Returns the terminal status string.
    """
    terminal = {"reported", "failed"}
    deadline = time.monotonic() + _POLL_TIMEOUT
    while time.monotonic() < deadline:
        data   = _api_get(ctx, f"samples/{sample_id}")
        status = data.get("status", "")
        print(f"[*] Sample {sample_id} status: {status}", flush=True)
        if status in terminal:
            return status
        time.sleep(_POLL_INTERVAL)
    raise TimeoutError(f"Triage sample {sample_id} did not reach 'reported' within {_POLL_TIMEOUT}s")


# ---------------------------------------------------------------------------
# Completion detection — real signal is "This analysis is finished" + Open Report
# ---------------------------------------------------------------------------

_FINISHED_JS = """() => {
    const txt = (document.body.innerText || '').toLowerCase();
    if (txt.includes('this analysis is finished')) return 'finished-text';
    const els = Array.from(document.querySelectorAll('button, a, [role="button"]'));
    if (els.some(el => /open report/i.test(el.innerText || ''))) return 'open-report-button';
    return null;
}"""


def _poll_for_finished(page: Page) -> str:
    """
    Stay on the current page (live-VM view) and reload every 20s until
    "This analysis is finished" text OR an "Open Report" element appears.
    Returns the indicator that fired, or raises TimeoutError.
    """
    deadline = time.monotonic() + _POLL_TIMEOUT
    attempt  = 0
    while time.monotonic() < deadline:
        attempt += 1
        try:
            time.sleep(3)   # let JS render after load/reload
            indicator = page.evaluate(_FINISHED_JS)
            if indicator:
                print(f"[+] Completion indicator: {indicator!r}", flush=True)
                return indicator
            elapsed = int(time.monotonic() - (deadline - _POLL_TIMEOUT))
            print(f"[*] Poll #{attempt} — sandbox still running ({elapsed}s elapsed) …",
                  flush=True)
        except Exception as exc:
            print(f"[!] Poll #{attempt} JS error: {exc}", flush=True)
        # Reload to pick up page updates (the live-VM view is mostly static HTML
        # with a countdown; "finished" text is injected when the run ends).
        try:
            page.reload(wait_until="domcontentloaded", timeout=20_000)
        except Exception as exc:
            print(f"[!] Poll #{attempt} reload error: {exc}", flush=True)
        time.sleep(_POLL_INTERVAL - 3)   # account for the 3s sleep above
    raise TimeoutError(
        f"Triage analysis did not finish within {_POLL_TIMEOUT}s on {page.url}"
    )


def _click_open_report(page: Page) -> str:
    """
    Click the "Open Report" button/link and return the URL of the report page.
    """
    btn = page.locator("button:has-text('Open Report'), a:has-text('Open Report')").first
    btn.click()
    try:
        page.wait_for_load_state("domcontentloaded", timeout=15_000)
    except PWTimeout:
        pass
    time.sleep(2)
    return page.url


# ---------------------------------------------------------------------------
# Real report page diagnostic dump
# ---------------------------------------------------------------------------

_REAL_REPORT_JS = """() => {
    const attr = (el, a) => el.getAttribute(a) || '';
    const vis  = el => el.offsetParent !== null
                    && getComputedStyle(el).display !== 'none'
                    && getComputedStyle(el).visibility !== 'hidden';

    // All headings
    const headings = Array.from(document.querySelectorAll('h1,h2,h3,h4')).map(el => ({
        tag:  el.tagName.toLowerCase(),
        text: (el.innerText || '').trim().slice(0, 120),
    }));

    // All links with href — tabs, anchors, sub-report links
    const links = Array.from(document.querySelectorAll('a[href]')).map(el => ({
        href: attr(el, 'href'),
        text: (el.innerText || '').trim().slice(0, 80),
        vis:  vis(el),
    })).filter(el => el.text || el.href);

    // Section containers whose class/id hint at report content
    const _kw = /process|network|registry|files?|signature|ioc|config|ttp|mitre|behavioral|overview|static|family|malware|threat/i;
    const sections = Array.from(document.querySelectorAll('[class],[id]')).filter(el => {
        const key = (attr(el,'class') + ' ' + attr(el,'id'));
        return _kw.test(key) && (el.innerText || '').trim().length > 0;
    }).map(el => ({
        tag:  el.tagName.toLowerCase(),
        id:   attr(el, 'id').slice(0, 40),
        cls:  attr(el, 'class').slice(0, 80),
        text: (el.innerText || '').trim().slice(0, 150),
        vis:  vis(el),
    }));

    // Score / verdict text
    const verdict = Array.from(document.querySelectorAll(
        '[class*="score"],[class*="verdict"],[class*="threat"],[class*="malicious"],[class*="severity"]'
    )).map(el => ({
        cls:  attr(el, 'class').slice(0, 60),
        text: (el.innerText || '').trim().slice(0, 80),
    }));

    return { headings, links, sections, verdict };
}"""


def _dump_real_report_page(page: Page, sample_id: str) -> None:
    page.screenshot(path="/tmp/triage_report_real.png")
    print(f"[*] Screenshot: /tmp/triage_report_real.png", flush=True)
    print(f"\n{'='*66}", flush=True)
    print(f"REAL REPORT PAGE — sample {sample_id}", flush=True)
    print(f"Title: {page.title()}", flush=True)
    print(f"URL:   {page.url}", flush=True)
    print(f"{'='*66}", flush=True)
    try:
        d = page.evaluate(_REAL_REPORT_JS)

        print("\n--- HEADINGS (h1–h4) ---", flush=True)
        for el in d["headings"]:
            print(f"  <{el['tag']}> {el['text']!r}", flush=True)

        print("\n--- LINKS / TABS / ANCHORS ---", flush=True)
        for el in d["links"]:
            print(f"  href={el['href']!r:55} text={el['text']!r:50} vis={el['vis']}",
                  flush=True)

        print("\n--- REPORT SECTION CONTAINERS ---", flush=True)
        seen: set[str] = set()
        for el in d["sections"]:
            key = el["cls"][:40] + el["id"]
            if key in seen:
                continue
            seen.add(key)
            print(f"  <{el['tag']} id={el['id']!r:30} cls={el['cls']!r:60}>",
                  flush=True)
            if el["text"]:
                print(f"      text preview: {el['text'][:120]!r}", flush=True)

        print("\n--- SCORE / VERDICT ---", flush=True)
        for el in d["verdict"]:
            print(f"  cls={el['cls']!r:55} text={el['text']!r}", flush=True)

    except Exception as exc:
        print(f"  [!] JS evaluate failed: {exc}", flush=True)
    print(f"{'='*66}\n", flush=True)


# ---------------------------------------------------------------------------
# Main public function
# ---------------------------------------------------------------------------

def _select_windows_vm(page: Page, sample_id: str) -> str:
    """
    After clicking Analyze, Triage now shows a VM/task list on the left panel.
    This function finds and clicks the Windows sandbox VM so we enter the live-VM
    view that eventually emits the "This analysis is finished" completion signal.

    Priority: Windows 11 (score 40) > Windows 10 (30) > any Windows (20) > behavioral (10).

    Strategy:
      1. Scan all <a href> links first — href often encodes the task name, most reliable.
      2. Fall back to button/tab/listitem elements matched by visible text.
      3. Click via page.goto() for links (avoids SPA interception issues), or text-click
         for non-link elements.
      4. Parse the post-click URL to extract and return the task name.
      5. If no VM panel is found at all, return "" and let the caller continue
         (single-task submissions and older Triage UI still work without selection).

    Returns the task name string (e.g. "windows11-ltsc_2024-x64" or "behavioral1"),
    or "" if no VM panel was found.
    """
    print("[*] Checking for VM selection panel …", flush=True)
    time.sleep(3)  # let the SPA render the task list after Analyze click

    _VM_FIND_JS = f"""() => {{
        const scores = [
            ['windows11', 40], ['win11', 40],
            ['windows10', 30], ['win10',  30],
            ['windows',   20],
            ['behavioral', 10],
        ];
        function scoreText(t) {{
            t = (t || '').toLowerCase();
            for (const [kw, s] of scores) if (t.includes(kw)) return s;
            return 0;
        }}
        let top = null, topScore = -1;

        // Priority 1: <a href> whose href or label matches a VM keyword
        for (const a of document.querySelectorAll('a[href]')) {{
            const href = a.getAttribute('href') || '';
            const label = (a.innerText || a.getAttribute('title') || '').trim();
            const s = Math.max(scoreText(href), scoreText(label));
            if (s > topScore) {{
                topScore = s;
                top = {{ href: href, text: label.slice(0, 120) }};
            }}
        }}

        // Priority 2: non-link clickables (tabs, buttons, list items) if no good link
        if (topScore < 10) {{
            const sel = 'button, [role="tab"], [role="option"], [role="listitem"], li';
            for (const el of document.querySelectorAll(sel)) {{
                const label = (el.innerText || el.getAttribute('aria-label') || '').trim();
                const s = scoreText(label);
                if (s > topScore) {{
                    topScore = s;
                    top = {{ href: null, text: label.slice(0, 120) }};
                }}
            }}
        }}

        return (top && topScore > 0) ? {{ score: topScore, ...top }} : null;
    }}"""

    try:
        vm_info = page.evaluate(_VM_FIND_JS)
    except Exception as exc:
        print(f"[!] VM panel JS evaluation failed: {exc}", flush=True)
        vm_info = None

    if not vm_info:
        print("[*] No VM selection panel detected — single-task or older UI; continuing.",
              flush=True)
        return ""

    vm_text  = (vm_info.get("text") or "").strip()
    vm_href  = (vm_info.get("href") or "").strip()
    vm_score = vm_info.get("score", 0)
    print(f"[*] VM candidate → text={vm_text!r}  href={vm_href!r}  score={vm_score}",
          flush=True)

    clicked = False

    # Prefer navigating via href — avoids SPA click-interception issues
    if vm_href:
        target = vm_href if vm_href.startswith("http") else f"{_BASE}{vm_href}"
        print(f"[*] Navigating to VM task page: {target}", flush=True)
        try:
            page.goto(target, wait_until="domcontentloaded", timeout=20_000)
            time.sleep(2)
            clicked = True
            print(f"[+] VM page loaded: {page.url}", flush=True)
        except Exception as exc:
            print(f"[!] VM navigation failed ({exc}), trying text click …", flush=True)

    # Fall back: click by visible text
    if not clicked and vm_text:
        print(f"[*] Clicking VM by text: {vm_text!r}", flush=True)
        for exact in (True, False):
            try:
                page.get_by_text(vm_text, exact=exact).first.click()
                time.sleep(2)
                clicked = True
                print(f"[+] VM clicked (exact={exact}), now at: {page.url}", flush=True)
                break
            except Exception as exc:
                print(f"[!] Text click (exact={exact}) failed: {exc}", flush=True)

    if not clicked:
        print("[!] Could not click VM entry — proceeding anyway (may time out).",
              flush=True)

    # Extract the task name from the URL so downstream probes use the right path
    # e.g. https://tria.ge/240601-abc123ef/windows11-ltsc_2024-x64  → "windows11-ltsc_2024-x64"
    task_name = ""
    m = re.search(rf"{re.escape(sample_id)}/([^/?#]+)", page.url)
    if m:
        task_name = m.group(1)
    print(f"[+] Task name resolved: {task_name!r}", flush=True)
    return task_name


def submit_and_fetch(file_path: str, password: str = "infected", headless: bool = True) -> dict:
    """
    In one logged-in Chromium session:
      1. Log in to tria.ge.
      2. Upload *file_path* via the dashboard upload form.
      3. Capture the sample ID from the resulting URL.
      4. Poll until analysis is 'reported'.
      5. Fetch overview.json + per-task report_triage.json via the authenticated session.
      6. Save combined result to /tmp/triage_report_{id}.json and return it.

    Parameters
    ----------
    file_path : str
        Local path to the sample file.  Must exist.
    password : str
        Archive password to pass to Triage (default 'infected').
    headless : bool
        Run Chromium headless (default True for pipeline use).

    Returns
    -------
    dict
        Combined report: {"sample_id": ..., "overview": {...}, "task_reports": [...]}
    """
    fp = Path(file_path)
    if not fp.exists():
        raise FileNotFoundError(f"Sample not found: {file_path}")

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=headless)
        ctx  = browser.new_context(viewport={"width": 1280, "height": 900})
        page = ctx.new_page()

        # ── 1. Login ──────────────────────────────────────────────────────
        if not _login(page):
            raise RuntimeError("Triage login failed — check credentials in .env")

        # ── 2. Upload via dashboard form ──────────────────────────────────
        print(f"[*] Navigating to dashboard for upload …", flush=True)
        page.goto(_DASH_URL, wait_until="networkidle", timeout=20_000)

        print(f"[*] Setting file: {fp}", flush=True)
        page.set_input_files("#input-file", str(fp))

        # Register a native-dialog handler in case Triage uses window.prompt()
        # for the password (unlikely but safe to cover).
        page.on("dialog", lambda d: d.accept(password))

        print("[*] Clicking submit …", flush=True)
        page.click("#submit-button")

        # ZIP files trigger a password modal — wait for it and fill it.
        # The modal may appear as a DOM overlay with a visible password input,
        # OR as a second form field that was hidden before submit.
        # We check for either within a short window; skip gracefully if absent.
        try:
            zip_pw_input = page.wait_for_selector(
                # Common patterns: a visible password/text input that is NOT the
                # main email/password inputs from the login form.
                "input[type='password']:visible, "
                "input[placeholder*='assword']:visible, "
                "input[placeholder*='infected']:visible, "
                "#sample-password:visible",
                timeout=5_000,
            )
            if zip_pw_input:
                zip_pw_input.fill(password)
                print(f"[*] Filled ZIP password modal with {password!r}.", flush=True)
                # Confirm — try a visible submit/OK button inside the modal first,
                # fall back to Enter on the input.
                ok_btn = page.query_selector(
                    "button[type='submit']:visible, "
                    "button:has-text('OK'):visible, "
                    "button:has-text('Submit'):visible, "
                    "button:has-text('Confirm'):visible"
                )
                if ok_btn:
                    ok_btn.click()
                else:
                    zip_pw_input.press("Enter")
        except PWTimeout:
            print("[*] No ZIP password modal appeared — continuing.", flush=True)

        # ── 3. Wait for /submit/{id} (environment-selection page) ───────────
        try:
            page.wait_for_url(
                lambda url: url != _DASH_URL and "/dashboard" not in url,
                timeout=30_000,
            )
        except PWTimeout:
            raise RuntimeError(f"Browser did not leave dashboard after submit. URL: {page.url}")

        time.sleep(2)
        submit_url = page.url
        print(f"[*] Environment-selection URL: {submit_url}", flush=True)

        # Extract sample ID from /submit/{id}
        m = re.search(r"/(?:submit|samples/)?(\d{6}-[a-z0-9]+)", submit_url)
        if not m:
            raise RuntimeError(f"Could not extract sample ID from URL: {submit_url}")
        sample_id = m.group(1)
        print(f"[+] Sample ID: {sample_id}", flush=True)

        # ── 4. Launch analysis — defaults are already correct ─────────────
        # The /submit page pre-selects the inner .exe and automatic-platform.
        # We only need to click #finish-submit ("Analyze").
        print("[*] Clicking #finish-submit (Analyze) …", flush=True)
        try:
            analyze_btn = page.wait_for_selector("#finish-submit", timeout=10_000)
            analyze_btn.click()
            print("[+] Analyze clicked — behavioral analysis launched.", flush=True)
        except PWTimeout:
            raise RuntimeError("Could not find #finish-submit button on /submit page")

        # Wait for URL to change away from /submit/ to the analysis/report page
        try:
            page.wait_for_url(
                lambda url: "/submit/" not in url,
                timeout=15_000,
            )
        except PWTimeout:
            pass  # Some flows stay on same URL while analysis starts; continue anyway

        time.sleep(2)
        analysis_url = page.url
        print(f"[*] Post-analyze URL: {analysis_url}", flush=True)

        # ── 5. Select Windows sandbox VM from the task list ──────────────────
        # Triage's new UI shows a VM/task list on the left after clicking Analyze.
        # We must click the Windows entry to enter the live-VM view whose page
        # eventually shows "This analysis is finished" and the "Open Report" button.
        task_name = _select_windows_vm(page, sample_id)
        if task_name:
            print(f"[+] SUBMITTED → VM selected ({task_name!r}) → polling …", flush=True)
        else:
            print(f"[+] SUBMITTED → no VM panel (single-task flow) → polling …", flush=True)

        # ── 6. Poll for "This analysis is finished" on the live-VM view ──────
        print(f"[*] Polling for analysis completion (up to {_POLL_TIMEOUT}s) …", flush=True)
        _poll_for_finished(page)
        print("[+] VM-SELECTED → REPORT-READY", flush=True)

        # ── 7. Click "Open Report" → navigate to real findings page ──────────
        print("[*] Clicking 'Open Report' …", flush=True)
        report_url = _click_open_report(page)
        print(f"[+] Report URL: {report_url}", flush=True)

        # ── 8. Extract structured evidence from the report page ───────────────
        time.sleep(2)
        evidence = extract_triage_report(page, sample_id)

        # ── 9. Download PCAP — defensive: failure must not interrupt evidence ─
        try:
            pcap_path = _download_pcap(page, sample_id)
        except Exception as _exc:
            pcap_path = None
            print(f"[!] PCAP download raised unexpectedly: {_exc}", flush=True)
        if pcap_path:
            evidence["pcap_path"] = pcap_path

        out_path = f"/tmp/triage_{sample_id}_evidence.json"
        Path(out_path).write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        print(f"[+] Evidence saved → {out_path}", flush=True)
        print(f"[+] family={evidence['family']!r}  score={evidence['score']!r}"
              f"  C2={evidence['malware_config'].get('c2')}", flush=True)
        ft = evidence.get("report_fulltext", "")
        print(f"  fulltext:  {len(ft):,} chars", flush=True)
        print(f"  registry:  {len(evidence.get('registry', []))} entries", flush=True)
        print(f"  pcap:      {pcap_path or '(not downloaded)'}", flush=True)

        browser.close()
        return evidence


# ---------------------------------------------------------------------------
# Completion detection on the behavioral1 report page
# ---------------------------------------------------------------------------

_BEHAVIORAL_DONE_JS = """() => {
    const txt = (document.body.innerText || '');
    const low = txt.toLowerCase();
    // Report content is present when we see these section names with enough body text
    if (txt.length > 800 && (
        low.includes('malware config') ||
        low.includes('signatures') ||
        low.includes('general')
    )) return 'report-content';
    // Score badge with a digit (e.g. "10/10")
    const scoreEl = document.querySelector('[class*="score"]');
    if (scoreEl && /\\d/.test(scoreEl.innerText || '')) return 'score-badge';
    return null;
}"""


def _poll_behavioral_until_ready(page: Page, behavioral_url: str) -> str:
    """Reload behavioral1 page until report content appears. Returns indicator."""
    deadline = time.monotonic() + _POLL_TIMEOUT
    attempt  = 0
    while time.monotonic() < deadline:
        attempt += 1
        try:
            time.sleep(4)
            indicator = page.evaluate(_BEHAVIORAL_DONE_JS)
            if indicator:
                return indicator
            elapsed = int(time.monotonic() - (deadline - _POLL_TIMEOUT))
            print(f"[*] Poll #{attempt} — report not ready yet ({elapsed}s) …", flush=True)
            page.reload(wait_until="domcontentloaded", timeout=20_000)
        except Exception as exc:
            print(f"[!] Poll #{attempt} error: {exc}", flush=True)
            time.sleep(_POLL_INTERVAL)
    return "timeout"


# ---------------------------------------------------------------------------
# Method (a) — JSON URL probing via session cookies
# ---------------------------------------------------------------------------

def _build_probe_urls(task_name: str = "behavioral1") -> list[tuple[str, str]]:
    """Return probe URL templates using the real VM task name (e.g. 'windows11-ltsc_2024-x64')."""
    t = task_name or "behavioral1"
    return [
        ("overview_json",    "{base}/{id}/overview.json"),
        ("task_dump",        f"{{base}}/{{id}}/{t}/dump.json"),
        ("task_report",      f"{{base}}/{{id}}/{t}/report.json"),
        ("api_overview",     "{base}/api/v0/samples/{id}/overview.json"),
        ("api_task_report",  f"{{base}}/api/v0/samples/{{id}}/{t}/report"),
    ]


def _probe_json_urls(ctx: BrowserContext, sample_id: str,
                     task_name: str = "behavioral1") -> dict:
    """
    Try each candidate JSON URL using the browser session cookies.
    Print the HTTP status of each.  Save any 200 response to /tmp and return
    a mapping of label → parsed JSON (for 200s only).
    """
    print(f"\n{'='*60}", flush=True)
    print(f"METHOD (a) — JSON URL probes  (task={task_name!r})", flush=True)
    print(f"{'='*60}", flush=True)
    results: dict[str, dict] = {}
    for label, template in _build_probe_urls(task_name):
        url = template.format(base=_BASE, id=sample_id)
        try:
            resp = ctx.request.get(url, timeout=10_000)
            status = resp.status
            if status == 200:
                try:
                    data = resp.json()
                    out = f"/tmp/triage_{sample_id}_{label}.json"
                    Path(out).write_text(json.dumps(data, indent=2), encoding="utf-8")
                    top_keys = list(data.keys()) if isinstance(data, dict) else f"[list len={len(data)}]"
                    print(f"  ✓ {label:25} {status}  top-level keys: {top_keys}", flush=True)
                    print(f"      saved → {out}", flush=True)
                    results[label] = data
                except Exception as je:
                    print(f"  ✓ {label:25} {status}  (not JSON: {je})", flush=True)
            else:
                print(f"  ✗ {label:25} {status}", flush=True)
        except Exception as exc:
            print(f"  ! {label:25} ERROR: {exc}", flush=True)
    print(f"{'='*60}\n", flush=True)
    return results


# ---------------------------------------------------------------------------
# Method (b) — HTML scrape of the behavioral1 page
# ---------------------------------------------------------------------------

_SCRAPE_JS = """() => {
    // Full page innerText — most reliable for SPA content
    const fullText = (document.body.innerText || '').slice(0, 25000);

    // Tables: headers + rows
    const tables = Array.from(document.querySelectorAll('table')).map(t => ({
        headers: Array.from(t.querySelectorAll('th')).map(h => h.innerText.trim()),
        rows:    Array.from(t.querySelectorAll('tr')).map(r =>
            Array.from(r.querySelectorAll('td,th')).map(c => c.innerText.trim())
        ).filter(r => r.some(c => c.length > 0)),
    }));

    // Definition lists (dt → dd key-value pairs)
    const defLists = Array.from(document.querySelectorAll('dl')).map(dl => {
        const items = {};
        Array.from(dl.querySelectorAll('dt')).forEach(dt => {
            const dd = dt.nextElementSibling;
            if (dd && dd.tagName === 'DD')
                items[dt.innerText.trim()] = dd.innerText.trim();
        });
        return items;
    }).filter(d => Object.keys(d).length > 0);

    return { fullText, tables, defLists };
}"""


def _parse_sections(full_text: str) -> dict:
    """
    Split the page innerText into named sections by known heading keywords.
    Returns {section_name: content_text}.
    """
    # Section boundary markers as they appear in the Triage report text
    markers = [
        "General", "Malware Config", "Signatures", "Process Tree",
        "Network Traffic", "Registry", "Dropped Files", "Extracted Files",
        "MITRE ATT&CK", "Overview",
    ]
    sections: dict[str, str] = {}
    positions: list[tuple[int, str]] = []
    for m in markers:
        idx = full_text.find(m)
        if idx != -1:
            positions.append((idx, m))
    positions.sort()
    for i, (start, name) in enumerate(positions):
        end = positions[i + 1][0] if i + 1 < len(positions) else len(full_text)
        sections[name] = full_text[start + len(name):end].strip()[:3000]
    return sections


def _scrape_behavioral(page: Page, sample_id: str) -> dict:
    """Extract structured data from the rendered behavioral1 page."""
    print(f"\n{'='*60}", flush=True)
    print("METHOD (b) — HTML scrape", flush=True)
    print(f"{'='*60}", flush=True)
    try:
        raw = page.evaluate(_SCRAPE_JS)
    except Exception as exc:
        print(f"  [!] JS evaluate failed: {exc}", flush=True)
        return {}

    sections = _parse_sections(raw["fullText"])

    print(f"\n  Sections found: {list(sections.keys())}", flush=True)

    for name, content in sections.items():
        print(f"\n  ── {name} ──", flush=True)
        # Print first 800 chars of each section
        print(f"  {content[:800]!r}", flush=True)

    if raw["tables"]:
        print(f"\n  Tables ({len(raw['tables'])} found):", flush=True)
        for i, t in enumerate(raw["tables"][:5]):   # cap at 5
            print(f"  Table #{i+1} headers={t['headers']}", flush=True)
            for row in t["rows"][:6]:               # cap at 6 rows
                print(f"    {row}", flush=True)

    if raw["defLists"]:
        print(f"\n  Definition lists ({len(raw['defLists'])} found):", flush=True)
        for dl in raw["defLists"][:5]:
            for k, v in list(dl.items())[:10]:
                print(f"    {k!r}: {v!r}", flush=True)

    print(f"\n  Full text length: {len(raw['fullText'])} chars", flush=True)
    out = f"/tmp/triage_{sample_id}_scrape.txt"
    Path(out).write_text(raw["fullText"], encoding="utf-8")
    print(f"  Full text saved → {out}", flush=True)
    print(f"{'='*60}\n", flush=True)

    return {"sections": sections, "tables": raw["tables"], "defLists": raw["defLists"]}


# ---------------------------------------------------------------------------
# Structured extraction from behavioral1 page
# ---------------------------------------------------------------------------

_EXTRACT_JS = """() => {
    const txt  = el => el ? el.innerText.trim() : '';
    const get  = id => document.getElementById(id);
    const qs   = s  => document.querySelector(s);
    const qsa  = s  => Array.from(document.querySelectorAll(s));
    const attr = (el, a) => el ? (el.getAttribute(a) || '') : '';

    // Each section is wrapped in try/catch so a single broken section
    // never prevents the others from being extracted.

    let score_raw = '';
    try {
        const scoreEl = get('score-block')
                     || qs('.score-block, [class*="score-block"], [class*="verdict-score"]')
                     || qs('[class*="threat-score"], [class*="score"]');
        score_raw = txt(scoreEl);
    } catch(e) {}

    let config_raw = '';
    try { config_raw = txt(get('malware-config')); } catch(e) {}

    let processes_raw = '';
    let proc_children = [];
    try {
        const procEl = get('processes');
        processes_raw = txt(procEl);
        proc_children = procEl
            ? qsa('#processes [class*="process"], #processes [class*="item"], #processes [class*="entry"]')
                  .map(el => ({ text: el.innerText.trim().slice(0, 500) }))
                  .filter(p => p.text.length > 2)
            : [];
    } catch(e) {}

    let network_raw = '';
    try { network_raw = txt(get('network')); } catch(e) {}

    let signatures_raw = '';
    let sig_children = [];
    try {
        const sigEl = get('signatures');
        signatures_raw = txt(sigEl);
        sig_children = sigEl
            ? qsa('#signatures li, #signatures [class*="item"], #signatures [class*="row"], #signatures [class*="sig"]')
                  .map(el => el.innerText.trim().slice(0, 300))
                  .filter(t => t.length > 2)
            : [];
    } catch(e) {}

    let mitre_raw = '';
    let mitre_children = [];
    let mitre_links = [];
    try {
        const mitreEl = get('mitre') || get('ttp') || qs('[id*="mitre"], [id*="ttp"]');
        mitre_raw = txt(mitreEl);
        mitre_children = mitreEl
            ? qsa('#mitre [class*="item"], #mitre [class*="tech"], #ttp [class*="item"], #ttp [class*="tech"], [id*="mitre"] [class*="item"]')
                  .map(el => el.innerText.trim().slice(0, 200))
                  .filter(t => t.length > 2)
            : [];
        // MITRE anchor links — href carries the canonical T-code (e.g. /techniques/T1082/)
        mitre_links = qsa('a[href*="/techniques/T"]').map(el => ({
            href: attr(el, 'href'),
            text: el.innerText.trim().slice(0, 100),
        }));
    } catch(e) {}

    let tags_raw = '';
    try {
        const tagsEl = get('tags') || qs('[class*="tag-list"], [class*="tags"]');
        tags_raw = txt(tagsEl);
    } catch(e) {}

    // Registry IOCs — scrape from signature detail tables.
    // Rows that contain registry paths (REGISTRY or HKEY_) in any
    // signature's IOC detail section.
    let registry_iocs = [];
    try {
        const sigEl = get('signatures');
        if (sigEl) {
            const regRows = Array.from(
                sigEl.querySelectorAll('tr, li, [class*="row"], [class*="ioc"], [class*="item"]')
            ).filter(el => {
                const t = el.innerText || '';
                return t.indexOf('REGISTRY') >= 0 || t.indexOf('HKEY_') >= 0;
            });
            registry_iocs = regRows.map(el => {
                // Use charCode-based split to avoid Python escape sequences
                const raw   = el.innerText || '';
                const lines = raw.split(String.fromCharCode(10))
                    .map(function(l) { return l.trim(); })
                    .filter(function(l) { return l.length > 2; });
                const action   = lines[0] || '';
                const path     = lines.find(function(l) {
                    return l.indexOf('REGISTRY') >= 0 || l.indexOf('HKEY_') >= 0;
                }) || lines[lines.length - 1] || '';
                const procLine = lines.find(function(l) {
                    return l.toLowerCase().indexOf('.exe') >= 0 && l !== path;
                }) || '';
                return { action: action, path: path, process: procLine };
            }).filter(function(r) { return r.path.length > 3; }).slice(0, 200);
        }
    } catch(e) {}

    return {
        score_raw, config_raw,
        processes_raw, proc_children,
        network_raw,
        signatures_raw, sig_children,
        mitre_raw, mitre_children, mitre_links,
        tags_raw,
        registry_iocs,
    };
}"""

# Regexes used by section parsers
_C2_PAT    = re.compile(r'([\w\-\.]+\.\w{2,}:\d+|(?:\d{1,3}\.){3}\d{1,3}:\d+)')
_URL_PAT   = re.compile(r'https?://\S+')
_TECH_PAT  = re.compile(r'(T\d{4}(?:\.\d{3})?)\b[^\n]{0,80}', re.MULTILINE)
_NAME_TECH = re.compile(r'([\w][\w\s\-/]{4,60}?)\s+(T\d{4}(?:\.\d{3})?)\b', re.MULTILINE)
_EXE_EXT   = re.compile(r'\.(exe|dll|bat|ps1|vbs|tmp|cab|msi|lnk|scr)$', re.IGNORECASE)
# Section header words that are never a family name or attribute key/value
_CONFIG_HEADERS = {"extracted", "family", "c2", "attributes", "overview",
                   "general", "config", "malware config"}


def _is_real_domain(s: str) -> bool:
    """Return False for filenames (e.g. sample.exe) masquerading as domain entries."""
    if "." not in s or _EXE_EXT.search(s):
        return False
    tld = s.rsplit(".", 1)[-1]
    return bool(re.match(r'^[a-zA-Z]{2,6}$', tld))


def _parse_score(raw: str) -> tuple[str, str]:
    m = re.search(r'(\d+)\s*/\s*(\d+)', raw)
    score = f"{m.group(1)}/{m.group(2)}" if m else ""
    low = raw.lower()
    if "malicious" in low:
        verdict = "malicious"
    elif "suspicious" in low:
        verdict = "suspicious"
    elif "benign" in low or "clean" in low:
        verdict = "benign"
    elif m:
        num = int(m.group(1))
        verdict = "malicious" if num >= 7 else "suspicious" if num >= 4 else "clean"
    else:
        verdict = "unknown"
    return score, verdict


def _parse_malware_config(raw: str) -> dict:
    """
    General parser for the Triage Malware Config section.

    Handles any family's label→value layout without hardcoding section names.
    Works by splitting the raw innerText on blank lines into "paragraphs".
    Each paragraph is one or more adjacent lines; the LAST line of a paragraph
    is the active label contribution (preceding lines are structural headers
    like "Extracted", "Credentials", "Attributes" that Triage renders directly
    before their first key with no blank line between them).

    Alternates paragraphs as (label, value, label, value …) pairs.

    Examples handled:
      XWorm   : Extracted/Family → xworm / C2 → host:port / Attributes+Install_directory → %AppData%
      VIPKL   : Extracted/Credentials/Protocol → smtp / Host → mail.x.com / Port → 587 …
      Any RAT : any section name → any key=value layout
    """
    _STRUCTURAL = {"extracted", "general"}  # top-level preamble words to skip
    _C2_KEYS    = {"c2", "host", "server", "domain", "url", "endpoint"}

    # Split into paragraphs (groups of non-empty lines separated by blank lines)
    paragraphs: list[list[str]] = []
    for block in re.split(r'\n[ \t]*\n', raw):
        lines = [l.strip() for l in block.splitlines() if l.strip()]
        if lines:
            paragraphs.append(lines)

    family      = ""
    c2:   list[str]       = []
    attrs: dict[str, str] = {}
    pending_key: str | None = None

    def _register(key: str, value: str) -> None:
        nonlocal family
        k_low = key.lower()
        if k_low == "family":
            if not family and len(value) < 50:
                family = value
            return
        if key and value:
            attrs[key] = value
        # Detect network endpoints: host:port patterns, URLs
        if _C2_PAT.search(value) or _URL_PAT.search(value):
            if value not in c2:
                c2.append(value)

    for para in paragraphs:
        # The structural contribution of this paragraph is its LAST line.
        # All preceding lines (e.g. "Extracted", "Credentials") are section
        # headers rendered without a blank line before the first key.
        active = para[-1]

        if active.lower() in _STRUCTURAL:
            pending_key = None
            continue

        if pending_key is None:
            pending_key = active
        else:
            _register(pending_key, active)
            pending_key = None

    # Post-process: synthesize host:port if Host + Port were separate attrs
    host_val = attrs.get("Host") or attrs.get("Server") or attrs.get("Domain") or ""
    port_val = attrs.get("Port") or ""
    if host_val:
        endpoint = f"{host_val}:{port_val}" if port_val else host_val
        if endpoint not in c2:
            c2.append(endpoint)

    # Fallback: scan all attr values for C2 patterns missed above
    for v in attrs.values():
        if (_C2_PAT.search(v) or _URL_PAT.search(v)) and v not in c2:
            c2.append(v)

    return {"family": family, "c2": c2, "attributes": attrs}


def _parse_registry(iocs: list[dict]) -> list[dict]:
    """
    Deduplicate and normalise registry IOC rows extracted from signature tables.
    Each input dict has {action, path, process} from the JS extractor.
    """
    registry: list[dict] = []
    seen: set[str] = set()
    for row in iocs:
        action  = (row.get("action") or "").strip()
        path    = re.sub(r'\s+', ' ', row.get("path") or "").strip()
        process = (row.get("process") or "").strip()
        if not path:
            continue
        key = f"{action}|{path}"
        if key in seen:
            continue
        seen.add(key)
        registry.append({
            "action":  action or "accessed",
            "path":    path,
            "process": process,
        })
    return registry


def _parse_processes(raw: str, children: list[dict]) -> list[dict]:
    processes: list[dict] = []
    source = children if children else []

    if source:
        for child in source[:50]:
            text  = child.get("text", "")
            lines = [l.strip() for l in text.splitlines() if l.strip()]
            image, cmd, sigs = "", "", []
            for line in lines:
                if ".exe" in line.lower() and not image:
                    parts = line.split(None, 1)
                    image = parts[0]
                    cmd   = line if len(parts) > 1 else ""
                elif image:
                    sigs.append(line)
            if image:
                processes.append({"image": image, "command_line": cmd,
                                   "signatures": sigs[:5]})
        return processes

    # Fallback: parse raw text
    lines   = [l.strip() for l in raw.splitlines() if l.strip()]
    current: dict | None = None
    for line in lines[:300]:
        if ".exe" in line.lower() and len(line) < 300:
            if current:
                processes.append(current)
            parts  = line.split(None, 1)
            image  = parts[0]
            cmd    = line if len(parts) > 1 else ""
            current = {"image": image, "command_line": cmd, "signatures": []}
        elif current and 3 < len(line) < 200:
            current["signatures"].append(line)
    if current:
        processes.append(current)
    return processes[:50]


def _parse_network(raw: str) -> dict:
    dns: list[str] = []
    tcp: list[str] = []
    udp: list[str] = []
    http_list: list[str] = []
    c2: list[str] = []

    lines  = [l.strip() for l in raw.splitlines() if l.strip()]
    bucket = "general"

    for line in lines:
        low = line.lower()
        if low in ("dns", "dns requests", "dns queries"):
            bucket = "dns";  continue
        if low in ("tcp", "tcp connections"):
            bucket = "tcp";  continue
        if low in ("udp", "udp traffic"):
            bucket = "udp";  continue
        if low in ("http", "http requests"):
            bucket = "http"; continue
        if "c2" in low and len(line) < 20:
            bucket = "c2";   continue

        urls = _URL_PAT.findall(line)
        if urls:
            http_list.extend(u for u in urls if u not in http_list)
            continue

        c2_matches = _C2_PAT.findall(line)
        if c2_matches:
            target = (dns  if bucket == "dns"  else
                      c2   if bucket == "c2"   else
                      udp  if bucket == "udp"  else tcp)
            for m in c2_matches:
                val = m.split(":")[0] if bucket == "dns" else m
                # Filter exe/dll filenames from the DNS list
                if bucket == "dns" and not _is_real_domain(val):
                    continue
                if val not in target:
                    target.append(val)
            continue

        # Plain domain in DNS bucket — reject filenames
        if (bucket == "dns" and "." in line and " " not in line
                and len(line) < 100 and _is_real_domain(line)):
            if line not in dns:
                dns.append(line)

    return {"dns": dns, "tcp": tcp, "udp": udp, "http": http_list, "c2": c2}


def _parse_signatures(raw: str, children: list[str]) -> list[dict]:
    if children:
        sigs = []
        for text in children[:100]:
            lines = [l.strip() for l in text.splitlines() if l.strip()]
            if lines:
                sigs.append({
                    "name":        lines[0],
                    "description": " ".join(lines[1:])[:200] if len(lines) > 1 else "",
                    "tags":        [],
                })
        return sigs
    # Fallback: one signature per non-empty line
    return [
        {"name": l, "description": "", "tags": []}
        for l in (l.strip() for l in raw.splitlines())
        if 3 < len(l) < 200 and not l.lower().startswith(("http", "tcp", "udp", "dns"))
    ][:100]


def _parse_mitre(raw: str, children: list[str],
                 links: list[dict] | None = None) -> list[dict]:
    techniques: list[dict] = []
    seen: set[str] = set()

    # Method 1 — anchor hrefs (most reliable: href = canonical T-code)
    # MITRE URLs use /techniques/T1614/001/ for sub-techniques, not /T1614.001/
    for link in (links or []):
        m = re.search(r'/techniques/(T\d{4})(?:/(\d{3}))?', link.get("href", ""))
        if not m:
            continue
        tid = m.group(1) + (f".{m.group(2)}" if m.group(2) else "")
        if tid in seen:
            continue
        seen.add(tid)
        # Strip trailing T-code from link text to get the name
        name = re.sub(r'\s+T\d{4}(?:\.\d{3})?$', '', link.get("text", "")).strip()[:80]
        techniques.append({"tactic": "", "technique_id": tid, "technique_name": name})

    # Method 2 — "Name T1234" pattern in raw text (Triage renders name before T-code)
    for m in _NAME_TECH.finditer(raw):
        tid  = m.group(2)
        name = m.group(1).strip()[:80]
        if tid in seen:
            continue
        seen.add(tid)
        techniques.append({"tactic": "", "technique_id": tid, "technique_name": name})

    # Method 3 — T-code-first pattern in children (fallback)
    for text in (children or []):
        for m in _TECH_PAT.finditer(text):
            tid  = m.group(0)[:9].strip()
            rest = re.sub(r'^[–\-:—\s]+', '', m.group(0)[len(tid):]).strip()[:80]
            if tid in seen:
                continue
            seen.add(tid)
            techniques.append({"tactic": "", "technique_id": tid,
                                "technique_name": rest})

    # Final sweep — any bare T-code in raw not yet captured
    for tid in re.findall(r'T\d{4}(?:\.\d{3})?', raw):
        if tid not in seen:
            seen.add(tid)
            techniques.append({"tactic": "", "technique_id": tid,
                                "technique_name": ""})
    return techniques


def extract_triage_report(page: Page, sample_id: str) -> dict:
    """
    Scrape the behavioral1 page into a structured evidence dict.

    Queries each stable container ID (#malware-config, #processes, #network,
    #signatures, #mitre/#ttp, score block) and parses their innerText.
    Every section is defensive — absent containers produce empty lists/dicts.

    Returns a dict with source='triage', ready for _extract_triage_evidence()
    in dynamic_analyzer.py.
    """
    try:
        raw = page.evaluate(_EXTRACT_JS)
    except Exception as exc:
        print(f"[!] extract_triage_report JS failed: {exc}", flush=True)
        raw = {}

    score, verdict = _parse_score(raw.get("score_raw", ""))
    config         = _parse_malware_config(raw.get("config_raw", ""))
    processes      = _parse_processes(raw.get("processes_raw", ""),
                                      raw.get("proc_children", []))
    network        = _parse_network(raw.get("network_raw", ""))
    signatures     = _parse_signatures(raw.get("signatures_raw", ""),
                                       raw.get("sig_children", []))
    mitre          = _parse_mitre(raw.get("mitre_raw", ""),
                                  raw.get("mitre_children", []),
                                  raw.get("mitre_links", []))
    registry       = _parse_registry(raw.get("registry_iocs", []))

    tags_raw = raw.get("tags_raw", "")
    tags = [t.strip().lower()
            for t in re.split(r'[\n,|·•]', tags_raw) if t.strip()] if tags_raw else []

    # Family preference order:
    # 1. Malware config block (most authoritative)
    # 2. "Family: <name>" from the first matching signature (Triage always puts
    #    this as the first entry for known families, e.g. "Family: WannaCry")
    # 3. First non-verdict tag (last resort — tags often carry arch/platform noise)
    family = config.get("family") or ""
    if not family:
        for sig in signatures:
            sig_name = sig.get("name", "")
            if sig_name.lower().startswith("family:"):
                family = sig_name.split(":", 1)[1].strip().lower()
                break
    if not family:
        family = next(
            (t for t in tags if t not in ("malicious", "suspicious", "clean", "")), ""
        )

    # Full rendered report text — Claude reads this directly as primary evidence
    report_fulltext = _capture_report_fulltext(page)

    # Replay Monitor screenshots — canvas frames captured while the detonation
    # video plays. Gated by settings.capture_screenshots so it can be disabled.
    screenshots: list[str] = []
    if settings.capture_screenshots:
        try:
            screenshots = _capture_replay_frames(
                page, sample_id, settings.screenshot_capture_secs
            )
        except Exception as _exc:
            print(f"[!] Screenshot capture failed: {_exc}", flush=True)

    return {
        "source":          "triage",
        "sample_id":       sample_id,
        "score":           score,
        "verdict":         verdict,
        "family":          family,
        "tags":            tags,
        "malware_config":  config,
        "processes":       processes,
        "network":         network,
        "signatures":      signatures,
        "mitre":           mitre,
        "registry":        registry,
        "report_fulltext": report_fulltext,
        "screenshots":     screenshots,
    }


# ---------------------------------------------------------------------------
# Full report text capture
# ---------------------------------------------------------------------------

# JS: expand all collapsed accordion sections so their text appears in innerText.
# Uses attribute manipulation instead of .click() to avoid event-handler side-effects.
_EXPAND_SECTIONS_JS = """() => {
    let n = 0;
    // aria-expanded="false" toggle buttons / headers
    document.querySelectorAll('[aria-expanded="false"]').forEach(function(el) {
        try { el.click(); n++; } catch(e) {}
    });
    // <details> elements that are closed
    document.querySelectorAll('details:not([open])').forEach(function(el) {
        el.setAttribute('open', ''); n++;
    });
    return n;
}"""

# JS: capture the full body innerText PLUS supplement with IOC row text.
#
# Problem: some signature IOC detail tables (e.g. registry key rows) have
# non-empty el.innerText on the individual <tr> but are NOT included in their
# parent section's innerText (browser rendering quirk with collapsed panels).
# Solution: always collect text from all <tr> and [class*="ioc"] children inside
# the signatures section, deduplicated against what's already in bodyText.
#
# Returns {bodyText, hiddenIocText}.
_FULLTEXT_CAPTURE_JS = """() => {
    const bodyText = document.body ? (document.body.innerText || '') : '';

    // Collect ALL row-level text from the signatures section.
    // Each row may be in a collapsed accordion that doesn't appear in bodyText.
    const sigEl = document.getElementById('signatures');
    const iocParts = [];
    if (sigEl) {
        const rows = Array.from(sigEl.querySelectorAll('tr, [class*="ioc"], [class*="detail"]'));
        rows.forEach(function(el) {
            // Use textContent so we get text even if element is display:none.
            // Fall back to innerText for normal visible rows.
            const tc = (el.textContent || el.innerText || '').replace(/[ \\t]+/g, ' ').trim();
            if (tc.length > 5) {
                // Only include if not already present in bodyText (avoid duplication)
                if (bodyText.indexOf(tc.slice(0, 40)) === -1) {
                    iocParts.push(tc);
                }
            }
        });
    }

    return {
        bodyText:      bodyText,
        hiddenIocText: iocParts.join(String.fromCharCode(10)),
    };
}"""

# Known report section headings used to strip nav preamble.
_REPORT_HEADINGS = {
    "general", "overview", "malware config", "malware configuration",
    "signatures", "processes", "network", "mitre", "downloads",
    "static", "behavioral", "config",
}


def _capture_report_fulltext(page: Page) -> str:
    """
    Return the complete behavioral report text from the current page.

    Steps:
      1. Expand collapsed accordion sections (aria-expanded, <details>).
      2. Capture document.body.innerText (visible text) plus supplement with
         textContent from hidden IOC rows (collapsed table cells).
      3. Clean: strip navigation preamble (everything before the first known
         report heading or score line), collapse excessive blank lines, trim.
    """
    # Phase 1: expand collapsed sections, then let DOM settle
    try:
        n_expanded = page.evaluate(_EXPAND_SECTIONS_JS)
        if n_expanded and n_expanded > 0:
            page.wait_for_timeout(700)
    except Exception:
        pass

    # Phase 2: capture text
    try:
        result = page.evaluate(_FULLTEXT_CAPTURE_JS)
        body_text   = result.get("bodyText", "")   if isinstance(result, dict) else ""
        hidden_ioc  = result.get("hiddenIocText", "") if isinstance(result, dict) else ""
    except Exception:
        body_text  = ""
        hidden_ioc = ""

    if not body_text:
        return ""

    # Phase 3: clean the body text
    lines = body_text.splitlines()

    # Strip nav preamble: find the first line that is a known report heading
    # or looks like a score badge (e.g. "10/10")
    start_idx = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        low = stripped.lower()
        if low in _REPORT_HEADINGS or re.match(r'^\d+/\d+', stripped):
            start_idx = i
            break

    lines = lines[start_idx:]

    # Strip footer: drop trailing lines that look like nav/footer boilerplate
    _FOOTER_SIGNALS = {"terms", "privacy", "contact", "feedback", "© hatching", "© triage"}
    end_idx = len(lines)
    for i in range(len(lines) - 1, max(len(lines) - 30, -1), -1):
        low = lines[i].strip().lower()
        if low in _FOOTER_SIGNALS or (low.startswith("©") and len(low) < 40):
            end_idx = i
    lines = lines[:end_idx]

    clean = re.sub(r'\n{3,}', '\n\n', '\n'.join(lines)).strip()

    # Collapse the memory dump download list.
    # These are analyst artifacts, not behavioral evidence: dozens of
    # "memory/PID-N-0xADDR-memory.dmp\nDownload" lines waste context.
    # Replace the entire block with a one-line count note.
    _DUMP_PAT = re.compile(
        r'(?:memory/[\w\-\.]+\.dmp\s*\n?\s*(?:Download\s*\n?)?)+',
        re.IGNORECASE,
    )
    dump_files = re.findall(r'memory/[\w\-\.]+\.dmp', clean, re.IGNORECASE)
    if dump_files:
        clean = _DUMP_PAT.sub(
            f"[{len(dump_files)} memory dump file(s) available — paths omitted for brevity]\n",
            clean,
        )

    # Append hidden IOC content not visible in innerText.
    # Clean up table-cell whitespace noise before appending.
    if hidden_ioc:
        ioc_lines = [l for l in hidden_ioc.splitlines() if l.strip() and l.strip() != " "]
        hidden_ioc = "\n".join(ioc_lines)
        if hidden_ioc:
            clean += "\n\n--- Signature IOC detail rows (collapsed table content) ---\n" + hidden_ioc

    return clean


# ---------------------------------------------------------------------------
# PCAP download diagnostic
# ---------------------------------------------------------------------------

_PCAP_DIAG_JS = """() => {
    const attr = (el, a) => el ? (el.getAttribute(a) || '') : '';

    // 1. Elements whose visible text mentions PCAP (button, a, span, div …)
    const pcapEls = Array.from(document.querySelectorAll('*')).filter(el => {
        const t = (el.innerText || el.textContent || '').trim();
        return /pcap/i.test(t) && t.length < 40;  // short label → likely a button/link
    }).map(el => ({
        tag:     el.tagName.toLowerCase(),
        id:      attr(el, 'id'),
        cls:     attr(el, 'class').slice(0, 80),
        text:    (el.innerText || el.textContent || '').trim().slice(0, 60),
        href:    attr(el, 'href'),
        onclick: attr(el, 'onclick').slice(0, 120),
        data:    Object.fromEntries(
                     Array.from(el.attributes)
                         .filter(a => a.name.startsWith('data-'))
                         .map(a => [a.name, a.value.slice(0, 80)])
                 ),
    }));

    // 2. All <a> links whose href smells like a PCAP download
    const pcapLinks = Array.from(document.querySelectorAll('a[href]')).filter(el =>
        /pcap|dump|\.pcapng|\/network/i.test(attr(el, 'href'))
    ).map(el => ({
        tag:  el.tagName.toLowerCase(),
        href: attr(el, 'href'),
        text: (el.innerText || '').trim().slice(0, 60),
    }));

    // 3. All links whose href contains the sample path (reveals URL structure)
    const sampleLinks = Array.from(document.querySelectorAll('a[href]')).filter(el =>
        /\/(static|download|report|file|artifact)/i.test(attr(el, 'href'))
    ).map(el => ({
        href: attr(el, 'href'),
        text: (el.innerText || '').trim().slice(0, 60),
    }));

    return { pcapEls, pcapLinks, sampleLinks };
}"""


def _dump_pcap_links(page: Page) -> None:
    print(f"\n{'='*66}", flush=True)
    print("PCAP DOWNLOAD DIAGNOSTIC", flush=True)
    print(f"{'='*66}", flush=True)
    try:
        d = page.evaluate(_PCAP_DIAG_JS)
    except Exception as exc:
        print(f"  [!] JS evaluate failed: {exc}", flush=True)
        return

    print(f"\n── 1. Elements with 'PCAP' text ({len(d['pcapEls'])} found) ──", flush=True)
    for el in d["pcapEls"]:
        print(f"  <{el['tag']} id={el['id']!r} cls={el['cls'][:50]!r}>", flush=True)
        print(f"    text    = {el['text']!r}", flush=True)
        if el["href"]:
            print(f"    href    = {el['href']!r}", flush=True)
        if el["onclick"]:
            print(f"    onclick = {el['onclick']!r}", flush=True)
        if el["data"]:
            print(f"    data-*  = {el['data']}", flush=True)

    print(f"\n── 2. Links with pcap/dump/.pcapng/network in href ({len(d['pcapLinks'])} found) ──",
          flush=True)
    for el in d["pcapLinks"]:
        print(f"  href={el['href']!r}  text={el['text']!r}", flush=True)

    print(f"\n── 3. Links with /static|/download|/report|/file|/artifact in href "
          f"({len(d['sampleLinks'])} found) ──", flush=True)
    for el in d["sampleLinks"][:30]:
        print(f"  href={el['href']!r}  text={el['text']!r}", flush=True)

    print(f"{'='*66}\n", flush=True)


# ---------------------------------------------------------------------------
# PCAP download — click the button and capture via Playwright download events
# ---------------------------------------------------------------------------

def _download_pcap(page: Page, sample_id: str) -> str | None:
    """
    Click the #download_pcapng button and capture whatever file the browser
    would normally save.  Returns the saved path on success, None on failure.

    Two complementary mechanisms run in parallel:
      • page.expect_download()  — Playwright intercepts the browser download
        regardless of whether the JS uses fetch/XHR, window.open, or a direct
        <a download> click.
      • page.on("request") listener — logs every outgoing URL that looks
        PCAP-related so we learn the URL pattern even if the download itself
        is handled oddly.
    """
    try:
        _ev_dir = Path(settings.upload_dir) / "evidence" / sample_id
        _ev_dir.mkdir(parents=True, exist_ok=True)
        out_path = str(_ev_dir / f"{sample_id}.pcapng")
    except Exception:
        out_path = f"/tmp/triage_{sample_id}.pcapng"

    print(f"\n{'='*66}", flush=True)
    print("PCAP DOWNLOAD", flush=True)
    print(f"{'='*66}", flush=True)

    # Collect any network requests that look PCAP-related (fallback intelligence)
    captured_urls: list[str] = []

    def _on_request(req) -> None:
        url = req.url
        if re.search(r'pcap|dump|\.pcap|/network', url, re.IGNORECASE):
            captured_urls.append(url)
            print(f"  [net] {req.method} {url}", flush=True)

    page.on("request", _on_request)

    try:
        btn = page.locator("#download_pcapng")
        if btn.count() == 0:
            print("  [!] #download_pcapng button not found in DOM.", flush=True)
            return None

        print(f"  [*] Found #download_pcapng — clicking with expect_download …",
              flush=True)

        with page.expect_download(timeout=30_000) as dl_info:
            btn.click()

        download = dl_info.value
        url       = download.url
        suggested = download.suggested_filename

        print(f"  [+] Download triggered!", flush=True)
        print(f"      URL       : {url}", flush=True)
        print(f"      Filename  : {suggested!r}", flush=True)

        download.save_as(out_path)
        size = Path(out_path).stat().st_size

        print(f"  [+] Saved → {out_path}  ({size:,} bytes)", flush=True)

        if size == 0:
            print("  [!] WARNING: file is 0 bytes — download may have failed.",
                  flush=True)

        print(f"{'='*66}\n", flush=True)
        return out_path

    except PWTimeout:
        print("  [!] Download did not trigger within 30 s.", flush=True)
        if captured_urls:
            print("  Captured PCAP-related request URLs (URL pattern reference):",
                  flush=True)
            for u in captured_urls:
                print(f"    {u}", flush=True)
        else:
            print("  No PCAP-related network requests captured either.", flush=True)
        print(f"{'='*66}\n", flush=True)
        return None

    except Exception as exc:
        print(f"  [!] PCAP download error: {exc}", flush=True)
        print(f"{'='*66}\n", flush=True)
        return None

    finally:
        # Remove listener so it doesn't fire during subsequent page activity
        try:
            page.remove_listener("request", _on_request)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Replay Monitor screenshot capture
# ---------------------------------------------------------------------------

def _capture_replay_frames(page: Page, sample_id: str,
                           capture_secs: int = 90) -> list[str]:
    """
    Capture detonation screenshots from the Triage Replay Monitor canvas.

    Strategy: the canvas player auto-plays in headless Chromium at real-time speed.
    We capture 3 frames:
      frame_01_start — immediately once the canvas is rendering real content
      frame_02_mid   — at capture_secs / 2
      frame_03_end   — at capture_secs (≈ end of detonation for ransomware detection)

    Returns a list of saved PNG paths (0–3 items). Never raises.
    """
    try:
        out_dir = Path(settings.upload_dir) / "evidence" / sample_id
        out_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        out_dir = Path("/tmp")
    frames: list[str] = []

    try:
        # Expand the collapsible Replay Monitor section and scroll into view.
        page.evaluate("""() => {
            const hdr = document.getElementById('monitor-header');
            if (hdr) hdr.click();
            const el = document.getElementById('replay-monitor');
            if (el) el.scrollIntoView({block: 'center'});
        }""")

        # Poll until the canvas is rendering a real frame (> 100 KB of pixel data).
        # At load the canvas starts with ~20 KB (blank/loading), then jumps to ~900 KB
        # once the first frame is composited.
        print("[*] Waiting for replay canvas …", flush=True)
        deadline = time.monotonic() + 30
        canvas_ready = False
        while time.monotonic() < deadline:
            info = page.evaluate("""() => {
                const m = document.getElementById('replay-monitor');
                const c = m && m.querySelector('canvas');
                if (!c) return null;
                return {w: c.width, h: c.height, dataLen: c.toDataURL('image/png').length};
            }""")
            if info and info.get("dataLen", 0) > 100_000:
                print(f"  Canvas ready: {info['w']}×{info['h']} "
                      f"({info['dataLen']:,} bytes)", flush=True)
                canvas_ready = True
                break
            time.sleep(2)

        if not canvas_ready:
            print("  [!] Replay canvas never loaded — skipping screenshots.",
                  flush=True)
            return []

        def _grab(label: str) -> str | None:
            try:
                png_b64 = page.evaluate("""() => {
                    const m = document.getElementById('replay-monitor');
                    const c = m ? m.querySelector('canvas') : null;
                    return c ? c.toDataURL('image/png') : null;
                }""")
                if not png_b64 or not png_b64.startswith("data:image"):
                    return None
                raw = base64.b64decode(png_b64.split(",", 1)[1])
                if len(raw) < 10_000:  # < 10 KB → blank loading frame
                    return None
                path = str(out_dir / f"triage_{sample_id}_frame_{label}.png")
                Path(path).write_bytes(raw)
                timer_text = page.evaluate("""() => {
                    const m = document.getElementById('replay-monitor');
                    return m ? m.innerText.replace(/\s+/g,' ').trim().slice(0,25) : '';
                }""")
                print(f"  [+] Screenshot {label}: {len(raw):,} bytes  "
                      f"@{timer_text!r}", flush=True)
                return path
            except Exception as exc:
                print(f"  [!] Screenshot {label} failed: {exc}", flush=True)
                return None

        # Read video duration from timer text ("00:01 / 02:29")
        timer_txt = page.evaluate("""() => {
            const m = document.getElementById('replay-monitor');
            return m ? m.innerText.replace(/\s+/g,' ').trim().slice(0,30) : '';
        }""") or ""
        duration_secs = 0
        dur_m = re.search(r'/\s*(\d+):(\d+)', timer_txt)
        if dur_m:
            duration_secs = int(dur_m.group(1)) * 60 + int(dur_m.group(2))

        # Don't wait past end-of-video; ensure minimum 5 s so we get 3 distinct frames.
        effective = (min(capture_secs, max(duration_secs - 5, 5))
                     if duration_secs > 0 else capture_secs)

        # Frame 1 — initial desktop state
        f = _grab("01_start")
        if f:
            frames.append(f)

        # Frame 2 — mid-detonation
        mid = effective // 2
        if mid > 3:
            time.sleep(mid)
            f = _grab("02_mid")
            if f:
                frames.append(f)

        # Frame 3 — near-end state (ransomware wallpaper / ransom note)
        remaining = effective - mid
        if remaining > 3:
            time.sleep(remaining)
            f = _grab("03_end")
            if f:
                frames.append(f)

    except Exception as exc:
        print(f"[!] _capture_replay_frames: {exc}", flush=True)

    return frames


# ---------------------------------------------------------------------------
# Read an already-submitted sample (skips upload — useful for testing)
# ---------------------------------------------------------------------------

def read_sample_report(sample_id: str, headless: bool = True) -> dict:
    """
    Log in, go directly to /{id}/behavioral1, detect report content (no
    "Open Report" click needed), then run JSON-probe + HTML-scrape diagnostics.

    Used for --read to test extraction against a finished sample without
    spending a new submission.
    """
    behavioral_url = f"{_BASE}/{sample_id}/behavioral1"

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=headless)
        ctx  = browser.new_context(viewport={"width": 1280, "height": 900})
        page = ctx.new_page()

        if not _login(page):
            raise RuntimeError("Triage login failed — check credentials in .env")

        print(f"[*] Navigating directly to {behavioral_url} …", flush=True)
        page.goto(behavioral_url, wait_until="domcontentloaded", timeout=20_000)
        time.sleep(4)   # let React/JS render

        # Detect completion immediately; poll if not yet rendered
        indicator = page.evaluate(_BEHAVIORAL_DONE_JS)
        if indicator:
            print(f"[+] Report content detected immediately ({indicator}).", flush=True)
        else:
            print(f"[*] Content not yet visible — polling …", flush=True)
            indicator = _poll_behavioral_until_ready(page, behavioral_url)
            print(f"[+] Ready ({indicator}).", flush=True)

        # Screenshot of the real report
        page.screenshot(path="/tmp/triage_report_real.png")
        print(f"[*] Screenshot: /tmp/triage_report_real.png", flush=True)
        print(f"[*] Report URL: {page.url}", flush=True)
        print(f"[*] Title: {page.title()}", flush=True)

        # PCAP download diagnostic — reveals button URL/mechanism
        _dump_pcap_links(page)

        # Download PCAP — defensive: failure must not interrupt evidence extraction
        try:
            pcap_path = _download_pcap(page, sample_id)
        except Exception as _exc:
            pcap_path = None
            print(f"[!] PCAP download raised unexpectedly: {_exc}", flush=True)

        # Structured extraction → evidence dict
        evidence = extract_triage_report(page, sample_id)

        if pcap_path:
            evidence["pcap_path"] = pcap_path

        out_path = f"/tmp/triage_{sample_id}_evidence.json"
        Path(out_path).write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        print(f"[+] Evidence saved → {out_path}", flush=True)

        # Print key fields so the operator can verify
        print(f"\n  family:     {evidence['family']!r}", flush=True)
        print(f"  score:      {evidence['score']!r}", flush=True)
        print(f"  verdict:    {evidence['verdict']!r}", flush=True)
        print(f"  C2:         {evidence['malware_config'].get('c2')}", flush=True)
        print(f"  processes:  {len(evidence['processes'])} entries", flush=True)
        print(f"  signatures: {len(evidence['signatures'])} entries", flush=True)
        print(f"  mitre:      {[t['technique_id'] for t in evidence['mitre']]}", flush=True)
        ft = evidence.get("report_fulltext", "")
        print(f"  fulltext:   {len(ft):,} chars", flush=True)
        print(f"  registry:   {len(evidence.get('registry', []))} entries", flush=True)
        print(f"  network dns:{evidence['network'].get('dns')}", flush=True)
        print(f"  network tcp:{evidence['network'].get('tcp')}", flush=True)
        print(f"  pcap:       {pcap_path or '(not downloaded)'}", flush=True)

        print("[*] Complete — keeping browser open 9s.", flush=True)
        time.sleep(9)
        browser.close()
        return evidence


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="TEMPORARY Triage Playwright bridge.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m backend.app.services.triage_playwright --login-test\n"
            "  python -m backend.app.services.triage_playwright --login-test --headless\n"
            "  python -m backend.app.services.triage_playwright --submit sample.zip --password infected\n"
            "  python -m backend.app.services.triage_playwright --read 250620-abc12def34\n"
        ),
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--login-test", action="store_true",
                      help="Diagnostic login test (headless=False by default).")
    mode.add_argument("--submit", metavar="FILE",
                      help="Submit a file, wait for analysis, dump the report page.")
    mode.add_argument("--read", metavar="SAMPLE_ID",
                      help="Skip upload — read an already-finished sample by ID.")
    parser.add_argument("--password", default="infected",
                        help="Archive password for submitted sample (default: infected).")
    parser.add_argument("--headless", action="store_true", default=False,
                        help="Run headless (default: False — browser window visible).")
    args = parser.parse_args()

    if args.login_test:
        _run_login_test(headless=args.headless)

    elif args.submit:
        result = submit_and_fetch(args.submit, password=args.password, headless=args.headless)
        print(json.dumps(result, indent=2))

    elif args.read:
        result = read_sample_report(args.read, headless=args.headless)
        print(json.dumps(result, indent=2))
