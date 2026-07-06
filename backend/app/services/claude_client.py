"""
Thin wrapper around the Anthropic Messages API.

All phases call this. Model and token budget are passed by the caller so each
phase can tune them independently via settings.
"""
from __future__ import annotations

import os
import sys

import anthropic

from ..config import settings

# Latest web search tool version — supports dynamic filtering on claude-sonnet-4-6+.
# Previous version (web_search_20250305) remains available but lacks dynamic filtering.
_WEB_SEARCH_TOOL_TYPE = "web_search_20260209"

# Fragments in an APIStatusError message that indicate web search is disabled in Console.
_WEB_SEARCH_DISABLED_HINTS = (
    "web_search",
    "web search",
    "server tool",
    "not enabled",
    "not available",
    "feature",
)


def _collect_text(message: anthropic.types.Message) -> str:
    """
    Extract and concatenate all text blocks from a response.

    When web search is enabled, response.content is a mixed list of text,
    server_tool_use, and web_search_tool_result blocks. When it is not,
    content is typically a single text block. Both cases are handled here.
    """
    parts = [
        block.text
        for block in message.content
        if getattr(block, "type", None) == "text" and hasattr(block, "text")
    ]
    return "\n".join(parts)


def call_claude(
    system_prompt: str,
    user_content: str | list,
    model: str | None = None,
    max_tokens: int = 8192,
    enable_web_search: bool = False,
    max_web_searches: int = 5,
) -> str:
    """
    Call the Anthropic Messages API and return the assistant's text response.

    Parameters
    ----------
    system_prompt:
        Full system prompt (skill file content, reference files, etc.).
    user_content:
        The user-turn message — either a plain string or a list of Anthropic
        content blocks (e.g. text + base64 image blocks for multimodal calls).
    model:
        Model ID string. Defaults to settings.analysis_model so callers can
        override per phase via ANALYSIS_MODEL in .env.
    max_tokens:
        Maximum tokens in the response. Caller sets this per phase.
    enable_web_search:
        When True, attaches the web_search tool so Claude can search the web.
        Requires web search to be enabled in the Anthropic Console.
    max_web_searches:
        Cap on the number of searches Claude may perform per call (max_uses).
        Only used when enable_web_search=True.

    Returns
    -------
    str
        All text blocks from the response joined with newlines.

    Raises
    ------
    RuntimeError
        Wraps all Anthropic SDK errors with a clear message so callers have one
        exception type to handle. If web search is not enabled in the Console,
        the message says so explicitly.
    """
    resolved_model = model or settings.analysis_model

    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)

    create_kwargs: dict = dict(
        model=resolved_model,
        max_tokens=max_tokens,
        system=system_prompt,
        messages=[{"role": "user", "content": user_content}],
    )

    if enable_web_search:
        create_kwargs["tools"] = [
            {
                "type": _WEB_SEARCH_TOOL_TYPE,
                "name": "web_search",
                "max_uses": max_web_searches,
            }
        ]

    try:
        with client.messages.stream(**create_kwargs) as stream:
            message = stream.get_final_message()
        if os.environ.get("CLAUDE_DEBUG") == "1":
            print(
                f"[claude_debug] stop_reason={message.stop_reason}"
                f"  output_tokens={message.usage.output_tokens}"
                f"  model={message.model}",
                file=sys.stderr,
            )
    except anthropic.APIConnectionError as exc:
        raise RuntimeError(
            f"Anthropic API connection failed: {exc}"
        ) from exc
    except anthropic.RateLimitError as exc:
        raise RuntimeError(
            f"Anthropic rate limit exceeded — back off and retry: {exc}"
        ) from exc
    except anthropic.APIStatusError as exc:
        msg_lower = (exc.message or "").lower()
        if enable_web_search and any(h in msg_lower for h in _WEB_SEARCH_DISABLED_HINTS):
            raise RuntimeError(
                f"Web search is not enabled for this API key "
                f"(Anthropic API error {exc.status_code}: {exc.message}). "
                "Enable it at: https://console.anthropic.com → Settings → Privacy → Web Search."
            ) from exc
        raise RuntimeError(
            f"Anthropic API error {exc.status_code}: {exc.message}"
        ) from exc

    return _collect_text(message)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Claude API client — standalone test",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m backend.app.services.claude_client --test-search 'latest Lazarus Group TTPs'\n"
        ),
    )
    parser.add_argument(
        "--test-search",
        metavar="QUERY",
        help="Call Claude with the given query and web search enabled; print the text result.",
    )
    args = parser.parse_args()

    if not args.test_search:
        parser.print_help()
        sys.exit(0)

    print(f"[*] Querying Claude with web search enabled: {args.test_search!r}", file=sys.stderr)
    try:
        result = call_claude(
            system_prompt="You are a helpful threat-intelligence assistant.",
            user_content=args.test_search,
            enable_web_search=True,
        )
    except RuntimeError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(1)

    print(result)
