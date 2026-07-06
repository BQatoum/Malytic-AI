"""
Dev helper: dump a completed case file to JSON.

Loads the case from the database and prints the full case_data JSON to stdout
so you can feed a real completed case into new phases offline without re-running
the expensive pipeline.

CLI:
    python -m backend.app.services.dump_case <case_id>
    python -m backend.app.services.dump_case <case_id> --compact
"""
from __future__ import annotations

import asyncio
import json
import sys

from ..database import AsyncSessionLocal
from . import case_file as cf_svc


async def _fetch(case_id: str) -> dict | None:
    async with AsyncSessionLocal() as db:
        row = await cf_svc.get_case(db, case_id)
        return dict(row.data) if row is not None else None


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Dump a completed case file as JSON",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m backend.app.services.dump_case <case_id>\n"
            "  python -m backend.app.services.dump_case <case_id> --compact\n"
        ),
    )
    parser.add_argument("case_id", help="Case ID to fetch")
    parser.add_argument(
        "--compact", action="store_true",
        help="Print compact JSON (no indentation)",
    )
    args = parser.parse_args()

    data = asyncio.run(_fetch(args.case_id))

    if data is None:
        print(f"[!] Case {args.case_id!r} not found in database.", file=sys.stderr)
        sys.exit(1)

    indent = None if args.compact else 2
    print(json.dumps(data, indent=indent, default=str))
