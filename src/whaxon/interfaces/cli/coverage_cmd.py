"""whaxon coverage <job_id> — report what a job skipped."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from whaxon.core import Core

EXIT_OK = 0
EXIT_NOT_FOUND = 1
EXIT_USAGE = 2


def main(args: list[str] | None = None) -> int:
    args = list(args or [])
    if len(args) != 1:
        print("Usage: whaxon coverage <job_id>", file=sys.stderr)
        return EXIT_USAGE

    job_id = args[0]
    core = Core(Path("data"))
    asyncio.run(core.initialize())

    job = core.store.get(job_id)
    if not job:
        print(f"Job not found: {job_id}", file=sys.stderr)
        return EXIT_NOT_FOUND

    rows = core.store.list_coverage(job_id)
    if not rows:
        print(f"No coverage gaps recorded for {job_id}.")
        return EXIT_OK

    print(f"Coverage gaps for {job_id} ({job['tool']} against {job['target']}):")
    for r in rows:
        print(f"  [{r['kind']:<14}] {r['tool_id']:<10} {r['target']:<20} {r['detail']}")
    return EXIT_OK
