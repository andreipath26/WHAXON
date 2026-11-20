"""Explicit dependency installation command for whaxon doctor."""
from __future__ import annotations

import argparse
import json
import sys

from whaxon.core.installer import apply_approved_dependency_plan


def main(args: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="whaxon doctor --install",
        description="Install one manifest-allowlisted Python package after explicit plan-ID approval.",
    )
    parser.add_argument("--check", required=True, metavar="DEPENDENCY_ID",
                        help="Dependency ID to install.")
    parser.add_argument("--approve", required=True, metavar="PLAN_ID",
                        help="Exact plan ID reviewed by the user.")
    ns = parser.parse_args(args)
    try:
        result = apply_approved_dependency_plan(ns.check, ns.approve)
    except (ValueError, OSError) as exc:
        print(f"Installation not started: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
