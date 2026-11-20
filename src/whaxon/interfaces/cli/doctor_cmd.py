"""whaxon doctor --plan: print a read-only remediation preview."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from whaxon.core.dependencies import collect_dependency_report
from whaxon.core.installer import apply_approved_dependency_plan
from whaxon.core.remediation import build_remediation_plan


def main(args: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="whaxon doctor",
        description="Read-only environment and dependency readiness report.",
    )
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="Print the versioned machine-readable report.")
    parser.add_argument("--check", metavar="DEPENDENCY_ID",
                        help="Show one dependency only (read-only).")
    parser.add_argument("--plan", action="store_true",
                        help="Generate a remediation preview; never executes commands.")
    parser.add_argument("--verify", action="store_true",
                        help="Run only manifest-curated, bounded external version probes.")
    parser.add_argument("--snapshot", action="store_true",
                        help="Save a local readiness snapshot after diagnostics.")
    parser.add_argument("--drift", action="store_true",
                        help="Compare current readiness with the latest saved snapshot.")
    parser.add_argument("--install", action="store_true",
                        help="Install one dependency after explicit plan-ID approval.")
    parser.add_argument("--approve", metavar="PLAN_ID",
                        help="Exact plan ID reviewed before installation.")
    parser.add_argument("--data", type=Path, default=Path("data"),
                        help="WHAXON data directory (default: ./data).")
    parser.add_argument("--core-only", action="store_true",
                        help="Skip optional Python extras and external tool checks.")
    ns = parser.parse_args(args)
    if ns.snapshot and ns.drift:
        parser.error("--snapshot and --drift cannot be combined")
    if ns.verify and ns.core_only:
        parser.error("--verify cannot be combined with --core-only")
    if ns.plan and (ns.verify or ns.snapshot or ns.drift or ns.install):
        parser.error("--plan cannot be combined with --verify, --snapshot, --drift or --install")
    if ns.install and (ns.verify or ns.snapshot or ns.drift or ns.core_only):
        parser.error("--install cannot be combined with --verify, --snapshot, --drift or --core-only")
    if ns.install:
        if not ns.check or not ns.approve:
            parser.error("--install requires both --check DEPENDENCY_ID and --approve PLAN_ID")
        try:
            result = apply_approved_dependency_plan(ns.check, ns.approve, data_dir=ns.data)
        except (ValueError, OSError) as exc:
            print(f"Installation not started: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "VERIFIED" else 1
    if ns.approve:
        parser.error("--approve can only be used with --install")
    if ns.plan:
        plan = build_remediation_plan(
            dependency_ids=[ns.check] if ns.check else None,
            data_dir=ns.data,
        )
        print(json.dumps(plan, indent=2, sort_keys=True))
        return 2 if plan["unknown_dependency_ids"] else 0
    report = collect_dependency_report(
        data_dir=ns.data,
        include_optional=not ns.core_only,
        include_external=not ns.core_only,
        verify_external=ns.verify,
    )
    if ns.check:
        matches = [d for d in report["dependencies"] if d["id"] == ns.check]
        if not matches:
            print(f"Unknown dependency id: {ns.check}")
            return 2
        report["dependencies"] = matches
        ready = sum(item["status"] == "READY" for item in matches)
        missing = sum(item["status"] == "MISSING" for item in matches)
        incompatible = sum(item["status"] == "INCOMPATIBLE" for item in matches)
        broken = sum(item["status"] == "BROKEN" for item in matches)
        required_blockers = sum(
            bool(item.get("required")) and item["status"] != "READY"
            for item in matches
        )
        optional_degraded = sum(
            not item.get("required") and item["status"] != "READY"
            for item in matches
        )
        report["summary"] = {
            "total": len(matches),
            "ready": ready,
            "missing": missing,
            "detected_unverified": sum(item["status"] == "DETECTED" for item in matches),
            "incompatible": incompatible,
            "broken": broken,
            "required_blockers": required_blockers,
            "optional_degraded": optional_degraded,
        }
        report["overall_status"] = (
            "BLOCKED" if required_blockers
            else "DEGRADED" if optional_degraded or missing or incompatible or broken
            else "READY"
        )
    if ns.snapshot:
        from whaxon.core.dependency_history import record_snapshot

        snapshot = record_snapshot(report, ns.data)
        print(json.dumps(snapshot, indent=2, sort_keys=True))
        return 0
    if ns.drift:
        from whaxon.core.dependency_history import compare_with_latest

        drift = compare_with_latest(report, ns.data)
        print(json.dumps(drift, indent=2, sort_keys=True))
        return 0
    if ns.as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        env = report["environment"]
        print(f"WHAXON environment readiness: {report['overall_status']}")
        print(f"Platform: {env['os']} {env['os_release']} ({env['architecture']})")
        print(f"Python:   {env['python']} — {env['python_executable']}")
        print(f"Venv:     {'yes' if env['virtual_environment'] else 'no'}")
        print()
        print(f"{'STATUS':14} {'ID':20} {'VERSION / PATH':34} REASON")
        for dep in report["dependencies"]:
            observed = dep.get("detected_version") or dep.get("detected_path") or "-"
            print(f"{dep['status']:14} {dep['id'][:20]:20} {observed[:34]:34} {dep['reason']}")
        print()
        print("This command is read-only. No packages were installed and no network was used.")
        print("Use --plan for a remediation preview; it also does not execute commands.")
    return 1 if report["overall_status"] == "BLOCKED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
