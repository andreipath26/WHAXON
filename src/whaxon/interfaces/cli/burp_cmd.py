"""whaxon burp-import <file.xml> [--data DIR] [--target LABEL]."""
from __future__ import annotations

import sys
import uuid
from pathlib import Path

from whaxon.core import Core


def main(args: list[str] | None = None) -> None:
    args = list(args or [])
    if not args or args[0] in ("-h", "--help"):
        print("Usage: whaxon burp-import <file.xml> [--data DIR] [--target LABEL]")
        return

    xml_path = Path(args[0])
    if not xml_path.exists():
        print(f"File not found: {xml_path}")
        sys.exit(1)

    data_dir = Path("data")
    target_label = ""
    i = 1
    while i < len(args):
        a = args[i]
        if a == "--data" and i + 1 < len(args):
            data_dir = Path(args[i + 1]); i += 2
        elif a == "--target" and i + 1 < len(args):
            target_label = args[i + 1]; i += 2
        else:
            print(f"Unknown arg: {a}")
            sys.exit(2)

    from whaxon.adapters import get_adapter
    adapter = get_adapter("burp")
    if adapter is None:
        print("burp adapter not registered")
        sys.exit(1)

    findings = adapter.parse_file(xml_path)
    if not findings:
        print("No findings parsed from XML")
        sys.exit(1)

    job_id = uuid.uuid4().hex[:12]
    core = Core(data_dir=data_dir)
    core.store.create(job_id)
    target = target_label or findings[0].data.get("host") or "imported"
    core.store.set_started(job_id, "burp", target)

    core.store.append_line(job_id, "stdout",
        f"Imported {len(findings)} finding(s) from {xml_path.name}")
    for f in findings:
        loc = f.data.get("location") or f.data.get("path") or ""
        core.store.append_line(job_id, "stdout",
            f"  [{f.severity}] {f.data.get('name', '')} {loc}")

    for idx, f in enumerate(findings):
        core.store.append_finding(job_id, f.to_dict(), idx)

    core.store.set_finished(job_id, 0, 0.0)

    print(f"job:      {job_id}")
    print(f"target:   {target}")
    print(f"findings: {len(findings)}")
    for f in findings:
        print(f"  [{f.severity:8}] {f.data.get('name', '')[:60]}")
