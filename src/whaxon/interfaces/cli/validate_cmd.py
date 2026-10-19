"""whaxon validate <job_id> <seq> — deterministic validation of a finding."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from whaxon.core import Core
from whaxon.core.findings import Finding
from whaxon.core.validator import Validator

EXIT_OK = 0
EXIT_NOT_FOUND = 1
EXIT_USAGE = 2

def main(args: list[str] | None = None) -> int:
    args = list(args or [])
    if len(args) != 2:
        print("Usage: whaxon validate <job_id> <seq>", file=sys.stderr)
        return EXIT_USAGE

    job_id, seq_str = args
    try:
        seq = int(seq_str)
    except ValueError:
        print(f"Invalid seq: {seq_str}", file=sys.stderr)
        return EXIT_USAGE

    data_dir = Path("data")
    core = Core(data_dir)
    asyncio.run(core.initialize())
    
    # Fetch the finding
    findings = core.store.get_findings(job_id)
    target_f = None
    for f in findings:
        if f["seq"] == seq:
            target_f = f
            break
            
    if not target_f:
        print(f"Finding not found: {job_id} seq {seq}", file=sys.stderr)
        return EXIT_NOT_FOUND

    print(f"[*] Validating {target_f['kind']} (job {job_id}, seq {seq})...")
    
    # Build the Finding object
    f_obj = Finding(
        kind=target_f["kind"],
        severity=target_f["severity"],
        source=target_f["source"],
        data=target_f["data"],
        raw_line=target_f["raw_line"]
    )

    # Run the validator
    pkg_payloads = Path(__file__).resolve().parent.parent.parent / "data" / "payloads"
    validator = Validator(pkg_payloads)
    result = validator.validate(f_obj)
    
    # Update the store
    core.store.update_verification(job_id, seq, result)
    
    print(f"[=] Verification status: {result.upper()}")
    return EXIT_OK
