"""whaxon evidence <job_id> [--add FILE --note TEXT] [--list] [--rm SEQ]."""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

from whaxon.core import Core


def main(args: list[str] | None = None) -> None:
    args = list(args or [])
    if not args or args[0] in ("-h", "--help"):
        print("Usage: whaxon evidence <job_id> [--add FILE] [--note TEXT] [--list] [--rm SEQ]")
        return
    job_id = args[0]
    data_dir = Path("data")
    action, add_file, note, rm_seq = "list", None, None, None
    i = 1
    while i < len(args):
        a = args[i]
        if a == "--data" and i + 1 < len(args): data_dir = Path(args[i + 1]); i += 2
        elif a == "--add" and i + 1 < len(args): action, add_file = "add", Path(args[i + 1]); i += 2
        elif a == "--note" and i + 1 < len(args): note = args[i + 1]; i += 2
        elif a == "--list": action = "list"; i += 1
        elif a == "--rm" and i + 1 < len(args): action, rm_seq = "rm", int(args[i + 1]); i += 2
        else: print(f"Unknown arg: {a}"); sys.exit(2)
    core = Core(data_dir=data_dir)
    if core.store.get(job_id) is None:
        print(f"No job with id {job_id}"); sys.exit(1)
    if action == "list":
        items = core.store.list_evidence(job_id)
        if not items: print("(no evidence)"); return
        for x in items: print(f"{x['seq']:>4}  {x['kind']:>10}  {x['name']:<40}  {x.get('note') or ''}")
    elif action == "add":
        if add_file and add_file.exists():
            dest_dir = data_dir / "evidence" / job_id
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = dest_dir / add_file.name
            shutil.copy2(add_file, dest)
            seq = core.store.add_evidence(job_id, "file", add_file.name, path=str(dest.relative_to(data_dir)), note=note)
            print(f"added file seq={seq}: {add_file.name}")
        elif note:
            print(f"added note seq={core.store.add_evidence(job_id, 'note', 'note', note=note)}")
        else: print("provide --add FILE or --note TEXT"); sys.exit(2)
    elif action == "rm":
        print("removed" if core.store.remove_evidence(job_id, rm_seq) else "not found")
