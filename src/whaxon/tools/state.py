"""whaxon state — dump the full project state to ~/Desktop/whaxon_state.md.

Read-only. Runs in ~15 seconds. Called via: whaxon state
"""
from __future__ import annotations

import ast
import hashlib
import importlib.metadata as _md
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
DESKTOP = Path.home() / "Desktop"
OUTPUT = DESKTOP / "whaxon_state.md"

SKIP_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache",
             ".ruff_cache", "node_modules", "build", "dist"}

SECRET_RX = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|bearer|AKIA[0-9A-Z]{16})"
    r"\s*[:=]\s*\S+"
)


def _run(cmd, cwd=None, timeout=30):
    try:
        r = subprocess.run(cmd, cwd=str(cwd or REPO), capture_output=True,
                           text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return f"[error running {cmd!r}: {e}]"


def _redact(text):
    return SECRET_RX.sub(lambda m: m.group(1) + "=<redacted>", text)


def _h(out, text):
    out.append("")
    out.append("## " + text)
    out.append("")


def _sub(out, text):
    out.append("")
    out.append("### " + text)
    out.append("")


def _code(out, text):
    out.append("```")
    out.extend((text or "").rstrip().splitlines() or [""])
    out.append("```")


def _kv(out, k, v):
    out.append(f"- **{k}**: {v}")


def _tree_files(root, suffixes=None):
    out = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if suffixes and not any(p.name.endswith(s) for s in suffixes):
            continue
        out.append(p)
    return out


def _rel(p):
    try:
        return str(p.relative_to(REPO))
    except ValueError:
        return str(p)


def _loc(p):
    try:
        return len(p.read_text(encoding="utf-8", errors="replace").splitlines())
    except Exception:
        return -1


def _sha256(p):
    try:
        h = hashlib.sha256()
        h.update(p.read_bytes())
        return h.hexdigest()
    except Exception:
        return "?"


def sec_metadata(out):
    _h(out, "1. Snapshot metadata")
    _kv(out, "generated", datetime.now().isoformat(timespec="seconds"))
    _kv(out, "host", socket.gethostname())
    _kv(out, "user", os.environ.get("USER") or os.environ.get("LOGNAME") or "?")
    _kv(out, "cwd", str(REPO))
    _kv(out, "python", sys.version.split()[0])
    _kv(out, "platform", platform.platform())
    _kv(out, "executable", sys.executable)
    try:
        from whaxon import __version__ as _v
        _kv(out, "whaxon", _v)
    except Exception:
        _kv(out, "whaxon", "(import failed)")
    _kv(out, "output", str(OUTPUT))


def sec_git(out):
    _h(out, "2. Git")
    _kv(out, "branch", _run(["git", "branch", "--show-current"]).strip())
    _kv(out, "HEAD", _run(["git", "log", "-1", "--format=%h %s"]).strip())
    _kv(out, "origin/HEAD", _run(["git", "log", "-1", "--format=%h %s", "origin/HEAD"]).strip())
    _kv(out, "ahead/behind", _run(["git", "rev-list", "--left-right", "--count",
                                   "origin/main...HEAD"]).strip())
    _kv(out, "remote", _run(["git", "remote", "-v"]).strip())

    _sub(out, "working tree (git status --short)")
    _code(out, _run(["git", "status", "--short"]) or "(clean)")

    _sub(out, "last 15 commits")
    _code(out, _run(["git", "log", "--oneline", "-15"]))

    _sub(out, "tags")
    _code(out, _run(["git", "tag"]) or "(none)")

    _sub(out, "stash")
    _code(out, _run(["git", "stash", "list"]) or "(empty)")

    _sub(out, "reflog — last 20 HEAD movements")
    _code(out, _run(["git", "reflog", "-20"]) or "(empty)")


def sec_tests(out, run_pytest=True):
    _h(out, "3. Tests")

    collected = ""
    if not run_pytest:
        _kv(out, "collected", "(skipped — pytest not run in this mode)")
        _kv(out, "result", "(skipped)")
    else:
        collected = _run(["python", "-m", "pytest", "tests/", "--collect-only", "-q", "-p", "no:cacheprovider"])
        last = [l for l in collected.splitlines()
                if "test" in l.lower() and "collected" in l.lower()]
        _kv(out, "collected", last[-1] if last else "(unknown)")

        run = _run(["python", "-m", "pytest", "tests/", "-q", "-p", "no:cacheprovider"], timeout=120)
        tail = [l for l in run.splitlines()
                if "passed" in l or "failed" in l or "error" in l.lower()]
        _kv(out, "result", tail[-1] if tail else "(unknown)")

    _sub(out, "test files with line counts")
    lines = []
    for p in _tree_files(REPO / "tests", suffixes=(".py",)):
        lines.append(f"{_loc(p):5d}  {_rel(p)}")
    _code(out, "\n".join(lines) or "(none)")

    _sub(out, "every test name")
    names = [l for l in collected.splitlines() if l.startswith("tests/")]
    _code(out, "\n".join(names) or "(none)")


def sec_env(out):
    _h(out, "4. Environment")

    _sub(out, "installed packages (whaxon-relevant)")
    pkgs = ["whaxon", "textual", "rich", "textual-image", "PySide6", "qasync",
            "flask", "gunicorn", "bcrypt", "flask-limiter", "markdown",
            "pymetasploit3", "platformdirs", "pytest", "pytest-asyncio",
            "ruff", "mypy"]
    lines = []
    for p in pkgs:
        try:
            lines.append(f"{p}=={_md.version(p)}")
        except _md.PackageNotFoundError:
            lines.append(f"{p}=<not installed>")
    _code(out, "\n".join(lines))

    _sub(out, "binaries on PATH")
    for b in ("pandoc", "weasyprint", "hashcat", "msfconsole",
              "impacket-secretsdump", "nmap", "nikto", "sqlmap"):
        _kv(out, b, shutil.which(b) or "(not found)")

    _sub(out, "WHAXON_* env vars set in this shell")
    env_lines = [f"{k}={_redact(v)}" for k, v in sorted(os.environ.items())
                 if k.startswith("WHAXON_")]
    _code(out, "\n".join(env_lines) or "(none set)")

    _sub(out, "daemon / running processes")
    ps = _run(["pgrep", "-af", "whaxon"])
    _code(out, ps.strip() or "(no whaxon processes)")

    _sub(out, "runtime files")
    pid_file = REPO / "data" / "whaxon.pid"
    log_file = REPO / "data" / "whaxon.log"
    _kv(out, "pid file", f"{pid_file} exists={pid_file.exists()}")
    _kv(out, "log file",
        f"{log_file} size={log_file.stat().st_size if log_file.exists() else 0}")


def sec_tree(out):
    _h(out, "5. Source tree")

    _sub(out, "src/ tree (directories)")
    _code(out, _run(["find", "src", "-type", "d", "-not", "-path", "*__pycache__*"]))

    _sub(out, "src/whaxon/*.py with line counts")
    lines = []
    for p in _tree_files(REPO / "src" / "whaxon", suffixes=(".py",)):
        lines.append(f"{_loc(p):5d}  {_rel(p)}")
    _code(out, "\n".join(lines))

    _sub(out, "web assets")
    for sub in ("templates", "static"):
        lines = []
        for p in _tree_files(REPO / "src" / "whaxon" / "interfaces" / "web" / sub):
            lines.append(f"{_loc(p):5d}  {_rel(p)}")
        _code(out, "\n".join(lines) or "(none)")


def sec_module_inventory(out):
    _h(out, "6. Module inventory (public symbols)")

    for p in _tree_files(REPO / "src" / "whaxon", suffixes=(".py",)):
        try:
            tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
        except Exception as e:
            _sub(out, _rel(p))
            _code(out, f"(parse error: {e})")
            continue

        _sub(out, f"{_rel(p)}  ({_loc(p)} lines)")
        doc = ast.get_docstring(tree)
        if doc:
            out.append(f"> {doc.splitlines()[0]}")

        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    if n.name.startswith("whaxon"):
                        imports.append(n.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module.startswith("whaxon"):
                    imports.append(node.module)
        if imports:
            out.append(f"- imports: {', '.join(sorted(set(imports)))}")

        members = []
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
                members.append(f"class {node.name}")
                for sub in node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if sub.name.startswith("_") and sub.name != "__init__":
                            continue
                        args = [a.arg for a in sub.args.args if a.arg != "self"]
                        members.append(f"    def {sub.name}({', '.join(args)})")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name.startswith("_"):
                    continue
                args = [a.arg for a in node.args.args]
                members.append(f"def {node.name}({', '.join(args)})")
            elif isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and t.id.isupper():
                        members.append(f"{t.id} = ...")
        if members:
            _code(out, "\n".join(members))


def sec_cli(out):
    _h(out, "7. CLI surface")
    _sub(out, "help string")
    _code(out, _run(["whaxon", "--help"]))
    _sub(out, "cli.py dispatch")
    _code(out, _run(["grep", "-nE", "mode ==|mode in", "src/whaxon/cli.py"]))


def sec_adapters(out):
    _h(out, "8. Adapters")
    lines = []
    for p in _tree_files(REPO / "src" / "whaxon" / "adapters", suffixes=(".py",)):
        text = p.read_text(encoding="utf-8", errors="replace")
        m = re.search(r'tool_id\s*=\s*"([^"]+)"', text)
        c = re.search(r"^class\s+(\w+)", text, re.MULTILINE)
        reg = "register(" in text
        cls = c.group(1) if c else "?"
        tid = m.group(1) if m else "?"
        lines.append(f"{_rel(p):60s}  class={cls:20s}  tool_id={tid:15s}  register={reg}")
    _code(out, "\n".join(lines))


def sec_routes(out):
    _h(out, "9. HTTP routes")
    text = (REPO / "src" / "whaxon" / "interfaces" / "web" / "server.py").read_text()
    rows = []
    for m in re.finditer(
        r'@app\.(get|post|put|delete|route)\(([^)]*)\)\s*\n\s*def\s+(\w+)', text
    ):
        lineno = text[:m.start()].count("\n") + 1
        rows.append(
            f"{m.group(1).upper():7s} {m.group(2).strip():50s} "
            f"{m.group(3):35s} line {lineno}"
        )
    _code(out, "\n".join(rows) or "(none)")


def sec_env_drift(out):
    _h(out, "10. Environment variable drift")

    code_vars = set()
    for p in _tree_files(REPO / "src" / "whaxon", suffixes=(".py",)):
        text = p.read_text(encoding="utf-8", errors="replace")
        code_vars |= set(re.findall(r"WHAXON_[A-Z_]+", text))

    doc_vars = set()
    candidates = _tree_files(REPO / "docs", suffixes=(".md",))
    candidates.append(REPO / "README.md")
    for p in candidates:
        if p.exists():
            text = p.read_text(encoding="utf-8", errors="replace")
            doc_vars |= set(re.findall(r"WHAXON_[A-Z_]+", text))

    _sub(out, "read in code but not mentioned in docs")
    _code(out, "\n".join(sorted(code_vars - doc_vars)) or "(none)")

    _sub(out, "documented but not read in code")
    _code(out, "\n".join(sorted(doc_vars - code_vars)) or "(none)")


def sec_drift(out, run_pytest=True):
    _h(out, "11. Drift verdicts")

    readme = (REPO / "README.md").read_text(encoding="utf-8", errors="replace")
    m = re.search(r"(\d+)\s+tests?\s+passing", readme)
    readme_n = int(m.group(1)) if m else None
    actual = None
    if run_pytest:
        collected = _run(["python", "-m", "pytest", "tests/", "--collect-only", "-q", "-p", "no:cacheprovider"])
        mm = re.search(r"(\d+)\s+tests?\s+collected", collected)
        if mm:
            actual = int(mm.group(1))
    if readme_n is not None and actual is not None:
        ok = readme_n == actual
        _kv(out, "README test count",
            f"doc={readme_n} actual={actual} {'OK' if ok else 'MISMATCH'}")

    intf = (REPO / "docs" / "interfaces.md").read_text(encoding="utf-8", errors="replace")
    m = re.search(r"(\w+)\s+subcommands", intf)
    declared = m.group(1) if m else "?"
    dispatch = _run(["grep", "-cE", "^    elif mode ==", "src/whaxon/cli.py"]).strip()
    _kv(out, "subcommand count", f"doc='{declared}' dispatch_branches={dispatch}")

    bad = _run(["grep", "-rln", "?fmt=", "README.md", "docs/api.md", "docs/interfaces.md", "docs/reports-and-evidence.md", "docs/findings.md"])
    _kv(out, "?fmt= in docs (target 0 files)", bad.strip() or "OK (0 files)")

    empty = []
    for d in sorted((REPO / "src").rglob("*")):
        if d.is_dir() and d.name not in SKIP_DIRS:
            if not any(d.iterdir()):
                empty.append(_rel(d))
    _kv(out, "empty directories under src/",
        ", ".join(empty) if empty else "OK (none)")

    emptypkg = []
    for d in sorted((REPO / "src").rglob("*")):
        if d.is_dir() and d.name not in SKIP_DIRS:
            files = [f for f in d.iterdir() if f.is_file()]
            if len(files) == 1 and files[0].name == "__init__.py":
                if files[0].stat().st_size < 20:
                    emptypkg.append(_rel(d))
    _kv(out, "empty packages",
        ", ".join(emptypkg) if emptypkg else "OK (none)")

    baks = _run(["find", ".", "-name", "*.bak", "-not", "-path", "*/.git/*"])
    _kv(out, ".bak files in tree",
        baks.strip().replace("\n", ", ") or "OK (none)")

    todo = _run(["grep", "-rn", "-E", "TODO|FIXME|XXX|HACK", "src/", "tests/"])
    todo_count = len([l for l in todo.strip().splitlines() if l])
    _kv(out, "TODO/FIXME/XXX/HACK count", str(todo_count))
    if todo_count:
        _code(out, todo.strip())


def sec_forensics(out):
    _h(out, "12. Forensics — what was happening before a crash?")

    files = (
        _tree_files(REPO / "src", suffixes=(".py",))
        + _tree_files(REPO / "tests", suffixes=(".py",))
    )
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)

    _sub(out, "20 most recently modified source files")
    lines = []
    for p in files[:20]:
        ts = datetime.fromtimestamp(p.stat().st_mtime).isoformat(timespec="seconds")
        lines.append(f"{ts}  {_rel(p)}")
    _code(out, "\n".join(lines))

    _sub(out, "files modified in the last hour")
    import time
    now = time.time()
    recent = [p for p in files if now - p.stat().st_mtime < 3600]
    _code(out, "\n".join(_rel(p) for p in recent) or "(none)")

    _sub(out, "stale temp files in /tmp")
    tmps = list(Path("/tmp").glob("whaxon_*")) if Path("/tmp").exists() else []
    _code(out, "\n".join(str(p) for p in tmps) or "(none)")

    _sub(out, "whaxon.log tail (last 30 lines)")
    log = REPO / "data" / "whaxon.log"
    if log.exists():
        lines = log.read_text(errors="replace").splitlines()[-30:]
        _code(out, "\n".join(lines))
    else:
        _code(out, "(no log file)")


def sec_store(out):
    _h(out, "13. Runtime store (if exists)")

    dbs = sorted((REPO / "data").glob("*.db")) + sorted((REPO / "data").glob("*.sqlite*"))
    if not dbs:
        _code(out, "(no store file)")
        return
    db = dbs[0]
    _kv(out, "store path", _rel(db))
    _kv(out, "size", f"{db.stat().st_size} bytes")
    try:
        import sqlite3
        c = sqlite3.connect(str(db))
        try:
            tables = c.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
            for (t,) in tables:
                n = c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                _kv(out, f"table {t}", f"{n} rows")
        finally:
            c.close()
    except Exception as e:
        _kv(out, "store read", f"error: {e}")


def sec_hashes(out):
    _h(out, "14. sha256 of source and test files")
    rows = []
    for p in (
        _tree_files(REPO / "src", suffixes=(".py",))
        + _tree_files(REPO / "tests", suffixes=(".py",))
    ):
        rows.append(f"{_sha256(p)}  {_rel(p)}")
    _code(out, "\n".join(rows))


def sec_state_card(out):
    _h(out, "15. docs/STATE.md (hand-authored state card)")
    p = REPO / "docs" / "STATE.md"
    if p.exists():
        _code(out, p.read_text(encoding="utf-8", errors="replace"))
    else:
        _code(out, "(no docs/STATE.md)")


def sec_changelog(out):
    _h(out, "16. docs/CHANGELOG.md (head 50)")
    p = REPO / "docs" / "CHANGELOG.md"
    if p.exists():
        _code(out, "\n".join(
            p.read_text(encoding="utf-8", errors="replace").splitlines()[:50]))
    else:
        _code(out, "(no CHANGELOG.md)")


def sec_sizes(out):
    _h(out, "17. Largest source files (excluding archive/ and images)")
    files = _tree_files(REPO / "src", suffixes=(".py",))
    files.sort(key=_loc, reverse=True)
    lines = [f"{_loc(p):5d}  {_rel(p)}" for p in files[:15]]
    _code(out, "\n".join(lines))


def build(run_pytest=True):
    out = []

    out.append("# WHAXON state snapshot")
    out.append("")
    out.append("Full read-only diagnostic dump of the WHAXON project. Paste its")
    out.append("contents into a fresh assistant session to bring the assistant")
    out.append("up to speed without running any commands.")
    out.append("")

    sec_metadata(out)
    sec_git(out)
    sec_tests(out, run_pytest=run_pytest)
    sec_env(out)
    sec_tree(out)
    sec_module_inventory(out)
    sec_cli(out)
    sec_adapters(out)
    sec_routes(out)
    sec_env_drift(out)
    sec_drift(out, run_pytest=run_pytest)
    sec_forensics(out)
    sec_store(out)
    sec_hashes(out)
    sec_state_card(out)
    sec_changelog(out)
    sec_sizes(out)

    out.append("")
    out.append("## End of snapshot")
    out.append("")
    return "\n".join(out)


def main(args=None):
    text = build()
    DESKTOP.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(text, encoding="utf-8")
    size = OUTPUT.stat().st_size
    print(f"Wrote {OUTPUT} ({size} bytes, {text.count(chr(10))} lines)")


if __name__ == "__main__":
    main()