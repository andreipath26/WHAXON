"""whaxon suggest <job_id> — print next-step suggestions for each finding."""
from __future__ import annotations

import sys
from pathlib import Path

from whaxon.core import Core


# Suggestion table — mirrors the JS version in the web UI.
# Each rule: (match_fn, [(label, tool, extra_template)])


def _suggest_open_port(f):
    d = f.get("data", {}) or {}
    port = d.get("port")
    svc = (d.get("service") or "").lower()
    host = d.get("host") or ""
    out = []
    if svc in ("http", "https", "commplex-link") or port in (80, 443, 8080, 8443):
        out.append((f"Nikto on port {port}", "nikto", ""))
        out.append(("Gobuster", "gobuster", ""))
    elif svc in ("mysql", "postgresql", "redis", "mongodb"):
        out.append((f"Nmap -sV on {port}", "nmap", f"-sV -p {port}"))
    else:
        out.append((f"Nmap -sV on {port}", "nmap", f"-sV -p {port}"))
    return out


def _suggest_web_issue(f):
    d = f.get("data", {}) or {}
    name = (d.get("name") or d.get("message") or "").lower()
    path = d.get("path") or "/"
    out = []
    if "sql" in name:
        out.append((f"SQLmap against {path}", "sqlmap", ""))
    elif "wordpress" in name or "wp-" in name:
        out.append(("WPScan", "wpscan", ""))
    else:
        out.append(("Nuclei templates", "nuclei", ""))
    out.append((f"Gobuster on {path}", "gobuster", ""))
    return out


def _suggest_found_path(f):
    return [("Nuclei templates", "nuclei", "")]


def _suggest_vulnerability(f):
    return [("Verify with nmap -sV", "nmap", "-sV")]


RULES = {
    "open_port": _suggest_open_port,
    "web_issue": _suggest_web_issue,
    "found_path": _suggest_found_path,
    "vulnerability": _suggest_vulnerability,
}


def main(args: list[str] | None = None) -> None:
    args = list(args or [])
    if not args or args[0] in ("-h", "--help"):
        print("Usage: whaxon suggest <job_id> [--data DIR]")
        return

    job_id = args[0]
    data_dir = Path("data")
    i = 1
    while i < len(args):
        if args[i] == "--data" and i + 1 < len(args):
            data_dir = Path(args[i + 1])
            i += 2
        else:
            print(f"Unknown arg: {args[i]}")
            sys.exit(2)

    core = Core(data_dir=data_dir)
    job = core.store.get(job_id)
    if job is None:
        print(f"No job with id {job_id}")
        sys.exit(1)

    findings = core.store.get_findings(job_id) or []
    if not findings:
        print("(no findings)")
        return

    target = job.get("target", "")
    print(f"Job {job_id} — {job.get('tool', '')} against {target}")
    print(f"{len(findings)} finding(s)")
    print()

    for idx, f in enumerate(findings, 1):
        kind = f.get("kind", "")
        sev = f.get("severity", "info")
        d = f.get("data", {}) or {}
        name = d.get("name") or d.get("message") or d.get("path") or f"port {d.get('port', '')}"
        print(f"[{idx}] {sev:8} {kind}: {name}")

        rule = RULES.get(kind)
        if rule:
            for label, tool, extra in rule(f):
                cmd = f"whaxon run {tool} {target}"
                if extra:
                    cmd += f' --extra "{extra}"'
                print(f"     → {label}")
                print(f"       {cmd}")
        else:
            print("     (no suggestions for this finding kind)")
        print()
