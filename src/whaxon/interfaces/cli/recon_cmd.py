"""whaxon recon <target> — passive recon pass (DNS, SSL, headers, tech, etc.)."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from whaxon.core import Core

EXIT_OK = 0
EXIT_OUT_OF_SCOPE = 1
EXIT_USAGE = 2
EXIT_ERROR = 3


def main(args: list[str] | None = None) -> int:
    args = list(args or [])
    data_dir = Path("data")
    checks: list[str] | None = None
    verbose = False
    positional: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--data" and i + 1 < len(args):
            data_dir = Path(args[i + 1]); i += 2
        elif a == "--checks" and i + 1 < len(args):
            checks = [c.strip() for c in args[i + 1].split(",") if c.strip()]
            i += 2
        elif a in ("-v", "--verbose"):
            verbose = True; i += 1
        elif a in ("-h", "--help"):
            _usage()
            return EXIT_OK
        else:
            positional.append(a); i += 1

    if len(positional) != 1:
        _usage()
        return EXIT_USAGE

    target = positional[0]
    core = Core(data_dir)
    asyncio.run(core.initialize(drain=False))

    if verbose:
        print(f"[recon] target={target}", file=sys.stderr)
        print(f"[recon] data_dir={data_dir}", file=sys.stderr)
        print(f"[recon] checks={checks or 'all'}", file=sys.stderr)

    match = core.scope.check(target)
    if verbose:
        print(f"[recon] scope: allowed={match.allowed} reason={match.reason} rule={match.matched_rule}", file=sys.stderr)
    if not match.allowed:
        print(f"Out of scope: {target} ({match.reason})", file=sys.stderr)
        return EXIT_OUT_OF_SCOPE

    if verbose:
        print("[recon] running checks...", file=sys.stderr)
    job_id = core.recon.run(target, checks=checks)
    if verbose:
        print(f"[recon] job_id={job_id}", file=sys.stderr)
    if job_id is None:
        print(f"No findings for {target}", file=sys.stderr)
        return EXIT_OK

    findings = core.store.get_findings(job_id)
    print(f"recon: {target}  (job {job_id}, {len(findings)} findings)")
    for f in findings:
        print(f"  [{f['severity']:8s}] {f['kind']:28s} {f['raw_line'][:90]}")
        if verbose:
            print(f"    data: {f.get('data')}", file=sys.stderr)
            print(f"    remediation: {f.get('remediation', '')[:120]}", file=sys.stderr)
            print(f"    impact: {f.get('impact', '')[:120]}", file=sys.stderr)
    return EXIT_OK


def _usage() -> None:
    print(
        "Usage: whaxon recon <target> [--data DIR] [--checks a,b,c]\n"
        "\n"
        "  Runs passive recon checks against <target>. Target must be in scope.\n"
        "\n"
        "  Available checks:\n"
        "    dns        A/AAAA/MX/NS/TXT/SOA records\n"
        "    ssl        TLS certificate, SANs, expiry\n"
        "    headers    missing security headers\n"
        "    tech       server framework / CMS detection\n"
        "    robots     /robots.txt and /sitemap.xml\n"
        "    security_txt  /.well-known/security.txt (RFC 9116)\n"
        "    cookies    Set-Cookie flag audit\n"
        "    redirects  redirect chain, HTTPS->HTTP downgrades\n"
        "    waf        WAF / CDN fingerprinting\n"
        "    dns_full   CAA, DMARC, SPF records\n"
        "\n"
        "  Default: all checks.",
        file=sys.stderr,
    )
