"""Severity correction policy.

Applied at resolve time when a finding's severity came from the adapter,
not from NVD. Some finding kinds cannot justify a high severity without
external confirmation — a directory listing is not critical, no matter
which tool reports it.

The policy is a ceiling, not a floor. It can only lower a severity. It
never raises one.

Rationale: findings written before an adapter fix carry the old adapter's
classification. The resolver cannot correct them because their CVEs have
no CVSS in NVD. This table is the correction.

Design ref: docs/report-redesign.md section 1a.
"""
from __future__ import annotations

SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _rank(sev: str) -> int:
    try:
        return SEV_ORDER.index(sev.lower())
    except ValueError:
        return len(SEV_ORDER) - 1


def _ceiling_for(raw_line: str) -> str | None:
    """Return a maximum severity for the finding, or None for no limit."""
    r = raw_line.lower()
    if "directory is browsable" in r or "directory indexing" in r:
        return "medium"
    if "directory listing" in r:
        return "medium"
    if "etags" in r and "inode" in r:
        return "info"
    if "may leak inodes" in r:
        return "info"
    if "server may leak" in r:
        return "info"
    if "x-frame-options" in r or "clickjacking" in r:
        return "low"
    if "strict-transport-security" in r:
        return "low"
    if "x-content-type-options" in r:
        return "low"
    # EOL / end-of-life signals. Informational on their own: the version
    # is old, but no exploit has been run against it.
    if "eol" in r or "end of life" in r:
        return "medium"
    if "weak ciphers" in r:
        return "medium"
    # VCS metadata disclosure. Real, but reconnaissance-grade.
    if "/.gitignore" in r or "gitignore file found" in r:
        return "medium"
    if "/.git/config" in r or "git repository" in r:
        return "high"
    return None


def apply_ceiling(finding: dict) -> dict:
    """Lower finding severity if a policy ceiling applies.

    Only acts when severity_source is 'adapter'. NVD-backed severities
    are not touched — they come from an authoritative source.
    """
    out = dict(finding)
    if out.get("severity_source") != "adapter":
        return out

    raw = out.get("raw_line") or ""
    ceiling = _ceiling_for(raw)
    if ceiling is None:
        return out

    current = (out.get("severity") or "info").lower()
    if _rank(current) < _rank(ceiling):
        out["severity"] = ceiling
        out["severity_policy_applied"] = True
        out["severity_policy_ceiling"] = ceiling
    return out
