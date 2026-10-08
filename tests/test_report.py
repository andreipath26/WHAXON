"""Tests for report generation.

Two layers:
  - per-job markdown/html: render_markdown / render_html (CLI `whaxon report`)
  - engagement: to_markdown / to_json (the WHAXON Report)

Guards:
  - render_html is documented to wrap markdown in <pre> AND escape it.
    A raw_line containing "<script>" must not appear unescaped.
  - to_markdown must include pivot chains when passed.
"""
from __future__ import annotations

from whaxon.core.report import render_html, render_markdown, to_json, to_markdown


def _job():
    return {"id": "x", "tool": "nmap", "target": "t", "status": "finished",
            "exit_code": 0, "duration_s": 1.0,
            "lines": [{"stream": "stdout", "text": "hello"},
                      {"stream": "stderr", "text": "<script>"}]}


def _f():
    return [{"kind": "open_port", "severity": "high", "source": "nmap",
             "data": {"port": 22}, "raw_line": "22/tcp"}]


def _f_xss():
    return [{"kind": "open_port", "severity": "high", "source": "nmap",
             "data": {"port": 22},
             "raw_line": '22/tcp <script>alert(1)</script>'}]


def _report_dict():
    return {
        "engagement": "default",
        "generated": "2026-09-27T00:00:00",
        "job_count": 1,
        "finding_count": 1,
        "severity_counts": {"critical": 0, "high": 1, "medium": 0,
                            "low": 0, "info": 0},
        "jobs": [{"job": _job(), "findings": _f()}],
        "loot": [],
    }


# ---------- per-job ----------

def test_render_markdown_has_job_header_and_finding():
    md = render_markdown(_job(), _f())
    assert "# Job x" in md
    assert "**[HIGH]**" in md
    assert "`open_port`" in md


def test_render_html_wraps_markdown_in_pre():
    h = render_html(_job(), _f())
    assert "<pre" in h
    assert "# Job x" in h


def test_render_html_escapes_script_in_raw_line():
    """XSS guard: raw_line carrying <script> must be HTML-escaped."""
    h = render_html(_job(), _f_xss())
    assert "<script>alert(1)</script>" not in h
    assert "&lt;script&gt;" in h


# ---------- engagement ----------

def test_to_markdown_has_waxon_banner_and_tables():
    md = to_markdown(_report_dict())
    assert "# WHAXON Engagement Report" in md
    assert "## Executive Summary" in md
    assert "## Job History" in md
    assert "| Job | Tool | Target | Status | Exit |" in md


def test_to_json_roundtrip():
    import json
    out = json.loads(to_json(_report_dict()))
    assert out["engagement"] == "default"
    assert out["job_count"] == 1


def test_to_markdown_includes_pivot_chains():
    chains = [{
        "root": {"kind": "msf_session", "id": "1", "evidence": "smb"},
        "descendants": [
            {"relation": "from_exploit",
             "child": {"kind": "host", "id": "10.0.0.5"},
             "evidence": "pivot"},
        ],
    }]
    md = to_markdown(_report_dict(), chains=chains)
    assert "## Pivot Chains" in md
    assert "msf_session" in md
    assert "10.0.0.5" in md


def test_to_markdown_without_chains_omits_section():
    md = to_markdown(_report_dict())
    assert "## Pivot Chains" not in md
