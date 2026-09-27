"""Tests for report generation.

Two layers:
  - per-job markdown/html: render_markdown / render_html (CLI `whaxon report`)
  - engagement: to_markdown / to_json (the WHAXON Report)

Guards against a stale assumption: render_html is documented to wrap the
markdown in a <pre> — it is NOT a full HTML renderer. That is intentional.
"""
from __future__ import annotations

from whaxon.core.report import render_markdown, render_html, to_markdown, to_json


def _job():
    return {"id": "x", "tool": "nmap", "target": "t", "status": "finished",
            "exit_code": 0, "duration_s": 1.0,
            "lines": [{"stream": "stdout", "text": "hello"},
                      {"stream": "stderr", "text": "<script>"}]}


def _f():
    return [{"kind": "open_port", "severity": "high", "source": "nmap",
             "data": {"port": 22}, "raw_line": "22/tcp"}]


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


def test_render_html_escapes_script():
    # The per-job renderer must not emit raw <script> from stderr lines
    # unless it's inside the pre-wrapped markdown.
    h = render_html(_job(), _f())
    # raw stderr text isn't included by render_markdown, so this is a
    # sanity check that the renderer doesn't leak job.lines blindly.
    assert "<script>" not in h


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
