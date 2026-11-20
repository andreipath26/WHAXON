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

from whaxon.core.report import _load, render_html, render_markdown, to_html, to_json, to_markdown


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
    assert "## Executive Brief" in md
    assert "## Appendix: Job History" in md
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
    assert "## Attack Surface" in md
    assert "msf_session" in md
    assert "10.0.0.5" in md


def test_to_markdown_without_chains_omits_section():
    md = to_markdown(_report_dict())
    assert "## Attack Surface" not in md


def test_engagement_html_escapes_untrusted_finding_values():
    report = _report_dict()
    report["engagement"] = "<script>alert(1)</script>"
    report["unique_findings"] = [{
        "kind": '<img src=x onerror=alert(1)>',
        "severity": "high",
        "target": '<svg onload=alert(2)>',
        "status": "candidate",
        "verification_status": "candidate",
        "verified_by": '<script>alert(3)</script>',
        "verification_reason": '<img src=x onerror=alert(4)>',
        "cost_range": {
            "incident_pattern": '<script>alert(5)</script>',
            "median": 10,
            "p90": 20,
            "source": '<img src=x onerror=alert(6)>',
        },
        "job_ids": ['<svg onload=alert(7)>'],
    }]

    for static in (False, True):
        html = to_html(report, static=static)
        assert "<script>alert(1)</script>" not in html
        assert "<img src=x onerror=alert(1)>" not in html
        assert "<svg onload=alert(2)>" not in html
        assert "<script>alert(3)</script>" not in html
        assert "<img src=x onerror=alert(4)>" not in html
        assert "<script>alert(5)</script>" not in html
        assert "<img src=x onerror=alert(6)>" not in html
        assert "<svg onload=alert(7)>" not in html


def test_engagement_html_discloses_recorded_evidence_scope_and_count_limits():
    report = _report_dict()

    for static in (False, True):
        html = to_html(report, static=static)
        assert "Evidence snapshot." in html
        assert "summarizes findings and jobs recorded by WHAXON" in html
        assert "does not establish that a target is free of vulnerabilities" in html
        assert "Recorded evidence" in html
        assert "Deterministic Correlation" not in html
        assert "unique finding" in html
        assert "findings identified across" not in html

    static_html = to_html(report, static=True)
    assert ">1 unique finding from 1 recorded job</p>" in static_html


def test_engagement_html_discloses_persisted_coverage_safely():
    report = _report_dict()
    report["jobs"][0]["coverage"] = [{
        "phase": "reconnaissance",
        "kind": "scope_blocked",
        "tool_id": "nikto",
        "target": "10.0.0.5",
        "detail": "<script>alert(9)</script> out of scope",
    }]

    for static in (False, True):
        html = to_html(report, static=static)
        assert "Coverage and untested work" in html
        assert "reconnaissance" in html
        assert "scope_blocked" in html
        assert "nikto" in html
        assert "&lt;script&gt;alert(9)&lt;/script&gt;" in html
        assert "<script>alert(9)</script>" not in html

    empty_html = to_html(_report_dict(), static=True)
    assert "No coverage gaps were recorded for this report." in empty_html
    assert "does not prove that every relevant check was performed" in empty_html

def test_html_report_is_fully_server_rendered_for_pdf_and_browser():
    report = _report_dict()
    report["unique_findings"] = [{
        "kind": "sqli",
        "severity": "high",
        "source": "validator",
        "target": "127.0.0.1",
        "raw_line": "parameter id accepts SQL syntax",
        "remediation": "Use parameterized queries.",
        "verification_status": "verified",
        "verified_by": "validator",
        "verification_reason": "Loopback fixture confirmed the behavior.",
        "job_ids": ["job-1"],
        "count": 2,
        "cvss": 8.1,
    }]
    report["raw_finding_count"] = 2
    report["jobs"] = [{
        "job": {
            "id": "job-1",
            "tool": "fixture",
            "target": "127.0.0.1",
            "status": "finished",
            "exit_code": 0,
            "started_at": "2026-11-06T12:00:00",
        },
        "findings": [],
        "coverage": [{
            "phase": "reconnaissance",
            "kind": "scope_blocked",
            "tool_id": "fixture",
            "target": "127.0.0.1",
            "detail": "authorization check blocked a request",
        }],
    }]

    html = to_html(report, overrides={
        "client": "Example Client",
        "prepared_by": "Security Team",
    }, static=True)

    assert "Generating narrative..." not in html
    assert "Executive overview" in html
    assert "Remediation roadmap" in html
    assert "Technical findings" in html
    assert "Job history and provenance" in html
    assert "WHAXON recorded 1 unique finding(s)" in html
    assert "Recorded observations" in html
    assert "Use parameterized queries." in html
    assert "Loopback fixture confirmed the behavior." in html
    assert "Example Client" in html
    assert "Security Team" in html
    assert "scope_blocked" in html
    assert "job-1" in html
    assert "{{" not in html
    assert "0 findings total" not in html


def test_html_report_escapes_untrusted_values_in_every_section():
    report = _report_dict()
    report["engagement"] = "</title><script>alert(1)</script>"
    report["client"] = '<img src=x onerror="alert(2)">'
    report["jobs"] = [{
        "job": {
            "id": "<svg onload=alert(3)>",
            "tool": "tool<script>",
            "target": "host<img src=x>",
            "status": "finished",
            "exit_code": 0,
            "started_at": "now",
        },
        "findings": [],
        "coverage": [{
            "phase": "<script>alert(4)</script>",
            "kind": "scope_blocked",
            "tool_id": "tool",
            "target": "host",
            "detail": "<img src=x onerror=alert(5)>",
        }],
    }]
    report["unique_findings"] = [{
        "kind": "<script>alert(6)</script>",
        "severity": "high",
        "source": "adapter",
        "target": "<svg onload=alert(7)>",
        "raw_line": "<img src=x onerror=alert(8)>",
        "remediation": "<script>alert(9)</script>",
        "proof": "</script><script>alert(10)</script>",
        "verification_status": "candidate",
        "verification_reason": "<svg onload=alert(11)>",
        "cost_range": {
            "incident_pattern": "<img src=x onerror=alert(13)>",
            "median": 1200,
            "source": "<script>alert(14)</script>",
        },
        "job_ids": ['<img src=x onerror=alert(12)>'],
    }]

    html = to_html(report, static=True)

    for payload in (
        "</title><script>alert(1)</script>",
        '<img src=x onerror="alert(2)">',
        "<svg onload=alert(3)>",
        "<script>alert(4)</script>",
        "<img src=x onerror=alert(5)>",
        "<script>alert(6)</script>",
        "<svg onload=alert(7)>",
        "<img src=x onerror=alert(8)>",
        "<script>alert(9)</script>",
        "</script><script>alert(10)</script>",
        "<svg onload=alert(11)>",
        "<img src=x onerror=alert(12)>",
        "<img src=x onerror=alert(13)>",
        "<script>alert(14)</script>",
    ):
        assert payload not in html
    assert "&lt;script&gt;" in html
    assert "&lt;img" in html
    assert "&lt;svg" in html
    assert "u003c/script" in html


def test_html_report_empty_and_coverage_states_are_explicit():
    report = _report_dict()
    report["finding_count"] = 0
    report["raw_finding_count"] = 0
    report["severity_counts"] = {
        severity: 0 for severity in ("critical", "high", "medium", "low", "info")
    }
    report["unique_findings"] = []
    report["jobs"] = []

    html = to_html(report, static=True)

    assert "No findings are available in this snapshot" in html
    assert "No coverage gaps were recorded for this report." in html
    assert "This does not prove that every relevant check was performed." in html
    assert "No job history was recorded." in html

def test_html_report_does_not_expand_template_tokens_from_untrusted_data():
    report = _report_dict()
    report["unique_findings"] = [{
        "kind": "literal {{COVERAGE}} in title",
        "severity": "low",
        "source": "fixture",
        "target": "127.0.0.1",
        "raw_line": "literal {{ACTIVITY}} in evidence",
        "remediation": "Preserve {{COVERAGE}} exactly as recorded.",
        "verification_status": "candidate",
    }]

    html = to_html(report, static=True)

    assert "literal {{COVERAGE}} in title" in html
    assert "literal {{ACTIVITY}} in evidence" in html
    assert "Preserve {{COVERAGE}} exactly as recorded." in html
    assert "{{FINDINGS}}" not in html


def test_html_report_renders_executive_brief_and_remediation_roadmap():
    report = _report_dict()
    report["unique_findings"] = [
        {
            "kind": "known exploited issue",
            "severity": "critical",
            "target": "api.example.test",
            "remediation": "Disable the affected endpoint and patch the service.",
            "verification_status": "verified",
            "kev": True,
        },
        {
            "kind": "sqli",
            "severity": "high",
            "target": "app.example.test",
            "remediation": "Validate the input handling and use parameterized queries.",
            "verification_status": "candidate",
            "cvss": 8.1,
        },
        {
            "kind": "shared configuration weakness",
            "severity": "medium",
            "target": "admin.example.test",
            "remediation": "Apply the hardened configuration.",
            "verification_status": "inconclusive",
            "cvss": 4.5,
            "count": 2,
        },
        {
            "kind": "informational observation",
            "severity": "info",
            "target": "docs.example.test",
            "remediation": "Review during routine maintenance.",
            "verification_status": "refuted",
        },
    ]

    html = to_html(report, static=True)

    assert html.index("Executive overview") < html.index("Executive brief")
    assert html.index("Executive brief") < html.index("Remediation roadmap")
    assert html.index("Remediation roadmap") < html.index("Technical findings")
    assert "Top three recorded priorities" in html
    assert html.count("deterministic urgency rules") == 1
    assert "1 of 4 recorded findings are marked verified" in html
    assert "known exploited issue" in html
    assert "Disable the affected endpoint and patch the service." in html
    assert "Immediate" in html
    assert "Short-term" in html
    assert "Medium-term" in html
    assert "Reference incident-cost data" in html
    assert "USD 266,000" in html
    assert "not a client-specific loss estimate" in html
    assert "Cyentia IRIS 2022 (geometric mean)" in html
    assert "Refuted records retained for context" in html
    assert "excluded from remediation priorities" in html


def test_markdown_engagement_report_has_evidence_qualified_priorities_and_cost_context():
    report = _report_dict()
    report["unique_findings"] = [
        {
            "kind": "known exploited issue",
            "severity": "critical",
            "target": "api.example.test",
            "raw_line": "exploitable observation",
            "remediation": "Disable the endpoint and patch the service.",
            "verification_status": "verified",
            "kev": True,
            "count": 2,
            "cost_range": {
                "incident_pattern": "Published breach data",
                "median": 1200,
                "source": "Public study",
            },
            "proof": "safe-fixture-command",
        },
        {
            "kind": "candidate issue",
            "severity": "high",
            "target": "app.example.test",
            "verification_status": "candidate",
            "remediation": "Review the input handling.",
        },
        {
            "kind": "refuted record",
            "severity": "info",
            "target": "docs.example.test",
            "verification_status": "refuted",
            "remediation": "Should not appear as an action.",
        },
    ]
    report["severity_counts"] = {"critical": 2, "high": 1, "medium": 0, "low": 0, "info": 0}

    markdown = to_markdown(report, lookup=False)

    assert "## Executive Brief" in markdown
    assert "1** are marked verified" in markdown
    assert "Highest recorded priorities" in markdown
    assert "## Remediation Roadmap" in markdown
    assert "Not a client-specific loss estimate" in markdown
    assert "Public study" in markdown
    assert "Verified reproduction material" in markdown
    roadmap = markdown.split("## Remediation Roadmap", 1)[1].split("## Appendix", 1)[0]
    assert "Should not appear as an action." not in roadmap
    assert "Refuted records remain in the technical appendix." in roadmap
    assert "### Info" in markdown
    assert "refuted record" in markdown
    assert "**[info]** refuted record" in markdown


def test_markdown_report_escapes_untrusted_priority_fields():
    report = _report_dict()
    report["unique_findings"] = [{
        "kind": "<script>alert(1)</script> | issue",
        "severity": "high",
        "target": "<img src=x> | host",
        "verification_status": "candidate",
        "remediation": "Use <safe> handling | always.",
    }]

    markdown = to_markdown(report, lookup=False)

    assert "<script>" not in markdown
    assert "<img" not in markdown
    assert "\\| issue" in markdown
    assert "\\| host" in markdown
    assert "Use &lt;safe&gt; handling \\| always." in markdown


def test_per_job_markdown_report_is_structured_and_preserves_evidence_state():
    job = _job()
    job["coverage"] = [{
        "phase": "reconnaissance",
        "kind": "scope_blocked",
        "tool_id": "nmap",
        "target": "10.0.0.8",
        "detail": "outside authorized scope",
    }]
    findings = [{
        "kind": "open_port",
        "severity": "high",
        "source": "nmap",
        "raw_line": "22/tcp open ssh",
        "remediation": "Restrict access to the SSH service.",
        "verification_status": "candidate",
        "verification_reason": "Requires owner confirmation.",
        "proof": "nmap -sV 10.0.0.8",
    }]

    markdown = render_markdown(job, findings)

    assert "## Executive Brief" in markdown
    assert "1 finding(s) were recorded" in markdown
    assert "### F001 **[HIGH]** `open_port`" in markdown
    assert "**Verification:** candidate" in markdown
    assert "Evidence recorded" in markdown
    assert "22/tcp open ssh" in markdown
    assert "Recommended remediation" in markdown
    assert "Recorded reproduction material" in markdown
    assert "Coverage and untested work" in markdown


def test_per_job_markdown_report_escapes_untrusted_client_values():
    markdown = render_markdown(
        {**_job(), "target": "<script>alert(1)</script> | host"},
        [{
            "kind": "issue",
            "severity": "high",
            "raw_line": "<img src=x onerror=alert(2)>",
            "remediation": "Use <safe> handling | always.",
            "verification_status": "candidate",
        }],
    )

    assert "<script>" not in markdown
    assert "<img" not in markdown
    assert "Use &lt;safe&gt; handling \\| always." in markdown


def test_markdown_priority_order_keeps_business_impact_and_evidence():
    report = _report_dict()
    report["unique_findings"] = [
        {
            "kind": "open_port",
            "severity": "critical",
            "business_impact": "low",
            "raw_line": "critical but low impact",
            "verification_status": "candidate",
        },
        {
            "kind": "sqli",
            "severity": "medium",
            "business_impact": "critical",
            "raw_line": "medium but high impact",
            "verification_status": "candidate",
        },
    ]

    markdown = to_markdown(report, lookup=False)

    assert markdown.index("medium but high impact") < markdown.index("critical but low impact")
    assert "/ Business: critical" in markdown
    assert "**[critical]** open_port" in markdown
    html = to_html(report, static=True)
    assert html.index("sqli") < html.index("open_port")



def test_engagement_markdown_escapes_untrusted_table_values():
    report = _report_dict()
    report["engagement"] = "<script>engagement</script>"
    report["jobs"][0]["job"].update({
        "id": "job|id\nnext",
        "tool": "tool|<script>",
        "target": "host|target",
        "status": "finished|<img>",
    })
    report["jobs"][0]["coverage"] = [{
        "phase": "phase|<script>",
        "kind": "scope|blocked",
        "tool_id": "scanner|<img>",
        "target": "host|target",
        "detail": "detail|<script>",
    }]
    report["session_findings"] = [{
        "kind": "sysinfo",
        "source": "session|<script>",
        "data": {
            "field": "OS|<img>",
            "value": "Linux\\n|verified",
            "session_id": "sid|<svg>",
        },
        "_job_id": "job|id",
    }]
    report["ai_runs"] = [{
        "id": "run|id",
        "goal": "goal|<script>",
        "phase": "phase|<script>",
        "status": "status|<img>",
        "step_count": 1,
        "phase_history": '[{"phase":"recon"},{"phase":"phase|<svg>"}]',
    }]
    report["loot"] = [{
        "kind": "env_var",
        "data": {"name": "TOKEN|<script>", "value": "secret|<img>"},
        "_job_id": "job|id",
    }]

    markdown = to_markdown(report, lookup=False)

    assert "<script>" not in markdown
    assert "<img>" not in markdown
    assert "<svg>" not in markdown
    assert "`job\\|id next`" in markdown
    assert "tool\\|&lt;script&gt;" in markdown
    assert "secret\\|&lt;img&gt;" in markdown
    chain_markdown = to_markdown(
        report,
        chains=[{
            "root": {"kind": "<script>root</script>", "id": "root|id", "evidence": "<img>"},
            "descendants": [{
                "relation": "from_exploit",
                "child": {"kind": "<svg>", "id": "child|id"},
                "evidence": "<script>child</script>",
            }],
        }],
        lookup=False,
    )
    assert "<script>root</script>" not in chain_markdown
    assert "<script>child</script>" not in chain_markdown
    assert "&lt;script&gt;root&lt;/script&gt;" in chain_markdown



def test_markdown_proof_blocks_cannot_be_closed_by_recorded_text():
    proof = "first line\n~~~\n<script>alert(1)</script>"
    job_report = render_markdown(_job(), [{
        "kind": "command_output",
        "severity": "high",
        "raw_line": "recorded",
        "proof": proof,
    }])
    assert "~~~~text\nfirst line\n~~~\n<script>alert(1)</script>\n~~~~" in job_report

    report = _report_dict()
    report["unique_findings"] = [{
        "kind": "command_output",
        "severity": "high",
        "verification_status": "candidate",
        "proof": proof,
    }]
    engagement_report = to_markdown(report, lookup=False)
    assert "    ~~~~text\n    first line\n    ~~~\n    <script>alert(1)</script>\n    ~~~~" in engagement_report


def test_engagement_load_deduplicates_findings_per_normalized_target():
    class Store:
        jobs = [
            {"id": "one", "tool": "nmap", "target": "EXAMPLE.test:443"},
            {"id": "two", "tool": "nmap", "target": "example.test"},
            {"id": "three", "tool": "nmap", "target": "other.test"},
        ]

        def history(self, limit=500):
            return self.jobs

        def get_findings(self, job_id):
            return [{
                "kind": "open_port",
                "severity": "high",
                "source": "nmap",
                "data": {"port": 22, "protocol": "tcp"},
                "raw_line": "22/tcp open ssh",
            }]

    report = _load(Store(), "engagement")

    assert report["raw_finding_count"] == 3
    assert report["finding_count"] == 2
    assert report["severity_counts"]["high"] == 2
    findings = {finding["target"]: finding for finding in report["unique_findings"]}
    assert findings["example.test"]["count"] == 2
    assert findings["example.test"]["job_ids"] == ["one", "two"]
    assert findings["other.test"]["count"] == 1


def test_engagement_report_target_counts_use_canonical_host_identity():
    report = _report_dict()
    report["job_count"] = 2
    report["jobs"] = [
        {"job": {"id": "one", "target": "EXAMPLE.test:443"}, "findings": []},
        {"job": {"id": "two", "target": "https://example.test/path"}, "findings": []},
    ]

    markdown = to_markdown(report, lookup=False)
    html = to_html(report, static=True)

    assert "**2 recorded job(s)** and **1 target(s)**" in markdown
    assert "2 recorded job(s) and 1 distinct target(s)" in html


def test_html_summary_counts_unknown_verification_as_candidate():
    report = _report_dict()
    report["unique_findings"] = [{
        "kind": "open_port",
        "severity": "high",
        "verification_status": "unexpected-state",
        "target": "127.0.0.1",
    }]

    html = to_html(report, static=True)

    assert "0 are marked verified, 1 remain candidate or inconclusive, and 0 are marked refuted." in html
    assert "tag-verification candidate" in html
