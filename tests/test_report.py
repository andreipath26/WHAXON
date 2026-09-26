from whaxon.core.report import render_markdown, render_html

def _job():
    return {"id": "x", "tool": "nmap", "target": "t", "status": "finished",
            "exit_code": 0, "duration_s": 1.0,
            "lines": [{"stream": "stdout", "text": "hello"},
                      {"stream": "stderr", "text": "<script>"}]}

def _f():
    return [{"kind": "open_port", "severity": "high", "source": "nmap",
             "data": {"port": 22}, "raw_line": "22/tcp"}]

def test_md():
    md = render_markdown(_job(), _f())
    assert "# WHAXON Report" in md
    assert "| high | 1 |" in md

def test_html_renders():
    h = render_html(_job(), _f())
    assert "<h1>" in h
    assert "<table>" in h

def test_html_escapes():
    h = render_html(_job(), _f())
    assert "<script>" not in h
