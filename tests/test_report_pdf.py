"""PDF export test. Skips when pandoc or weasyprint not installed."""
from __future__ import annotations

import shutil
import pytest

from whaxon.core.report import to_pdf_bytes, render_markdown


pytestmark = pytest.mark.skipif(
    not (shutil.which("pandoc") and shutil.which("weasyprint")),
    reason="pandoc and weasyprint must be on PATH",
)


def test_pdf_starts_with_pdf_magic():
    job = {"id": "j", "tool": "nmap", "target": "10.0.0.5",
           "status": "finished", "exit_code": 0, "duration_s": 0.1,
           "lines": []}
    findings = [{"kind": "open_port", "severity": "high",
                 "source": "nmap", "data": {"port": 443},
                 "raw_line": "443/tcp open https"}]
    md = render_markdown(job, findings)
    data = to_pdf_bytes(md)
    assert data.startswith(b"%PDF-")
    assert len(data) > 1000
