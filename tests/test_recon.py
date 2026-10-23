"""Recon pipeline tests. Focus on the seam — that recon findings actually
reach the correlator and produce correlated findings."""
from __future__ import annotations

from whaxon.core.findings import Finding
from whaxon.core.recon import ReconRunner


def _make_core(tmp_path, monkeypatch):
    """Reuse the project's app factory to get a wired Core, event bus, store."""
    from tests.test_server import _make_app  # same fixture shape used elsewhere
    _app, core = _make_app(tmp_path, monkeypatch)
    return core


def test_recon_out_of_scope_emits_one_finding_and_touches_nothing(tmp_path, monkeypatch):
    core = _make_core(tmp_path, monkeypatch)
    runner = ReconRunner(core.scope, core.bus, core.runner._resolve_findings)

    called = []
    runner.register("dns", lambda t: (called.append(t), [])[1])

    result = runner.run("203.0.113.5")   # TEST-NET-3, not in default scope
    assert result is None
    assert called == []  # check never ran


def test_recon_in_scope_emits_findings_through_pipeline(tmp_path, monkeypatch):
    core = _make_core(tmp_path, monkeypatch)
    runner = ReconRunner(core.scope, core.bus, core.runner._resolve_findings)

    def fake_tech(t):
        return [
            Finding(kind="tech_detected", severity="info", source="recon:tech",
                    data={"product": "apache", "version": "2.4.25"},
                    raw_line=f"Apache/2.4.25 via {t}",
                    lookup_hint="apache 2.4.25"),
            Finding(kind="open_port", severity="info", source="recon:tech",
                    data={"port": 443, "service": "apache", "version": "2.4.25"},
                    raw_line=f"443/tcp open  https   Apache/2.4.25 via {t}"),
        ]
    runner.register("tech", fake_tech)

    job_id = runner.run("127.0.0.1")   # loopback, in default scope
    assert job_id == "recon:127.0.0.1"

    raws = core.store.get_findings(job_id)
    assert any(f["kind"] == "tech_detected" for f in raws)

    correlated = [f for f in raws if f["kind"] == "correlated"]
    assert correlated, f"expected correlator to fire, got {raws}"


def test_recon_check_exception_becomes_error_finding(tmp_path, monkeypatch):
    core = _make_core(tmp_path, monkeypatch)
    runner = ReconRunner(core.scope, core.bus, core.runner._resolve_findings)

    def boom(t):
        raise RuntimeError("simulated failure")
    runner.register("dns", boom)

    job_id = runner.run("127.0.0.1")
    raws = core.store.get_findings(job_id)
    assert any(f["kind"] == "recon_error" for f in raws)
