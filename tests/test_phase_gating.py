"""Phase-gated catalog — v2 of docs/agent-architecture.md §5."""
from __future__ import annotations

from whaxon.ai.phases import (
    CATEGORY_BY_PHASE,
    categories_for,
    filter_catalog,
)

_TOOLS = [
    {"id": "nmap", "category": "recon"},
    {"id": "nikto", "category": "web"},
    {"id": "nuclei", "category": "vuln"},
    {"id": "msf_sysinfo", "category": "session"},
]


def test_category_map_covers_all_phases() -> None:
    from whaxon.ai.phases import PHASES
    for phase in PHASES:
        assert phase in CATEGORY_BY_PHASE


def test_recon_phase_only_recon_tools() -> None:
    ids = [t["id"] for t in filter_catalog(_TOOLS, "recon")]
    assert ids == ["nmap"]


def test_enumeration_phase_web_only() -> None:
    ids = [t["id"] for t in filter_catalog(_TOOLS, "enumeration")]
    assert ids == ["nikto"]


def test_vulnerability_phase_vuln_and_web() -> None:
    ids = [t["id"] for t in filter_catalog(_TOOLS, "vulnerability")]
    assert set(ids) == {"nikto", "nuclei"}


def test_post_access_phase_session_only() -> None:
    ids = [t["id"] for t in filter_catalog(_TOOLS, "post-access")]
    assert ids == ["msf_sysinfo"]


def test_done_phase_empty() -> None:
    assert filter_catalog(_TOOLS, "done") == []


def test_unknown_phase_returns_empty() -> None:
    assert filter_catalog(_TOOLS, "bogus") == []


def test_categories_for_unknown_phase_is_empty() -> None:
    assert categories_for("bogus") == ()


def test_gating_off_by_default(tmp_path, monkeypatch) -> None:
    """When WHAXON_AI_PHASE_GATING is unset, catalog_all returns everything."""
    from whaxon.core import Core
    from whaxon.core.ai_bridge import build_executor

    monkeypatch.delenv("WHAXON_AI_PHASE_GATING", raising=False)
    data = tmp_path / "data"
    data.mkdir()
    (data / "tools.json").write_text(
        '{"tools":[{"id":"nmap","name":"Nmap","category":"recon",'
        '"binary":"/bin/echo","args":"{target}"},'
        '{"id":"msf_sysinfo","name":"MSF sysinfo","category":"session",'
        '"transport":"msf_session","command":"sysinfo","binary":""}]}'
    )
    core = Core(data_dir=data)
    ex = build_executor(core)
    ids = {t["id"] for t in ex.catalog_all()}
    assert "nmap" in ids
    assert "msf_sysinfo" in ids


def test_gating_on_filters_by_phase(tmp_path, monkeypatch) -> None:
    from whaxon.core import Core
    from whaxon.core.ai_bridge import build_executor

    monkeypatch.setenv("WHAXON_AI_PHASE_GATING", "true")
    data = tmp_path / "data"
    data.mkdir()
    (data / "tools.json").write_text(
        '{"tools":[{"id":"nmap","name":"Nmap","category":"recon",'
        '"binary":"/bin/echo","args":"{target}"},'
        '{"id":"msf_sysinfo","name":"MSF sysinfo","category":"session",'
        '"transport":"msf_session","command":"sysinfo","binary":""}]}'
    )
    core = Core(data_dir=data)

    # Default phase is recon: only nmap visible.
    ex = build_executor(core)
    ids = {t["id"] for t in ex.catalog_all()}
    assert ids == {"nmap"}

    # Force phase to post-access: only the session tool.
    core.store.create_ai_run("ai-gate", "goal", phase="post-access")
    ex = build_executor(core, ai_run_id="ai-gate")
    ids = {t["id"] for t in ex.catalog_all()}
    assert ids == {"msf_sysinfo"}