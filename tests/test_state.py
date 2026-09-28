"""Tests for the whaxon state diagnostic dump."""
from __future__ import annotations

from whaxon.tools import state


def test_build_returns_string():
    text = state.build(run_pytest=False)
    assert isinstance(text, str)
    assert len(text) > 1000


def test_build_has_expected_sections():
    text = state.build(run_pytest=False)
    for section in (
        "## 1. Snapshot metadata",
        "## 2. Git",
        "## 3. Tests",
        "## 4. Environment",
        "## 7. CLI surface",
        "## 11. Drift verdicts",
    ):
        assert section in text, f"missing {section}"


def test_build_includes_whaxon_version():
    text = state.build(run_pytest=False)
    assert "whaxon" in text
    assert "0.2.0" in text


def test_build_output_is_well_formed_markdown():
    text = state.build(run_pytest=False)
    assert text.startswith("# WHAXON state snapshot")
    assert text.rstrip().endswith("## End of snapshot")
    assert "### working tree (git status --short)" in text
