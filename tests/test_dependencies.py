from __future__ import annotations

import json
import re
import subprocess
import tomllib

import pytest

from whaxon.core.dependencies import collect_dependency_report, load_dependency_manifest


def _distribution_id(requirement: str) -> str:
    name = re.split(r"[<>=!~;]", requirement.strip(), maxsplit=1)[0]
    name = name.split("[", 1)[0].strip()
    return name.lower().replace("_", "-").replace(".", "-")


def test_dependency_report_is_read_only_and_versioned():
    report = collect_dependency_report(include_optional=False)
    assert report["schema_version"] == 1
    assert report["environment"]["python_executable"]
    assert report["dependencies"]
    assert report["safety"] == {
        "read_only": True,
        "installation_attempted": False,
        "network_accessed": False,
        "privilege_escalation_attempted": False,
    }


def test_dependency_report_json_serializable():
    report = collect_dependency_report(include_optional=True)
    encoded = json.dumps(report)
    assert '"dependencies"' in encoded


def test_packaged_catalog_is_used_when_user_data_is_not_initialized(tmp_path):
    report = collect_dependency_report(data_dir=tmp_path, include_optional=False)
    assert any(d["id"] == "nmap" for d in report["dependencies"])


def test_optional_dependencies_do_not_block_core(tmp_path):
    report = collect_dependency_report(data_dir=tmp_path, include_optional=True)
    if report["summary"]["required_blockers"] == 0:
        assert report["overall_status"] in {"READY", "DEGRADED"}


def test_manifest_has_unique_ids_and_profiles():
    from whaxon.core.dependencies import load_dependency_manifest

    manifest = load_dependency_manifest()
    ids = [entry["id"] for entry in manifest["dependencies"]]
    assert len(ids) == len(set(ids))
    assert "core" in manifest["profiles"]


def test_external_version_probe_is_opt_in_and_bounded(tmp_path, monkeypatch):
    import whaxon.core.dependencies as dependencies

    (tmp_path / "tools.json").write_text(json.dumps({
        "tools": [{"id": "nmap", "name": "Nmap", "binary": "nmap", "transport": "cli"}]
    }))
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(
            argv, 0, stdout="Nmap version 7.95 ( https://nmap.org )", stderr=""
        )

    executable = tmp_path / "nmap"
    executable.write_text("#!/bin/sh\\nexit 0\\n", encoding="utf-8")
    executable.chmod(0o755)
    monkeypatch.setattr(dependencies.shutil, "which", lambda _binary: str(executable))
    monkeypatch.setattr(dependencies.subprocess, "run", fake_run)

    detected = dependencies.collect_dependency_report(
        data_dir=tmp_path, include_optional=False, verify_external=False
    )
    assert next(d for d in detected["dependencies"] if d["id"] == "nmap")["status"] == "DETECTED"
    assert calls == []

    verified = dependencies.collect_dependency_report(
        data_dir=tmp_path, include_optional=False, verify_external=True
    )
    nmap = next(d for d in verified["dependencies"] if d["id"] == "nmap")
    assert nmap["status"] == "READY"
    assert nmap["detected_version"] == "7.95"
    assert calls[0][1]["shell"] is False
    assert calls[0][1]["timeout"] == 8


def test_external_version_probe_failure_is_not_ready(tmp_path, monkeypatch):
    import whaxon.core.dependencies as dependencies

    (tmp_path / "tools.json").write_text(json.dumps({
        "tools": [{"id": "nmap", "name": "Nmap", "binary": "nmap", "transport": "cli"}]
    }))
    executable = tmp_path / "nmap"
    executable.write_text("#!/bin/sh\\nexit 0\\n", encoding="utf-8")
    executable.chmod(0o755)
    monkeypatch.setattr(dependencies.shutil, "which", lambda _binary: str(executable))
    monkeypatch.setattr(
        dependencies.subprocess,
        "run",
        lambda argv, **kwargs: subprocess.CompletedProcess(argv, 1, stdout="", stderr="bad"),
    )
    report = dependencies.collect_dependency_report(
        data_dir=tmp_path, include_optional=False, verify_external=True
    )
    nmap = next(d for d in report["dependencies"] if d["id"] == "nmap")
    assert nmap["status"] == "BROKEN"


def test_unsupported_python_runtime_blocks_core(monkeypatch):
    import whaxon.core.dependencies as dependencies

    monkeypatch.setattr(dependencies.platform, "python_version", lambda: "3.10.14")
    report = dependencies.collect_dependency_report(
        include_optional=False,
        include_external=False,
    )
    runtime = next(item for item in report["dependencies"] if item["id"] == "python")
    assert runtime["status"] == "INCOMPATIBLE"
    assert report["overall_status"] == "BLOCKED"


def test_invalid_manifest_disables_external_version_probes(tmp_path, monkeypatch):
    import whaxon.core.dependencies as dependencies

    (tmp_path / "tools.json").write_text(json.dumps({
        "tools": [{"id": "nmap", "name": "Nmap", "binary": "nmap", "transport": "cli"}]
    }))
    monkeypatch.setattr(dependencies, "load_dependency_manifest", lambda: (_ for _ in ()).throw(ValueError("invalid")))
    executable = tmp_path / "nmap"
    executable.write_text("nmap executable", encoding="utf-8")
    executable.chmod(0o755)
    monkeypatch.setattr(dependencies.shutil, "which", lambda _binary: str(executable))
    monkeypatch.setattr(
        dependencies.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("probe must not run")),
    )
    report = dependencies.collect_dependency_report(
        data_dir=tmp_path, include_optional=False, verify_external=True
    )
    assert next(item for item in report["dependencies"] if item["id"] == "dependency-manifest")["status"] == "BROKEN"
    assert next(item for item in report["dependencies"] if item["id"] == "nmap")["status"] == "DETECTED"


def test_malformed_tool_catalog_is_reported_as_broken(tmp_path):
    (tmp_path / "tools.json").write_text("[]")
    report = collect_dependency_report(
        data_dir=tmp_path, include_optional=False, verify_external=False
    )
    catalog = next(item for item in report["dependencies"] if item["id"] == "tool-catalog")
    assert catalog["status"] == "BROKEN"


def test_manifest_covers_all_declared_runtime_dependencies():
    from pathlib import Path

    manifest = load_dependency_manifest()
    project = tomllib.loads(
        (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]
    declared = {
        _distribution_id(requirement)
        for requirement in project.get("dependencies", [])
    }
    for extra, requirements in project.get("optional-dependencies", {}).items():
        if extra == "dev":
            continue
        declared.update(
            _distribution_id(requirement)
            for requirement in requirements
        )
    manifest_ids = {
        item["id"].lower().replace("_", "-")
        for item in manifest["dependencies"]
        if item["kind"] == "python-package"
    }
    assert declared <= manifest_ids


def test_version_comparison_handles_prereleases_and_zero_padding():
    from whaxon.core.dependencies import _version_tuple

    assert _version_tuple("2.6.0") == _version_tuple("2.6")
    assert _version_tuple("2.6rc1") < _version_tuple("2.6")
    assert _version_tuple("2.6b2") < _version_tuple("2.6rc1")
    assert _version_tuple("2.6.dev1") < _version_tuple("2.6a1")
    assert _version_tuple("2.6.post1") > _version_tuple("2.6")
    assert _version_tuple("2.6+vendor.1") == _version_tuple("2.6")


def test_untrusted_catalog_cannot_redirect_curated_probe(tmp_path, monkeypatch):
    import whaxon.core.dependencies as dependencies

    (tmp_path / "tools.json").write_text(json.dumps({
        "tools": [{
            "id": "nmap",
            "name": "Nmap",
            "binary": "attacker-controlled-binary",
            "transport": "cli",
        }]
    }))
    calls = []
    executable = tmp_path / "attacker-controlled-binary"
    executable.write_text("#!/bin/sh\\nexit 0\\n", encoding="utf-8")
    executable.chmod(0o755)
    monkeypatch.setattr(dependencies.shutil, "which", lambda _binary: str(executable))

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="Nmap version 99.0", stderr="")

    monkeypatch.setattr(dependencies.subprocess, "run", fake_run)
    report = dependencies.collect_dependency_report(
        data_dir=tmp_path, include_optional=False, verify_external=True
    )
    item = next(d for d in report["dependencies"] if d["id"] == "nmap")
    assert item["status"] == "DETECTED"
    assert "no trusted version probe" in item["reason"].lower()
    assert calls == []

def test_version_comparison_honours_epochs():
    from whaxon.core.dependencies import _version_tuple
    assert _version_tuple("2!1.0") > _version_tuple("1!99.0")

def test_version_comparison_keeps_release_segments_separate_from_stage():
    from whaxon.core.dependencies import _version_tuple
    assert _version_tuple("1.0.1") > _version_tuple("1.0.dev1")
    assert _version_tuple("1.0.1") > _version_tuple("1.0")

def test_external_binary_reports_path_ambiguity_and_filesystem_identity(tmp_path, monkeypatch):
    import os

    import whaxon.core.dependencies as dependencies

    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    binary_a = first / "nmap"
    binary_b = second / "nmap"
    binary_a.write_text("first executable", encoding="utf-8")
    binary_b.write_text("second executable", encoding="utf-8")
    binary_a.chmod(0o755)
    binary_b.chmod(0o755)
    monkeypatch.setenv("PATH", os.pathsep.join((str(first), str(second))))
    monkeypatch.setattr(dependencies.shutil, "which", lambda _binary: str(binary_a))
    (tmp_path / "tools.json").write_text(json.dumps({
        "tools": [{"id": "nmap", "name": "Nmap", "binary": "nmap", "transport": "cli"}]
    }), encoding="utf-8")

    report = dependencies.collect_dependency_report(
        data_dir=tmp_path, include_optional=False, verify_external=False
    )
    nmap = next(item for item in report["dependencies"] if item["id"] == "nmap")
    assert nmap["status"] == "DETECTED"
    assert nmap["path_conflict"] is True
    assert len(nmap["path_candidates"]) == 2
    assert nmap["executable_identity"]["identity_kind"] == "local-filesystem-metadata"
    assert len(nmap["executable_identity"]["fingerprint"]) == 64
    assert "PATH ambiguity" in nmap["reason"]


def test_external_binary_with_unreadable_identity_is_not_version_probed(tmp_path, monkeypatch):
    import whaxon.core.dependencies as dependencies

    (tmp_path / "tools.json").write_text(json.dumps({
        "tools": [{"id": "nmap", "name": "Nmap", "binary": "nmap", "transport": "cli"}]
    }), encoding="utf-8")
    monkeypatch.setattr(dependencies.shutil, "which", lambda _binary: "/missing/nmap")
    monkeypatch.setattr(
        dependencies.subprocess, "run",
        lambda *_args, **_kwargs: pytest.fail("must not probe an uninspectable executable"),
    )
    report = dependencies.collect_dependency_report(
        data_dir=tmp_path, include_optional=False, verify_external=True
    )
    nmap = next(item for item in report["dependencies"] if item["id"] == "nmap")
    assert nmap["status"] == "BROKEN"
    assert nmap["executable_identity"] is None
    assert "identity could not be inspected" in nmap["reason"]


def test_version_probe_does_not_clear_path_ambiguity(tmp_path, monkeypatch):
    import os

    import whaxon.core.dependencies as dependencies

    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    selected = first / "nmap"
    other = second / "nmap"
    selected.write_text("selected executable", encoding="utf-8")
    other.write_text("shadow executable", encoding="utf-8")
    selected.chmod(0o755)
    other.chmod(0o755)
    (tmp_path / "tools.json").write_text(json.dumps({
        "tools": [{"id": "nmap", "name": "Nmap", "binary": "nmap", "transport": "cli"}]
    }), encoding="utf-8")
    monkeypatch.setenv("PATH", os.pathsep.join((str(first), str(second))))
    monkeypatch.setattr(dependencies.shutil, "which", lambda _binary: str(selected))
    monkeypatch.setattr(
        dependencies.subprocess, "run",
        lambda argv, **kwargs: subprocess.CompletedProcess(
            argv, 0, stdout="Nmap version 7.95", stderr=""
        ),
    )
    report = dependencies.collect_dependency_report(
        data_dir=tmp_path, include_optional=False, verify_external=True
    )
    nmap = next(item for item in report["dependencies"] if item["id"] == "nmap")
    assert nmap["status"] == "BROKEN"
    assert nmap["path_conflict"] is True
    assert "PATH ambiguity" in nmap["reason"]



def test_gobuster_version_probe_uses_global_version_flag():
    import re

    gobuster = next(
        item for item in load_dependency_manifest()["external_tools"]
        if item["id"] == "gobuster"
    )
    assert gobuster["version_args"] == ["--version"]
    assert re.search(gobuster["version_regex"], "Gobuster v3.8.2")
    assert re.search(gobuster["version_regex"], "3.8.2")
    assert re.search(gobuster["version_regex"], "gobuster version 3.8.2")



def test_nuclei_version_probe_accepts_prefixed_version():
    import re

    nuclei = next(
        item for item in load_dependency_manifest()["external_tools"]
        if item["id"] == "nuclei"
    )
    assert re.search(nuclei["version_regex"], "Nuclei Engine Version: v3.4.10")
    assert re.search(nuclei["version_regex"], "Nuclei Engine Version: 3.4.10")
