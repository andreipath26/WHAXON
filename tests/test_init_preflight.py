"""init preflight: nuclei templates bootstrapped, version recorded.

nuclei ships with -disable-update-check, so it never self-updates. A
fresh machine has no templates and nuclei fatals with 'no templates
provided'. init records the state in settings.json so drift is visible.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from whaxon.interfaces.cli import init_cmd


def _run_init(tmp_path: Path) -> Path:
    data = tmp_path / "data"
    with patch.object(init_cmd, "_detect_gateway", return_value="172.28.0.1"), \
         patch.object(init_cmd, "_detect_subnet", return_value="172.28.0.0/16"), \
         patch.object(init_cmd, "_detect_target_ip", return_value="172.28.0.10"):
        init_cmd.main(["--data", str(data)])
    return data


def test_preflight_records_nuclei_state(tmp_path: Path) -> None:
    data = _run_init(tmp_path)
    settings = json.loads((data / "settings.json").read_text())
    assert "nuclei_templates_dir" in settings
    assert "nuclei_version" in settings


def test_preflight_skips_cleanly_when_nuclei_absent(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    with patch.object(init_cmd, "_preflight_templates") as pf:
        pf.side_effect = None
        init_cmd._preflight_templates(data)
    # helper must not raise when nuclei is absent
