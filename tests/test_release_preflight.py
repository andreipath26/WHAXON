"""Tests for release tag preflight checks."""
from __future__ import annotations

import io
import json
import subprocess
from unittest.mock import Mock

import pytest

from scripts import verify_release_commit


def test_verify_main_ancestry_checks_exact_tag_commit(monkeypatch):
    run = Mock()
    monkeypatch.setattr(verify_release_commit.subprocess, "run", run)
    verify_release_commit.verify_main_ancestry("abc123")
    run.assert_called_once_with(
        ["git", "merge-base", "--is-ancestor", "abc123", "FETCH_HEAD"],
        check=True,
    )


def test_verify_main_ancestry_rejects_commit_outside_main(monkeypatch):
    run = Mock(side_effect=subprocess.CalledProcessError(1, ["git", "merge-base"]))
    monkeypatch.setattr(verify_release_commit.subprocess, "run", run)
    with pytest.raises(subprocess.CalledProcessError):
        verify_release_commit.verify_main_ancestry("abc123")


class _Response:
    def __init__(self, payload):
        self.payload = io.BytesIO(json.dumps(payload).encode())

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.payload.close()

    def read(self, *args):
        return self.payload.read(*args)


def test_green_ci_requires_success_for_same_commit_and_workflow():
    opener = Mock(return_value=_Response({"workflow_runs": [
        {"name": "CI", "head_sha": "abc123", "status": "completed", "conclusion": "success"},
        {"name": "CI", "head_sha": "other", "status": "completed", "conclusion": "success"},
        {"name": "README freeze", "head_sha": "abc123", "status": "completed", "conclusion": "success"},
    ]}))
    assert verify_release_commit.has_green_ci_for_exact_commit(
        "owner/repo", "abc123", "token", opener=opener
    )
    request, = opener.call_args.args
    assert request.full_url.endswith("?head_sha=abc123&per_page=100")
    assert request.get_header("Authorization") == "Bearer token"


@pytest.mark.parametrize("run", [
    {"name": "CI", "head_sha": "abc123", "status": "in_progress", "conclusion": None},
    {"name": "CI", "head_sha": "other", "status": "completed", "conclusion": "success"},
    {"name": "CI", "head_sha": "abc123", "status": "completed", "conclusion": "failure"},
])
def test_green_ci_rejects_nonmatching_or_incomplete_run(run):
    opener = Mock(return_value=_Response({"workflow_runs": [run]}))
    assert not verify_release_commit.has_green_ci_for_exact_commit(
        "owner/repo", "abc123", "token", opener=opener
    )
