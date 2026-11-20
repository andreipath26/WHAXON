"""Tests for verifying published PyPI distributions."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts.verify_pypi_release import verify_pypi_release


class _Response:
    def __init__(self, payload):
        self.stream = io.BytesIO(json.dumps(payload).encode())

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stream.close()

    def read(self, *args):
        return self.stream.read(*args)


def _published(version: str, artifacts: dict[str, bytes]):
    return {
        "info": {"version": version},
        "urls": [
            {
                "filename": name,
                "digests": {"sha256": hashlib.sha256(content).hexdigest()},
            }
            for name, content in artifacts.items()
        ],
    }


def test_pypi_verification_matches_exact_local_wheel_and_sdist(tmp_path: Path):
    artifacts = {"whaxon-1.2.3-py3-none-any.whl": b"wheel", "whaxon-1.2.3.tar.gz": b"sdist"}
    for name, data in artifacts.items():
        (tmp_path / name).write_bytes(data)
    opener = Mock(return_value=_Response(_published("1.2.3", artifacts)))

    verify_pypi_release("1.2.3", tmp_path, opener=opener, sleeper=Mock(), attempts=1)

    assert opener.call_count == 1


def test_pypi_verification_rejects_a_published_hash_mismatch(tmp_path: Path):
    (tmp_path / "whaxon-1.2.3-py3-none-any.whl").write_bytes(b"expected")
    opener = Mock(return_value=_Response(_published(
        "1.2.3", {"whaxon-1.2.3-py3-none-any.whl": b"different"}
    )))

    with pytest.raises(RuntimeError, match="SHA-256 does not match"):
        verify_pypi_release("1.2.3", tmp_path, opener=opener, sleeper=Mock(), attempts=1)


def test_pypi_verification_waits_until_all_local_files_are_published(tmp_path: Path):
    artifacts = {"whaxon-1.2.3-py3-none-any.whl": b"wheel", "whaxon-1.2.3.tar.gz": b"sdist"}
    for name, data in artifacts.items():
        (tmp_path / name).write_bytes(data)
    partial = _published("1.2.3", {next(iter(artifacts)): next(iter(artifacts.values()))})
    complete = _published("1.2.3", artifacts)
    opener = Mock(side_effect=[_Response(partial), _Response(complete)])
    sleeper = Mock()

    verify_pypi_release("1.2.3", tmp_path, opener=opener, sleeper=sleeper, attempts=2)

    assert opener.call_count == 2
    sleeper.assert_called_once_with(20.0)
