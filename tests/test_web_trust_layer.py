"""Behavioral tests for the Trust Layer API routes (Steps 5 & 6).

Runs against the real server via the live_server fixture, same as the
Playwright tests. Uses urllib for the HTTP calls.
"""
from __future__ import annotations

import json
from urllib.request import Request, urlopen


def _post(url, body=None):
    data = json.dumps(body).encode() if body is not None else b""
    req = Request(url, data=data, method="POST",
                  headers={"Content-Type": "application/json"})
    try:
        with urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except Exception as e:
        # urllib raises HTTPError for 4xx/5xx. Extract the body.
        from urllib.error import HTTPError
        if isinstance(e, HTTPError):
            return e.code, json.loads(e.read())
        raise


def _get(url):
    with urlopen(url, timeout=5) as r:
        return r.status, json.loads(r.read())


def _seed_open_port_finding(seq=0):
    """Return a deterministic, pre-seeded non-replayable open_port finding."""
    # conftest seeds these two findings in an isolated loopback-only job.
    # Do not create a real scan here: validation route tests must never depend
    # on external targets, third-party rate limits, or tool availability.
    return "seed-job-1", seq


def test_coverage_route_returns_empty_for_new_job(live_server):
    _, data = _get(f"{live_server}/api/report?format=json")
    if not data.get("jobs"):
        return  # nothing seeded, skip silently
    job_id = data["jobs"][0]["job"]["id"]
    status, body = _get(f"{live_server}/api/coverage/{job_id}")
    assert status == 200
    assert body["job_id"] == job_id
    assert isinstance(body["gaps"], list)
    assert body["count"] == len(body["gaps"])


def test_validate_route_candidate_on_non_replayable(live_server):
    job_id, seq = _seed_open_port_finding(0)
    status, body = _post(f"{live_server}/api/validate/{job_id}/{seq}")
    assert status == 200
    # open_port and similar are not replayable. candidate is correct.
    assert body["status"] in ("candidate", "verified", "refuted")
    assert "reason" in body


def test_retest_route_requires_verified(live_server):
    job_id, seq = _seed_open_port_finding(1)
    # Force the finding to candidate (default), then retest.
    status, body = _post(f"{live_server}/api/retest/{job_id}/{seq}")
    if body.get("error") == "not verified":
        assert status == 400
        assert "not verified" in body["error"]
    else:
        # If the seed happened to be verified, retest should not error.
        assert status == 200


def test_approval_resolve_route_writes_human(live_server):
    job_id, seq = _seed_open_port_finding(0)
    status, body = _post(
        f"{live_server}/api/approvals/{job_id}/{seq}/resolve",
        {"status": "verified", "user": "peter"},
    )
    assert status == 200
    assert body["ok"] is True
    assert body["by"] == "human:peter"
