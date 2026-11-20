"""Tests for whaxon.interfaces.web.server — the Flask API.

Session 1 of 3: covers non-MSF, non-AI endpoints. MSF and AI endpoints
require mock clients and are covered in tests/test_server_msf.py and
tests/test_server_ai.py (not yet written).

Auth note: the server's `_auth_gate` skips auth for loopback requests
(remote_addr in 127.0.0.1/::1/None). Flask's test_client() defaults to
None, so auth is off by default in these tests. To test the auth path,
pass `environ_base={"REMOTE_ADDR": "10.0.0.1"}` to each request.

Known bug found while writing these tests: server.py defines two
`/api/health` routes (lines 326 and 347 in the commit prior to this
file). Flask keeps only the last one. The richer readiness probe
(MSF check + data dir writability) is unreachable. See the commit
message for details.
"""
from __future__ import annotations

import hashlib
import json
from io import BytesIO

from whaxon.core import Core
from whaxon.interfaces.web.server import (
    AsyncRunner,
    JobRegistry,
    create_app,
)

# ---------------------------------------------------------------- helpers

def _make_app(tmp_path, monkeypatch, auth=False):
    """Build a Flask app for testing. Returns (app, core).

    If auth=True, sets credentials AND leaves remote_addr as loopback
    so `_auth_gate` still skips. To force the auth check, requests must
    set environ_base={"REMOTE_ADDR": "10.0.0.1"}.
    """
    monkeypatch.setenv("WHAXON_DATA", str(tmp_path))
    if auth:
        monkeypatch.setenv("WHAXON_AUTH_USER", "testuser")
        monkeypatch.setenv(
            "WHAXON_AUTH_PASS_HASH",
            hashlib.sha256(b"testpass").hexdigest(),
        )
    else:
        monkeypatch.delenv("WHAXON_AUTH_USER", raising=False)
        monkeypatch.delenv("WHAXON_AUTH_PASS_HASH", raising=False)

    core = Core(data_dir=tmp_path)
    registry = JobRegistry(core)
    runner = AsyncRunner(core)
    app = create_app(core, registry, runner)
    app.config["TESTING"] = True
    return app, core


def _seed_job(core, job_id="j1", findings=None, status="finished"):
    store = core.store
    store.create(job_id)
    store.set_started(job_id, "nmap", "10.0.0.5")
    for i, f in enumerate(findings or []):
        store.append_finding(job_id, f, i)
    if status == "finished":
        store.set_finished(job_id, 0, 0.1)
    elif status == "failed":
        store.set_failed(job_id, "boom")
    return job_id


def _finding(kind="open_port", severity="high", port=22):
    return {
        "kind": kind,
        "severity": severity,
        "source": "nmap",
        "data": {"port": port},
        "raw_line": f"{port}/tcp open",
    }


# ---------------------------------------------------------------- /api/health

def test_health_reachable(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.get("/api/health")
    assert r.status_code in (200, 503)
    data = r.get_json()
    assert "status" in data
    assert "checks" in data


def test_burp_import_route_persists_imported_findings(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    xml = (
        "<issues><issue><name>Test issue</name><severity>High</severity>"
        "<confidence>Certain</confidence><host>example.test</host>"
        "<path>/login</path><location>https://example.test/login</location>"
        "</issue></issues>"
    )

    response = app.test_client().post(
        "/api/import/burp",
        data={"file": (BytesIO(xml.encode("utf-8")), "burp.xml")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 201
    result = response.get_json()
    assert result["target"] == "example.test"
    assert result["count"] == 1
    job = core.store.get(result["job_id"])
    findings = core.store.get_findings(result["job_id"])
    assert job is not None
    assert findings[0]["source"] == "burp"
    assert findings[0]["kind"] == "web_issue"
    assert findings[0]["data"]["location"] == "https://example.test/login"


def test_burp_import_route_rejects_missing_bad_extension_and_empty_xml(
    tmp_path, monkeypatch,
):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()

    missing = client.post("/api/import/burp")
    bad_extension = client.post(
        "/api/import/burp",
        data={"file": (BytesIO(b"<issues/ >"), "burp.txt")},
        content_type="multipart/form-data",
    )
    empty_xml = client.post(
        "/api/import/burp",
        data={"file": (BytesIO(b"<issues/>"), "burp.xml")},
        content_type="multipart/form-data",
    )

    assert missing.status_code == 400
    assert bad_extension.status_code == 400
    assert empty_xml.status_code == 400


# ---------------------------------------------------------------- /api/tools

def test_tools_lists_catalog(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.get("/api/tools")
    assert r.status_code == 200
    data = r.get_json()
    assert isinstance(data, list)
    for tool in data:
        assert "id" in tool
        assert "available" in tool


# ---------------------------------------------------------------- /api/history

def test_history_empty(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.get("/api/history")
    assert r.status_code == 200
    assert r.get_json() == []


def test_history_returns_finished_jobs(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1")
    _seed_job(core, "j2")
    client = app.test_client()
    r = client.get("/api/history")
    assert r.status_code == 200
    data = r.get_json()
    ids = {e["id"] for e in data}
    assert ids == {"j1", "j2"}
    assert all(isinstance(e["started_at"], (int, float)) for e in data)


def test_active_jobs_lists_only_running_jobs(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "running-job", status="running")
    _seed_job(core, "finished-job", status="finished")

    response = app.test_client().get("/api/jobs/active")

    assert response.status_code == 200
    jobs = response.get_json()
    assert [job["id"] for job in jobs] == ["running-job"]
    assert jobs[0]["status"] == "running"
    assert jobs[0]["tool"] == "nmap"


# ---------------------------------------------------------------- /api/jobs/<id>

def test_job_detail(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1")
    client = app.test_client()
    r = client.get("/api/jobs/j1")
    assert r.status_code == 200
    data = r.get_json()
    assert data["id"] == "j1"
    assert data["tool"] == "nmap"
    assert data["target"] == "10.0.0.5"


def test_job_not_found(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.get("/api/jobs/missing")
    assert r.status_code == 404


def test_job_findings(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1", findings=[_finding(port=22), _finding(port=80)])
    client = app.test_client()
    r = client.get("/api/jobs/j1/findings")
    assert r.status_code == 200
    data = r.get_json()
    assert len(data) == 2
    assert {f["data"]["port"] for f in data} == {22, 80}


# ---------------------------------------------------------------- /api/report

def test_report_md(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1", findings=[_finding()])
    client = app.test_client()
    r = client.get("/api/report?format=md")
    assert r.status_code == 200
    text = r.get_data(as_text=True)
    assert "# WHAXON Engagement Report" in text


def test_report_json(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1", findings=[_finding()])
    client = app.test_client()
    r = client.get("/api/report?format=json")
    assert r.status_code == 200
    data = r.get_json()
    assert "job_count" in data
    assert data["job_count"] == 1
    assert "chains" in data


def test_report_fmt_alias_matches_format(tmp_path, monkeypatch):
    """?fmt= and ?format= must return the same payload (the alias fix)."""
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1", findings=[_finding()])
    client = app.test_client()
    a = client.get("/api/report?format=json").get_data()
    b = client.get("/api/report?fmt=json").get_data()
    da = json.loads(a)
    db = json.loads(b)
    da.pop("generated", None)
    db.pop("generated", None)
    assert da == db


def test_report_whaxon_envelope(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1", findings=[_finding()])
    client = app.test_client()
    r = client.get("/api/report?format=whaxon")
    assert r.status_code == 200
    env = json.loads(r.get_data(as_text=True))
    assert env["format"] == "whaxon"
    assert env["version"] == 1
    assert env["tool"].startswith("whaxon/")
    assert env["engagement"] == "default"
    assert env["integrity"].startswith("sha256:")
    assert env["integrity_note"] == "SHA-256 covers the payload for integrity checking only; the envelope is unsigned and has no external trust anchor, so it does not prove authenticity."
    assert "payload" in env


def test_report_whaxon_integrity_matches_payload(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1", findings=[_finding()])
    client = app.test_client()
    r = client.get("/api/report?format=whaxon")
    env = json.loads(r.get_data(as_text=True))
    canonical = json.dumps(env["payload"], default=str, sort_keys=True)
    expected = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert env["integrity"] == expected


# ---------------------------------------------------------------- /api/jobs/<id>/report

def test_per_job_report_md(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1", findings=[_finding()])
    client = app.test_client()
    r = client.get("/api/jobs/j1/report?format=md")
    assert r.status_code == 200
    assert r.get_data(as_text=True).startswith("# Job j1")


def test_per_job_report_fmt_alias(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, "j1", findings=[_finding()])
    client = app.test_client()
    a = client.get("/api/jobs/j1/report?format=md").get_data(as_text=True)
    b = client.get("/api/jobs/j1/report?fmt=md").get_data(as_text=True)
    assert a == b


# ---------------------------------------------------------------- /api/scope

def test_scope_get(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.get("/api/scope")
    assert r.status_code == 200
    data = r.get_json()
    assert "enabled" in data or "in_scope" in data


def test_scope_check_localhost_allowed(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.post("/api/scope/check", json={"target": "127.0.0.1"})
    assert r.status_code == 200
    data = r.get_json()
    assert data["allowed"] is True


def test_scope_check_public_denied(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.post("/api/scope/check", json={"target": "8.8.8.8"})
    assert r.status_code == 200
    data = r.get_json()
    assert data["allowed"] is False


# ---------------------------------------------------------------- /api/loot, /api/tree, /api/pivot

def test_loot_empty(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.get("/api/loot")
    assert r.status_code == 200
    data = r.get_json()
    assert data["loot"] == []
    assert data["count"] == 0


def test_tree_empty(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.get("/api/tree")
    assert r.status_code == 200


def test_pivot_graph_empty(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.get("/api/pivot/graph")
    assert r.status_code == 200
    data = r.get_json()
    assert data["count"] == 0


# ---------------------------------------------------------------- /api/settings

def test_settings_get(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.get("/api/settings")
    assert r.status_code == 200


# ---------------------------------------------------------------- UI routes

def test_ui_renders(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.get("/ui")
    assert r.status_code == 200
    assert b"WHAXON" in r.get_data()


def test_root_redirects_to_canonical_ui_v2(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.get("/")
    assert r.status_code in (301, 302)
    assert r.headers["Location"].endswith("/ui-v2")


def test_legacy_ui_route_remains_available(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.get("/ui")
    assert r.status_code == 200
    assert b"page-findings" in r.data


def test_canonical_ui_v2_route_is_available(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.get("/ui-v2")
    assert r.status_code == 200
    assert b"WHAXON" in r.data


# ---------------------------------------------------------------- scope wiring


def test_scope_page_has_wiring_hooks(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.get("/ui")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert 'id="scope-rules"' in body
    assert 'id="scope-count"' in body
    assert 'id="scope-check-input"' in body
    assert 'id="scope-check-btn"' in body
    assert 'id="scope-check-result"' in body


# ---------------------------------------------------------------- findings wiring


def test_findings_page_has_wiring_hooks(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.get("/ui")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert 'id="findings-tbody"' in body
    assert 'id="findings-summary"' in body
    assert 'id="kpi-critical"' in body
    assert 'id="kpi-high"' in body
    assert 'id="kpi-medium"' in body
    assert 'id="kpi-low"' in body
    assert 'id="donut-critical"' in body
    assert 'id="donut-summary"' in body
    assert 'id="legend-critical"' in body
    assert 'id="legend-low"' in body


# ---------------------------------------------------------------- auth path

def test_auth_required_when_non_loopback_and_creds_set(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch, auth=True)
    client = app.test_client()
    r = client.get("/api/tools", environ_base={"REMOTE_ADDR": "10.0.0.1"})
    assert r.status_code == 401


def test_auth_accepts_correct_basic(tmp_path, monkeypatch):
    import base64
    app, _ = _make_app(tmp_path, monkeypatch, auth=True)
    client = app.test_client()
    creds = base64.b64encode(b"testuser:testpass").decode()
    r = client.get(
        "/api/tools",
        environ_base={"REMOTE_ADDR": "10.0.0.1"},
        headers={"Authorization": f"Basic {creds}"},
    )
    assert r.status_code == 200


def test_auth_rejects_wrong_password(tmp_path, monkeypatch):
    import base64
    app, _ = _make_app(tmp_path, monkeypatch, auth=True)
    client = app.test_client()
    creds = base64.b64encode(b"testuser:wrong").decode()
    r = client.get(
        "/api/tools",
        environ_base={"REMOTE_ADDR": "10.0.0.1"},
        headers={"Authorization": f"Basic {creds}"},
    )
    assert r.status_code == 401


def test_auth_skipped_for_loopback(tmp_path, monkeypatch):
    """Auth gate lets loopback through even with credentials set."""
    app, _ = _make_app(tmp_path, monkeypatch, auth=True)
    client = app.test_client()
    r = client.get("/api/tools")  # no Authorization header
    assert r.status_code == 200

def test_run_defaults_to_v2_plan_response_and_ignores_json_opt_in(tmp_path, monkeypatch):
    """A request body cannot re-enable the legacy direct ToolRunner route."""
    from types import SimpleNamespace

    app, core = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    submitted = []
    monkeypatch.setattr(
        core.scope,
        "check",
        lambda target: SimpleNamespace(allowed=True, reason="", matched_rule="loopback"),
    )
    monkeypatch.setattr(core.catalog, "get", lambda tool_id: object())
    monkeypatch.setattr(AsyncRunner, "submit", lambda self, task: submitted.append(task))

    before = core.store.history()
    response = client.post(
        "/api/run",
        json={
            "tool_id": "echo",
            "target": "127.0.0.1",
            "legacy_execution_enabled": True,
            "allow_legacy_execution": True,
        },
    )

    assert response.status_code == 410
    payload = response.get_json()
    assert payload["legacy_execution_enabled"] is False
    assert payload["v2_plan_endpoint"] == "/api/v2/workflows"
    assert payload["v2_run_endpoint"] == "/api/v2/workflows/<plan_id>/run"
    assert payload["approval_granted"] is False
    assert payload["execution_submitted"] is False
    assert "reviewable plan" in payload["error"]
    assert core.store.history() == before
    assert submitted == []


def test_run_legacy_execution_requires_server_operator_opt_in(tmp_path, monkeypatch):
    """Only the server-side operator setting can retain the compatibility path."""
    from types import SimpleNamespace

    monkeypatch.setenv("WHAXON_LEGACY_TOOL_EXECUTION_ENABLED", "true")
    app, core = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    submitted = []
    monkeypatch.setattr(
        core.scope,
        "check",
        lambda target: SimpleNamespace(allowed=True, reason="", matched_rule="loopback"),
    )
    monkeypatch.setattr(core.catalog, "get", lambda tool_id: object())
    monkeypatch.setattr(AsyncRunner, "submit", lambda self, task: submitted.append(task))

    response = client.post(
        "/api/run",
        json={"tool_id": "echo", "target": "127.0.0.1"},
    )

    assert response.status_code == 202
    assert response.get_json()["job_id"]
    assert len(submitted) == 1


def test_run_refuses_to_start_when_scope_check_raises(tmp_path, monkeypatch):
    """A scope-check failure must fail closed and must not enqueue a scan."""
    app, core = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    submitted = []

    monkeypatch.setattr(
        core.scope,
        "check",
        lambda target: (_ for _ in ()).throw(RuntimeError("scope service unavailable")),
    )
    monkeypatch.setattr(core.catalog, "get", lambda tool_id: object())
    monkeypatch.setattr(AsyncRunner, "submit", lambda self, task: submitted.append(task))

    before = core.store.history()
    response = client.post(
        "/api/run",
        json={"tool_id": "nmap", "target": "127.0.0.1"},
    )

    assert response.status_code == 503
    assert "scope evaluation failed" in response.get_json()["error"]
    assert core.store.history() == before
    assert submitted == []


def test_run_refuses_out_of_scope_target_without_override(tmp_path, monkeypatch):
    """A denied scope decision must not enqueue a scan."""
    from types import SimpleNamespace

    app, core = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    submitted = []
    monkeypatch.setattr(
        core.scope,
        "check",
        lambda target: SimpleNamespace(
            allowed=False,
            reason="target is not in scope",
            matched_rule=None,
        ),
    )
    monkeypatch.setattr(AsyncRunner, "submit", lambda self, task: submitted.append(task))

    before = core.store.history()
    response = client.post(
        "/api/run",
        json={"tool_id": "nmap", "target": "198.51.100.25"},
    )

    assert response.status_code == 403
    assert "out of scope" in response.get_json()["error"]
    assert core.store.history() == before
    assert submitted == []


def test_run_ignores_client_scope_override_and_rejects_target_arguments(tmp_path, monkeypatch):
    """Clients cannot enable an out-of-scope run or inject a second target."""
    from types import SimpleNamespace

    app, core = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    submitted = []
    monkeypatch.setattr(
        core.scope,
        "check",
        lambda target: SimpleNamespace(
            allowed=False,
            reason="target is not in scope",
            matched_rule=None,
        ),
    )
    monkeypatch.setattr(core.catalog, "get", lambda tool_id: object())
    monkeypatch.setattr(AsyncRunner, "submit", lambda self, task: submitted.append(task))

    before = core.store.history()
    payloads = [
        (
            {"tool_id": "nmap", "target": "198.51.100.25", "allow_out_of_scope": True},
            403,
        ),
        (
            {"tool_id": "nmap", "target": "198.51.100.25", "scope_override": True},
            403,
        ),
        (
            {
                "tool_id": "nmap",
                "target": "198.51.100.25",
                "extra_args": "--target 127.0.0.1",
            },
            400,
        ),
    ]
    for payload, expected_status in payloads:
        response = client.post("/api/run", json=payload)
        assert response.status_code == expected_status, payload
        assert "error" in response.get_json()

    assert core.store.history() == before
    assert submitted == []

# ---------------------------------------------------------------- local browser boundary

def test_loopback_listener_rejects_cross_origin_state_change(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    response = client.post(
        "/api/run",
        json={"tool_id": "echo", "target": "127.0.0.1"},
        headers={"Origin": "https://attacker.example"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert response.status_code == 403
    assert "cross-origin" in response.get_json()["error"]


def test_loopback_client_rejects_dns_rebinding_host_even_on_network_listener(tmp_path, monkeypatch):
    monkeypatch.setenv("WHAXON_HOST", "0.0.0.0")
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    response = client.get(
        "/api/tools",
        headers={"Host": "attacker.example"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert response.status_code == 403
    assert "Host" in response.get_json()["error"]


def test_loopback_listener_rejects_cross_site_fetch_metadata(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    response = client.post(
        "/api/scope/disable",
        json={},
        headers={"Sec-Fetch-Site": "cross-site"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert response.status_code == 403
    assert "cross-origin" in response.get_json()["error"]

def test_web_validation_refuses_out_of_scope_job_target(tmp_path, monkeypatch):
    monkeypatch.setenv("WHAXON_LEGACY_VALIDATION_ENABLED", "true")
    app, core = _make_app(tmp_path, monkeypatch)
    core.store.create("outside")
    core.store.set_started("outside", "sqlmap", "google.com")
    core.store.append_finding("outside", _finding(kind="sqli"), 0)

    response = app.test_client().post(
        "/api/validate/outside/0",
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert response.status_code == 403
    assert "out of scope" in response.get_json()["error"].lower()


def test_legacy_validation_api_is_default_denied_before_read_or_replay(tmp_path, monkeypatch):
    from whaxon.core.validator import Validator

    monkeypatch.delenv("WHAXON_LEGACY_VALIDATION_ENABLED", raising=False)
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, findings=[_finding(kind="sqli")])
    calls = []
    read_findings = core.store.get_findings
    monkeypatch.setattr(core.store, "get_findings", lambda *_: calls.append("read"))
    monkeypatch.setattr(Validator, "validate", lambda *_a, **_k: calls.append("replay"))

    response = app.test_client().post("/api/validate/j1/0")

    assert response.status_code == 410
    assert response.get_json()["legacy_validation_enabled"] is False
    assert response.get_json()["approval_granted"] is False
    assert response.get_json()["replay_attempted"] is False
    assert calls == []
    assert read_findings("j1")[0]["verification_status"] == "candidate"


def test_legacy_validation_api_runs_only_with_explicit_opt_in(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from whaxon.core.validator import Validator

    monkeypatch.setenv("WHAXON_LEGACY_VALIDATION_ENABLED", "true")
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, findings=[_finding(kind="sqli")])
    monkeypatch.setattr(
        core.scope, "check",
        lambda target: SimpleNamespace(allowed=True, reason="in scope", matched_rule="test"),
    )
    replayed = []
    monkeypatch.setattr(
        Validator, "validate",
        lambda _self, finding, target_url=None: (
            replayed.append((finding.kind, target_url)) or ("verified", "synthetic proof")
        ),
    )

    response = app.test_client().post("/api/validate/j1/0")

    assert response.status_code == 200
    assert response.get_json() == {"status": "verified", "reason": "synthetic proof"}
    assert replayed == [("sqli", "http://10.0.0.5")]
    assert core.store.get_findings("j1")[0]["verification_status"] == "verified"


def test_legacy_retest_api_is_default_denied_before_read_or_replay(tmp_path, monkeypatch):
    from whaxon.core.validator import Validator

    monkeypatch.delenv("WHAXON_LEGACY_VALIDATION_ENABLED", raising=False)
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, findings=[_finding(kind="sqli")])
    core.store.update_verification("j1", 0, "verified", by="test", reason="seeded proof")
    calls = []
    read_findings = core.store.get_findings
    monkeypatch.setattr(core.store, "get_findings", lambda *_: calls.append("read"))
    monkeypatch.setattr(Validator, "revalidate", lambda *_a, **_k: calls.append("replay"))

    response = app.test_client().post("/api/retest/j1/0")

    assert response.status_code == 410
    assert response.get_json()["legacy_validation_enabled"] is False
    assert response.get_json()["approval_granted"] is False
    assert response.get_json()["replay_attempted"] is False
    assert calls == []
    assert read_findings("j1")[0]["verification_status"] == "verified"

def test_tool_catalog_reports_adapter_availability(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    response = app.test_client().get("/api/tools")
    assert response.status_code == 200
    tools = response.get_json()
    assert isinstance(tools, list)
    assert tools
    assert all(isinstance(tool.get("adapter_available"), bool) for tool in tools)

def test_evidence_upload_sanitizes_filename_and_delete_removes_file(tmp_path, monkeypatch):
    import io

    app, core = _make_app(tmp_path, monkeypatch)
    core.store.create("evidence-job")
    core.store.set_started("evidence-job", "test", "127.0.0.1")
    client = app.test_client()
    response = client.post(
        "/api/jobs/evidence-job/evidence",
        data={"file": (io.BytesIO(b"evidence bytes"), "../../outside.txt")},
        content_type="multipart/form-data",
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert response.status_code == 201
    assert response.get_json()["name"] == "outside.txt"
    item = core.store.list_evidence("evidence-job")[0]
    data_root = core.data_dir.resolve()
    saved = (data_root / item["path"]).resolve()
    assert saved.is_relative_to(data_root)
    assert saved.read_bytes() == b"evidence bytes"

    download = client.get(
        f"/api/jobs/evidence-job/evidence/{item['seq']}/download",
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert download.status_code == 200
    assert download.data == b"evidence bytes"

    deleted = client.delete(
        f"/api/jobs/evidence-job/evidence/{item['seq']}",
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert deleted.status_code == 200
    assert not saved.exists()
    assert core.store.list_evidence("evidence-job") == []


def test_evidence_routes_reject_unknown_jobs(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    response = app.test_client().get(
        "/api/jobs/unknown-job/evidence",
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert response.status_code == 404


def test_evidence_download_rejects_path_traversal(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    core.store.create("evidence-job")
    core.store.set_started("evidence-job", "test", "127.0.0.1")
    seq = core.store.add_evidence(
        "evidence-job", "file", "outside.txt", path="../../outside.txt"
    )
    response = app.test_client().get(
        f"/api/jobs/evidence-job/evidence/{seq}/download",
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert response.status_code == 403
    assert response.get_json()["error"] == "unsafe evidence path"

def test_msf_session_exec_refuses_out_of_scope_session(tmp_path, monkeypatch):
    monkeypatch.setenv("WHAXON_LEGACY_MSF_EXECUTION_ENABLED", "true")
    app, core = _make_app(tmp_path, monkeypatch)
    monkeypatch.setattr(core.msf, "is_up", lambda: True)
    monkeypatch.setattr(core.msf, "sessions", lambda: {
        "9": {"target_host": "8.8.8.8", "type": "shell"}
    })
    executed = []
    monkeypatch.setattr(core.msf, "session_exec", lambda *a, **kw: executed.append(a))

    response = app.test_client().post(
        "/api/msf/sessions/9/exec",
        json={"command": "id"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert response.status_code == 403
    assert executed == []


def test_msf_port_forward_refuses_out_of_scope_destination(tmp_path, monkeypatch):
    from whaxon.core import portfwd

    monkeypatch.setenv("WHAXON_LEGACY_MSF_EXECUTION_ENABLED", "true")
    app, core = _make_app(tmp_path, monkeypatch)
    monkeypatch.setattr(core.msf, "is_up", lambda: True)
    monkeypatch.setattr(core.msf, "sessions", lambda: {
        "9": {"target_host": "127.0.0.1", "type": "shell"}
    })
    created = []
    monkeypatch.setattr(portfwd, "add_forward", lambda *a, **kw: created.append(a))

    response = app.test_client().post(
        "/api/msf/sessions/9/portfwd",
        json={"lport": 4444, "rhost": "8.8.8.8", "rport": 80},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert response.status_code == 403
    assert created == []


def test_msf_run_rejects_path_traversal_module_path(tmp_path, monkeypatch):
    monkeypatch.setenv("WHAXON_LEGACY_MSF_EXECUTION_ENABLED", "true")
    app, _ = _make_app(tmp_path, monkeypatch)
    response = app.test_client().post(
        "/api/msf/run",
        json={"module_type": "exploit", "module_path": "../arbitrary", "target": "127.0.0.1"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert response.status_code == 400
    assert "module path" in response.get_json()["error"]

def test_loopback_listener_rejects_cross_site_get_requests(tmp_path, monkeypatch):
    monkeypatch.setenv("WHAXON_HOST", "127.0.0.1")
    app, _ = _make_app(tmp_path, monkeypatch)
    response = app.test_client().get(
        "/api/pivot/candidates",
        headers={"Sec-Fetch-Site": "cross-site"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert response.status_code == 403
    assert "cross-origin" in response.get_json()["error"]

# ---------------------------------------------------------------- malformed run request handling

def test_run_rejects_malformed_request_fields(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    payloads = [
        [],
        "not-an-object",
        {"tool_id": [], "target": "127.0.0.1"},
        {"tool_id": "echo", "target": []},
        {"tool_id": "echo", "target": "x" * 2049},
    ]
    for payload in payloads:
        response = client.post("/api/run", json=payload)
        assert response.status_code == 400, payload
        assert "error" in response.get_json()


def test_https_reverse_proxy_origin_is_accepted_when_explicitly_trusted(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("WHAXON_HOST", "127.0.0.1")
    monkeypatch.setenv("WHAXON_TRUST_PROXY", "1")
    monkeypatch.setenv("WHAXON_ALLOWED_HOSTS", "whaxon.example.com")
    app, _ = _make_app(tmp_path, monkeypatch)
    response = app.test_client().get(
        "/api/scope",
        headers={
            "Host": "whaxon.example.com",
            "X-Forwarded-Proto": "https",
            "Origin": "https://whaxon.example.com",
        },
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert response.status_code == 200

def test_network_auth_requires_non_default_bcrypt_credentials(monkeypatch):
    import hashlib

    from whaxon.interfaces.web import server as web_server

    monkeypatch.setattr(web_server, "_bcrypt", None)
    assert not web_server._remote_auth_ready("admin", "long-unique-password", "")
    assert not web_server._remote_auth_ready(
        "admin", "", hashlib.sha256(b"password").hexdigest()
    )
    assert not web_server._remote_auth_ready("whaxon-admin", "whaxon", "")

    monkeypatch.setattr(web_server, "_bcrypt", __import__("bcrypt"))
    strong_hash = web_server._bcrypt.hashpw(
        b"long-unique-password", web_server._bcrypt.gensalt(rounds=12)
    ).decode("utf-8")
    assert web_server._remote_auth_ready("admin", "", strong_hash)
    weak_hash = web_server._bcrypt.hashpw(
        b"password", web_server._bcrypt.gensalt(rounds=11)
    ).decode("utf-8")
    assert not web_server._remote_auth_ready("admin", "", weak_hash)


# ------------------------------------------------------- dependency readiness

def test_dependency_diagnostics_endpoint_is_read_only(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    response = app.test_client().get("/api/dependencies")
    assert response.status_code == 200
    report = response.get_json()
    assert report["schema_version"] == 1
    assert report["safety"]["read_only"] is True
    assert report["safety"]["installation_attempted"] is False


def test_dependency_plan_endpoint_validates_input_and_does_not_install(
    tmp_path, monkeypatch
):
    app, _ = _make_app(tmp_path, monkeypatch)
    client = app.test_client()
    invalid = client.post("/api/dependencies/plan", json={"dependency_ids": "nmap"})
    assert invalid.status_code == 400
    response = client.post(
        "/api/dependencies/plan", json={"dependency_ids": ["python"]}
    )
    assert response.status_code == 200
    plan = response.get_json()
    assert plan["safety"]["read_only"] is True
    assert plan["safety"]["commands_executed"] is False


def test_dependency_install_endpoint_requires_exact_approval(
    tmp_path, monkeypatch
):
    app, _ = _make_app(tmp_path, monkeypatch)
    response = app.test_client().post(
        "/api/dependencies/install",
        json={"dependency_id": "textual", "approved_plan_id": "not-a-plan"},
    )
    assert response.status_code == 400


def test_dependency_install_endpoint_queues_approved_operation(
    tmp_path, monkeypatch
):
    import whaxon.core.dependency_jobs as jobs

    calls = []
    monkeypatch.setattr(
        jobs,
        "start_install_operation",
        lambda dependency_id, approved_plan_id, data_dir: (
            calls.append((dependency_id, approved_plan_id, data_dir))
            or {
                "operation_id": "0123456789abcdef0123456789abcdef",
                "status": "QUEUED",
                "progress": 0,
            }
        ),
    )
    app, _ = _make_app(tmp_path, monkeypatch)
    response = app.test_client().post(
        "/api/dependencies/install",
        json={
            "dependency_id": "textual",
            "approved_plan_id": "plan-0123456789abcdef",
        },
    )
    assert response.status_code == 202
    assert response.get_json()["status"] == "QUEUED"
    assert calls == [(
        "textual",
        "plan-0123456789abcdef",
        tmp_path,
    )]


def test_dependency_install_status_endpoint_returns_operation(
    tmp_path, monkeypatch
):
    import whaxon.core.dependency_jobs as jobs

    operation_id = "0123456789abcdef0123456789abcdef"
    monkeypatch.setattr(
        jobs,
        "get_install_operation",
        lambda data_dir, requested_id: {
            "operation_id": requested_id,
            "status": "VERIFYING",
            "progress": 80,
        },
    )
    app, _ = _make_app(tmp_path, monkeypatch)
    response = app.test_client().get(
        f"/api/dependencies/install/{operation_id}"
    )
    assert response.status_code == 200
    assert response.get_json()["status"] == "VERIFYING"


def test_dependency_install_cancel_endpoint_sets_cancel_request(
    tmp_path, monkeypatch
):
    import whaxon.core.dependency_jobs as jobs

    operation_id = "0123456789abcdef0123456789abcdef"
    monkeypatch.setattr(
        jobs,
        "cancel_install_operation",
        lambda data_dir, requested_id: {
            "operation_id": requested_id,
            "status": "INSTALLING",
            "cancel_requested": True,
        },
    )
    app, _ = _make_app(tmp_path, monkeypatch)
    response = app.test_client().post(
        f"/api/dependencies/install/{operation_id}/cancel"
    )
    assert response.status_code == 202
    assert response.get_json()["cancel_requested"] is True


def test_dependency_readiness_is_integrated_into_existing_diagnostics_page(
    tmp_path, monkeypatch
):
    app, _ = _make_app(tmp_path, monkeypatch)
    response = app.test_client().get("/ui-v2/diagnostics")
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert 'id="whaxon-dependency-readiness-ui"' in page
    assert 'id="dep-check"' in page
    assert 'id="dep-rows"' in page
    assert 'id="dep-plan"' in page
    assert 'id="dep-operation"' in page
    assert "bg-surface-container-low" in page


def test_dependency_audit_integrity_endpoint(tmp_path, monkeypatch):
    import whaxon.core.installer as installer

    monkeypatch.setattr(
        installer,
        "verify_dependency_audit",
        lambda: {"valid": True, "events_checked": 3, "head_hash": "a" * 64},
    )
    app, _ = _make_app(tmp_path, monkeypatch)
    response = app.test_client().get("/api/dependencies/audit")
    assert response.status_code == 200
    assert response.get_json()["valid"] is True
    assert response.get_json()["events_checked"] == 3


def test_dependency_audit_integrity_endpoint_fails_on_corruption(tmp_path, monkeypatch):
    import whaxon.core.installer as installer

    monkeypatch.setattr(
        installer,
        "verify_dependency_audit",
        lambda: {"valid": False, "events_checked": 1, "reason": "hash_mismatch"},
    )
    app, _ = _make_app(tmp_path, monkeypatch)
    response = app.test_client().get("/api/dependencies/audit")
    assert response.status_code == 409
    assert response.get_json()["valid"] is False


# ---------------------------------------------------------------- G03 API retest eligibility and conservative outcomes

def test_retest_api_refuses_candidate_without_replay(tmp_path, monkeypatch):
    from whaxon.core.validator import Validator

    monkeypatch.setenv("WHAXON_LEGACY_VALIDATION_ENABLED", "true")
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, findings=[_finding()])
    called = []
    monkeypatch.setattr(
        Validator, "revalidate",
        lambda *args, **kwargs: called.append(True),
    )

    response = app.test_client().post("/api/retest/j1/0")

    assert response.status_code == 400
    assert response.get_json()["error"] == "not verified"
    assert called == []
    assert core.store.get_findings("j1")[0]["verification_status"] == "candidate"


def test_retest_api_persists_inconclusive_instead_of_fixed(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from whaxon.core.validator import Validator

    monkeypatch.setenv("WHAXON_LEGACY_VALIDATION_ENABLED", "true")
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, findings=[_finding()])
    core.store.update_verification("j1", 0, "verified", by="test", reason="seeded proof")
    monkeypatch.setattr(
        core.scope, "check",
        lambda target: SimpleNamespace(allowed=True, reason="in scope", matched_rule="test"),
    )
    monkeypatch.setattr(
        Validator, "revalidate",
        lambda *args, **kwargs: ("inconclusive", "replay unavailable; no fix inferred"),
    )

    response = app.test_client().post("/api/retest/j1/0")

    assert response.status_code == 200
    assert response.get_json() == {
        "status": "inconclusive",
        "reason": "replay unavailable; no fix inferred",
    }
    stored = core.store.get_findings("j1")[0]
    assert stored["verification_status"] == "inconclusive"
    assert stored["verification_reason"] == "replay unavailable; no fix inferred"


# ---------------------------------------------------------------- G04 API report coverage

def test_api_engagement_reports_include_persisted_coverage_gaps(tmp_path, monkeypatch):
    app, core = _make_app(tmp_path, monkeypatch)
    _seed_job(core, findings=[_finding()])
    core.store.record_coverage(
        "j1", "nikto", "10.0.0.5", "scope_blocked",
        "out of scope; no request was sent", phase="reconnaissance",
    )
    client = app.test_client()

    json_response = client.get("/api/report?format=json")
    assert json_response.status_code == 200
    coverage = json_response.get_json()["jobs"][0]["coverage"]
    assert coverage == [{
        "seq": 0,
        "tool_id": "nikto",
        "target": "10.0.0.5",
        "kind": "scope_blocked",
        "detail": "out of scope; no request was sent",
        "phase": "reconnaissance",
    }]

    markdown = client.get("/api/report?format=md").get_data(as_text=True)
    assert "## Coverage Gaps" in markdown
    assert "scope_blocked" in markdown
    assert "out of scope; no request was sent" in markdown

    html_response = client.get("/api/report?format=html")
    assert html_response.status_code == 200
    html = html_response.get_data(as_text=True)
    assert "Coverage and untested work" in html
    assert "scope_blocked" in html
    assert "out of scope; no request was sent" in html
