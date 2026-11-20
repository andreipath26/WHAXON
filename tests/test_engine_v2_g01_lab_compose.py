import asyncio
import hashlib
import json
import runpy
from pathlib import Path


def test_g01_compose_is_fixed_private_lab_without_published_ports():
    root = Path(__file__).resolve().parents[1]
    compose = (root / "docker-compose.g01-lab.yml").read_text(encoding="utf-8")
    runner = (root / "Dockerfile.g01-lab-runner").read_text(encoding="utf-8")
    entrypoint = (root / "scripts/g01-lab-runner-entrypoint.sh").read_text(encoding="utf-8")
    workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    project = (root / "pyproject.toml").read_text(encoding="utf-8")

    for address in ("172.28.0.10", "172.28.0.11"):
        assert address in compose
    assert 'network_mode: "service:msf-target"' in compose
    assert "internal: true" in compose
    assert "ports:" not in compose
    assert "WHAXON_ENABLE_V2_LAB_INITIAL_ACCESS: \"1\"" in compose
    assert "WHAXON_MSF_HOST: 127.0.0.1" in compose
    assert 'WHAXON_MSF_TIMEOUT: "30"' in compose
    assert "metasploitframework/metasploit-framework:6.5.4@sha256:5ede8e5bccb4be4461754326ae2096e3a6bc2e0227aae4fa6b569f4ae442e548" in runner
    assert "git -C /opt/sqlmap checkout 5a12bd290d16992d0b46837b17b2694c8b64c746" in runner
    assert "gobuster_Linux_x86_64.tar.gz" in runner
    assert "c8a8c6a966eeb011d682a0ef2305a3e3a86b8b3fabe744350c00a766cc0f8021" in runner
    assert "tleemcjr/metasploitable2@sha256:e559450b37dccc1909eafa2df5b20bb052e1bd801246f4539a3ef183d5f7288a" in compose
    assert "-a 127.0.0.1" in entrypoint
    assert "ruby /usr/src/metasploit-framework/msfrpcd" in entrypoint
    assert "engine-v2-g01-controlled-lab:" in workflow
    assert "scripts/g01-lab-chain.py" in workflow
    assert "./scripts/sqlmap_boolean_oracle.py:/sqlmap_boolean_oracle.py:ro" in compose
    assert "socket.create_connection(('172.28.0.10', 139)" in compose
    assert compose.count("condition: service_started") == 2
    assert "fixture-health.json" in workflow
    assert "target-port-probe.txt" in workflow
    assert "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2" in workflow
    assert 'metasploit = ["pymetasploit3==1.0.6"]' in project
    assert workflow.index("Generate ephemeral Metasploit RPC credential") < workflow.index(
        "Validate isolated fixed-address lab topology"
    )
    assert "sha256sum -c g01-mission-report.json.sha256" in workflow
    assert 'SQLI_URL = "http://172.28.0.10:8080/search?id=1"' in (
        root / "scripts/g01-lab-chain.py"
    ).read_text(encoding="utf-8")


def test_failed_initial_access_cleanup_stops_only_new_matching_lab_sessions():
    root = Path(__file__).resolve().parents[1]
    cleanup = runpy.run_path(str(root / "scripts/g01-lab-chain.py"))[
        "_cleanup_new_lab_sessions"
    ]

    class FakeMsf:
        def __init__(self):
            matching = {
                "via_exploit": "exploit/multi/samba/usermap_script",
                "target_host": "172.28.0.10:139",
            }
            self.sessions_by_id = {"5": matching.copy(), "7": matching.copy()}
            self.stopped = []

        def sessions(self, *, strict=False):
            return dict(self.sessions_by_id)

        def connect(self):
            return self

        def call(self, method, args):
            assert method == "session.stop"
            session_id = str(args[0])
            self.stopped.append(session_id)
            self.sessions_by_id.pop(session_id, None)
            return {"result": "success"}

    msf = FakeMsf()
    core = type("CoreFixture", (), {"msf": msf})()
    stopped = asyncio.run(cleanup(core, {"5"}))
    assert stopped == ["7"]
    assert msf.stopped == ["7"]
    assert "5" in msf.sessions_by_id


def test_g01_bootstrap_failure_writes_a_verifiable_minimal_artifact(tmp_path):
    root = Path(__file__).resolve().parents[1]
    ensure_failure = runpy.run_path(str(root / "scripts/g01-lab-chain.py"))[
        "_ensure_failure_artifact"
    ]
    artifact = tmp_path / "g01-mission-report.json"

    ensure_failure(artifact, RuntimeError("fixture setup failed"))

    report_bytes = artifact.read_bytes()
    report = json.loads(report_bytes)
    digest, filename = artifact.with_suffix(artifact.suffix + ".sha256").read_text(
        encoding="ascii"
    ).split()
    assert report["status"] == "failed"
    assert report["failure"] == "RuntimeError"
    assert report["completed_stages"] == []
    assert filename == artifact.name
    assert digest == hashlib.sha256(report_bytes).hexdigest()


def test_g01_bootstrap_failure_does_not_replace_an_existing_report(tmp_path):
    root = Path(__file__).resolve().parents[1]
    ensure_failure = runpy.run_path(str(root / "scripts/g01-lab-chain.py"))[
        "_ensure_failure_artifact"
    ]
    artifact = tmp_path / "g01-mission-report.json"
    artifact.write_text('{"status":"complete"}\n', encoding="utf-8")

    ensure_failure(artifact, RuntimeError("later failure"))

    assert json.loads(artifact.read_text(encoding="utf-8"))["status"] == "complete"
