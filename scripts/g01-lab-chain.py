"""Execute the fixed Engine V2 G01 chain in the isolated Compose lab."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import time
from pathlib import Path

from whaxon.core import Core
from whaxon.core.workflow import WorkflowPlan, WorkflowTask

MISSION_ID = "g01-controlled-lab"
SQLI_URL = "http://172.28.0.10:8080/search?id=1"


def _task(core: Core, *, task_id: str, capability: str, target: str,
          permissions: tuple[str, ...], impact: str, inputs=None,
          depends_on=(), timeout_s=180.0) -> WorkflowTask:
    return WorkflowTask(
        id=task_id, capability_id=capability, target=target,
        inputs=inputs or {}, depends_on=depends_on,
        permissions=permissions, impact=impact, timeout_s=timeout_s,
    )


def _ensure_failure_artifact(artifact: Path, failure: Exception) -> None:
    """Retain a minimal hashed report when a stage fails before chain setup."""
    if artifact.exists():
        return
    artifact.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "whaxon.g01-controlled-lab.v1",
        "mission_id": MISSION_ID,
        "status": "failed",
        "failure": type(failure).__name__,
        "completed_stages": [],
        "required_chain": [
            "scope", "recon", "enumeration", "initial_access",
            "verification", "report", "retest",
        ],
    }
    encoded = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    artifact.write_text(encoded, encoding="utf-8")
    digest = hashlib.sha256(encoded.encode()).hexdigest()
    artifact.with_suffix(artifact.suffix + ".sha256").write_text(
        f"{digest}  {artifact.name}\n", encoding="ascii",
    )


async def _run_stage(core: Core, stage: str, tasks: tuple[WorkflowTask, ...]):
    plan_id = f"g01-{stage}"
    bindings = {}
    for task in tasks:
        manifest = core.providers.manifest_for(task.capability_id)
        bindings[task.id] = {
            "provider_id": manifest.provider_id,
            "manifest_fingerprint": manifest.fingerprint,
        }
    plan = WorkflowPlan(
        mission_id=MISSION_ID,
        tasks=tasks,
        metadata={"release_stage": stage, "provider_bindings": bindings},
    )
    core.save_workflow_plan(plan_id, plan)
    for task in tasks:
        if task.impact in {"moderate", "high", "critical"}:
            core.grant_workflow_approval(
                plan_id, task.id, f"ci-{stage}-{task.id}", "g01-ci-operator",
                expires_at=time.time() + 3600,
            )
    result = await core.run_workflow_plan(
        plan_id, max_tasks=len(tasks), max_attempts=1, max_concurrency=1,
    )
    report = core.workflow_report(plan_id)
    if result.get("complete") is not True or report.get("status") != "complete":
        raise RuntimeError(json.dumps({
            "stage": stage, "result": result, "report": report,
        }, sort_keys=True))
    return {"plan_id": plan_id, "result": result, "report": report}


async def _cleanup_new_lab_sessions(core: Core, before_session_ids: set[str]) -> list[str]:
    """Close matching lab shells opened by a failed initial-access stage."""
    stopped = []
    sessions = await asyncio.to_thread(core.msf.sessions, strict=True)
    for session_id, info in sessions.items():
        if str(session_id) in before_session_ids:
            continue
        module = str(info.get("via_exploit") or "").removeprefix("exploit/")
        peer = str(info.get("target_host") or info.get("tunnel_peer") or "")
        host = peer.rsplit(":", 1)[0].strip("[]") if peer.count(":") == 1 else peer.strip("[]")
        if module != "multi/samba/usermap_script" or host != "172.28.0.10":
            continue
        reply = await asyncio.to_thread(
            core.msf.connect().call, "session.stop", [str(session_id)],
        )
        if not isinstance(reply, dict) or reply.get("result") != "success":
            raise RuntimeError(f"cleanup failed for newly opened Metasploit session {session_id}")
        current = await asyncio.to_thread(core.msf.sessions, strict=True)
        if str(session_id) in current:
            raise RuntimeError(f"Metasploit session {session_id} remained open")
        stopped.append(str(session_id))
    return stopped


async def run(data_dir: Path, artifact: Path) -> dict:
    data_dir.mkdir(parents=True, exist_ok=True)
    artifact.parent.mkdir(parents=True, exist_ok=True)
    scope_path = data_dir / "scope.json"
    scope_path.write_text(json.dumps({
        "engagement": "repository-owned Engine V2 G01 lab",
        "enabled": True,
        "in_scope": ["172.28.0.10/32"],
        "out_of_scope": [],
        "notes": "Single target .10 hosts Samba and the seeded verifier fixture; callback runner .11 is excluded.",
    }, sort_keys=True), encoding="utf-8")

    catalog_path = data_dir / "tools.json"
    catalog = json.loads((Path(__file__).resolve().parents[1]
                          / "src/whaxon/data/tools.json").read_text(encoding="utf-8"))
    wordlist = Path("/usr/share/wordlists/whaxon-g01.txt")
    wordlist.parent.mkdir(parents=True, exist_ok=True)
    wordlist.write_text("admin\nrobots.txt\nsearch\n", encoding="utf-8")
    overrides = {
        "nmap": "-sT -sV -Pn -n -p 139,445,8080 {target}",
        "gobuster": (
            "dir -u http://{target}:8080 -w /usr/share/wordlists/whaxon-g01.txt "
            "-q -t 1 --no-error --timeout 3s"
        ),
        "sqlmap": (
            f"-u {{target}} --batch --flush-session --technique=B --level=1 --risk=1 "
            f"--threads=1 --timeout=2 --retries=0 --disable-coloring "
            f"--output-dir={data_dir / 'sqlmap-output'}"
        ),
    }
    for tool in catalog["tools"]:
        if tool["id"] in overrides:
            tool["args"] = overrides[tool["id"]]
    catalog_path.write_text(json.dumps(catalog, sort_keys=True), encoding="utf-8")

    if os.environ.get("WHAXON_ENABLE_V2_LAB_INITIAL_ACCESS") != "1":
        raise RuntimeError("the isolated G01 runner must explicitly enable its fixed lab capability")
    core = Core(data_dir)
    await core.initialize(drain=False)
    core.create_mission(MISSION_ID, "Prove the fixed controlled G01 workflow chain")

    stages = []
    stages.append(await _run_stage(core, "recon", (
        _task(core, task_id="nmap-recon", capability="tool.nmap",
              target="172.28.0.10", permissions=("network.scan",), impact="moderate"),
    )))
    stages.append(await _run_stage(core, "enumeration", (
        _task(core, task_id="gobuster-enum", capability="tool.gobuster",
              target="172.28.0.10", permissions=("network.scan",), impact="moderate"),
        _task(core, task_id="sqlmap-source", capability="tool.sqlmap",
              target=SQLI_URL, permissions=("network.scan",), impact="moderate",
              depends_on=("gobuster-enum",)),
    )))

    enumeration_evidence = core.workflow_evidence("g01-enumeration")
    sqlmap_attempt = next(
        item for item in enumeration_evidence["attempts"]
        if item["task_key"] == "sqlmap-source"
    )
    source_job_id = sqlmap_attempt.get("job_id")
    source_finding = next(
        (finding for finding in sqlmap_attempt.get("findings", [])
         if finding.get("kind") == "sqli"),
        None,
    )
    if not source_job_id or source_finding is None:
        raise RuntimeError("the sealed SQLmap attempt did not produce a same-target SQLi finding")

    before_access_sessions = await asyncio.to_thread(core.msf.sessions, strict=True)
    before_access_session_ids = set(before_access_sessions)
    try:
        access = await _run_stage(core, "initial_access", (
            _task(core, task_id="fixed-samba-access",
                  capability="lab.initial_access.samba_usermap",
                  target="172.28.0.10", permissions=("network.exploit",),
                  impact="critical", timeout_s=90.0),
        ))
        stages.append(access)
        access_attempt = core.workflow_evidence(access["plan_id"])["attempts"][0]
        if (
            access_attempt.get("evidence_status") != "recorded"
            or access_attempt.get("integrity_status") != "verified"
        ):
            raise RuntimeError("initial-access evidence is not recorded and sealed")
        access_job_id = access_attempt.get("job_id")
        if not isinstance(access_job_id, str) or not access_job_id:
            raise RuntimeError("initial-access evidence has no linked job")
        access_findings = core.store.get_findings(access_job_id) or []
        session_finding = next((
            finding for finding in access_findings
            if isinstance(finding, dict)
            and finding.get("kind") == "msf_session"
            and finding.get("source") == "engine-v2-lab-access"
            and isinstance(finding.get("data"), dict)
            and finding["data"].get("host") == "172.28.0.10"
            and finding["data"].get("module") == "multi/samba/usermap_script"
        ), None)
        session_id = str((session_finding or {}).get("data", {}).get("session_id") or "")
        if not session_id.isdigit():
            raise RuntimeError("sealed initial-access finding has no valid lab session id")
    except Exception as exc:
        cleanup_exception = None
        try:
            stopped = await _cleanup_new_lab_sessions(core, before_access_session_ids)
            cleanup = {"result": "success", "stopped_sessions": stopped}
        except Exception as cleanup_exc:
            cleanup_exception = cleanup_exc
            cleanup = {"result": "failed", "reason": type(cleanup_exc).__name__}
        failure = {
            "schema_version": "whaxon.g01-controlled-lab.v1",
            "mission_id": MISSION_ID,
            "status": "failed",
            "failure": type(exc).__name__,
            "operator_session_cleanup": cleanup,
        }
        encoded = json.dumps(failure, indent=2, sort_keys=True) + "\n"
        artifact.write_text(encoded, encoding="utf-8")
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        artifact.with_suffix(artifact.suffix + ".sha256").write_text(
            f"{digest}  {artifact.name}\n", encoding="ascii",
        )
        if cleanup["result"] != "success":
            raise RuntimeError("initial-access failure left cleanup unconfirmed") from cleanup_exception
        raise
    result = {
        "schema_version": "whaxon.g01-controlled-lab.v1",
        "mission_id": MISSION_ID,
        "status": "partial",
        "required_chain": ["scope", "recon", "enumeration", "initial_access",
                           "verification", "report", "retest"],
        "stages": stages,
        "mission_report": None,
        "operator_session_cleanup": {"session_id": session_id, "result": "pending"},
    }

    def persist() -> str:
        result.pop("artifact_sha256", None)
        encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
        artifact.write_text(encoded, encoding="utf-8")
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        artifact.with_suffix(artifact.suffix + ".sha256").write_text(
            f"{digest}  {artifact.name}\n", encoding="ascii",
        )
        return digest

    chain_error = None
    cleanup_error = None
    try:
        verification = await _run_stage(core, "verification", (
            _task(core, task_id="verify-sqli", capability="tool.verify_sqli",
                  target=SQLI_URL, permissions=("network.verify",), impact="moderate",
                  inputs={"source_job_id": source_job_id,
                          "finding_seq": source_finding["seq"]}),
        ))
        stages.append(verification)
        result["stages"] = stages
        verification_evidence = core.workflow_evidence(verification["plan_id"])
        verified_attempt = verification_evidence["attempts"][0]
        if (
            verified_attempt.get("evidence_status") != "recorded"
            or verified_attempt.get("integrity_status") != "verified"
        ):
            raise RuntimeError("verification evidence is not recorded and sealed")
        verified_job_id = verified_attempt.get("job_id")
        if not isinstance(verified_job_id, str) or not verified_job_id:
            raise RuntimeError("verification evidence has no linked job")
        verification_findings = core.store.get_findings(verified_job_id) or []
        verified_finding = next((
            finding for finding in verification_findings
            if isinstance(finding, dict)
            and finding.get("kind") == "sqli"
            and finding.get("source") == "engine-v2-verifier"
            and finding.get("verification_status") == "verified"
            and finding.get("verified_by") == "engine-v2"
            and isinstance(finding.get("data"), dict)
            and finding["data"].get("status") == "verified"
            and finding["data"].get("source_job_id") == source_job_id
            and finding["data"].get("source_finding_seq") == source_finding["seq"]
        ), None)
        if verified_finding is None:
            raise RuntimeError("independent SQLi verification did not persist a verified result")

        retest = await _run_stage(core, "retest", (
            _task(core, task_id="retest-sqli", capability="tool.retest_sqli",
                  target=SQLI_URL, permissions=("network.verify",), impact="moderate",
                  inputs={"source_job_id": verified_job_id,
                          "finding_seq": verified_finding["seq"]}),
        ))
        stages.append(retest)
        result["stages"] = stages

        mission_report = core.workflow_mission_report(MISSION_ID)
        result["mission_report"] = mission_report
        if mission_report.get("status") != "complete":
            raise RuntimeError(json.dumps(mission_report, sort_keys=True))
        result["status"] = "complete"
    except Exception as exc:
        chain_error = exc
        result["status"] = "failed"
        result["failure"] = type(exc).__name__
        try:
            result["mission_report"] = core.workflow_mission_report(MISSION_ID)
        except Exception:
            result["mission_report"] = {"status": "unavailable"}
    finally:
        try:
            stop_reply = core.msf.connect().call("session.stop", [session_id])
            if not isinstance(stop_reply, dict) or stop_reply.get("result") != "success":
                raise RuntimeError("Metasploit did not confirm session.stop")
            if session_id in core.msf.sessions(strict=True):
                raise RuntimeError("CI lab shell session remained open after cleanup")
            result["operator_session_cleanup"] = {
                "session_id": session_id, "result": "success",
            }
        except Exception as exc:
            cleanup_error = exc
            result["operator_session_cleanup"] = {
                "session_id": session_id, "result": "failed",
                "reason": type(exc).__name__,
            }
            result["status"] = "failed"
        result["artifact_sha256"] = persist()

    if chain_error is not None:
        raise chain_error
    if cleanup_error is not None:
        raise RuntimeError("controlled-lab Metasploit session cleanup was not confirmed") from cleanup_error
    if result["status"] != "complete":
        raise RuntimeError("controlled-lab mission did not complete")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, default=Path("/var/lib/whaxon"))
    parser.add_argument("--artifact", type=Path,
                        default=Path("/artifacts/g01-mission-report.json"))
    options = parser.parse_args()
    try:
        result = asyncio.run(run(options.data_dir, options.artifact))
    except Exception as exc:
        try:
            _ensure_failure_artifact(options.artifact, exc)
        except OSError:
            pass
        raise
    print(json.dumps({
        "mission_id": result["mission_id"], "status": result["status"],
        "artifact": str(options.artifact),
        "artifact_sha256": result["artifact_sha256"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
