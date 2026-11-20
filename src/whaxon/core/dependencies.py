"""Read-only dependency detection and capability readiness for WHAXON.

This module only inspects the active runtime, installed distributions and
external-tool catalog. Installation is handled by a separate consent-gated
module; diagnostics never mutate the environment or invoke package managers.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


def load_dependency_manifest() -> dict[str, Any]:
    """Load and minimally validate the packaged dependency manifest."""
    path = Path(__file__).resolve().parents[1] / "data" / "dependencies.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(raw, dict)
        or raw.get("schema_version") != SCHEMA_VERSION
        or not isinstance(raw.get("dependencies"), list)
        or not isinstance(raw.get("profiles"), dict)
    ):
        raise ValueError("unsupported or malformed dependency manifest")
    seen: set[str] = set()
    for entry in raw["dependencies"]:
        if not isinstance(entry, dict) or not entry.get("id") or entry["id"] in seen:
            raise ValueError("dependency manifest contains an invalid or duplicate id")
        seen.add(entry["id"])
        if entry.get("kind") == "python-package" and not entry.get("minimum_version"):
            raise ValueError(f"dependency {entry['id']} has no minimum_version")
    external_tools = raw.get("external_tools", [])
    if not isinstance(external_tools, list):
        raise ValueError("dependency manifest external_tools must be a list")
    external_ids: set[str] = set()
    for entry in external_tools:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("id"), str)
            or entry["id"] in external_ids
            or not isinstance(entry.get("binary"), str)
            or not entry["binary"]
            or not isinstance(entry.get("version_args"), list)
            or any(not isinstance(arg, str) or "\x00" in arg for arg in entry["version_args"])
            or not isinstance(entry.get("version_regex"), str)
        ):
            raise ValueError("dependency manifest contains an invalid external-tool probe")
        try:
            re.compile(entry["version_regex"])
        except re.error as exc:
            raise ValueError("dependency manifest contains an invalid version regex") from exc
        external_ids.add(entry["id"])
    return raw


@dataclass(frozen=True)
class DependencyResult:
    id: str
    name: str
    kind: str
    required: bool
    status: str
    detected_version: str | None = None
    detected_path: str | None = None
    required_version: str | None = None
    capabilities: tuple[str, ...] = ()
    reason: str = ""
    remediation: str = ""
    path_candidates: tuple[str, ...] = ()
    path_conflict: bool = False
    executable_identity: dict[str, Any] | None = None


def _path_candidates(binary: str, selected: str | None) -> tuple[str, ...]:
    """List distinct executable candidates in PATH order without executing them."""
    candidates: list[str] = []
    extensions = [""]
    if os.name == "nt":
        extensions = [item.lower() for item in os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";")]
        if Path(binary).suffix:
            extensions = [""]
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        # Empty PATH entries mean the current directory; never treat cwd as an
        # implicit executable search location in diagnostics.
        if not entry:
            continue
        for extension in extensions:
            candidate = Path(entry) / (binary + extension)
            try:
                if candidate.is_file() and (os.name == "nt" or os.access(candidate, os.X_OK)):
                    resolved = os.path.realpath(candidate)
                    if resolved not in candidates:
                        candidates.append(resolved)
            except OSError:
                continue
    if selected:
        resolved_selected = os.path.realpath(selected)
        if resolved_selected not in candidates:
            candidates.insert(0, resolved_selected)
    return tuple(candidates)


def _executable_identity(path: str | None) -> dict[str, Any] | None:
    """Return a local file identity fingerprint, not a publisher/signature claim."""
    if not path:
        return None
    try:
        resolved = os.path.realpath(path)
        info = os.stat(resolved)
        if not os.path.isfile(resolved):
            return None
        identity = f"{resolved}\\0{info.st_dev}\\0{info.st_ino}\\0{info.st_size}\\0{info.st_mtime_ns}"
        return {
            "real_path": resolved,
            "size_bytes": info.st_size,
            "modified_ns": info.st_mtime_ns,
            "fingerprint": hashlib.sha256(identity.encode("utf-8", errors="surrogateescape")).hexdigest(),
            "identity_kind": "local-filesystem-metadata",
        }
    except OSError:
        return None


def _version_tuple(value: str) -> tuple[int, tuple[int, ...], int, int]:
    """Compare common PEP 440 release/prerelease forms without string coercion.

    Local build labels do not affect the minimum-version decision. Unknown
    version syntax fails closed instead of accidentally treating letters and
    digits as one numeric component.
    """
    match = re.fullmatch(
        r"\s*(?:([0-9]+)!)?(\d+(?:\.\d+)*)"
        r"(?:[-_.]?(a|alpha|b|beta|rc|pre|preview|dev|post)[-_.]?(\d*)?)?"
        r"(?:\+[a-zA-Z0-9.-]+)?\s*",
        value,
        re.IGNORECASE,
    )
    if not match:
        raise ValueError(f"unsupported version format: {value!r}")
    release = [int(part) for part in match.group(2).split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    label = (match.group(3) or "").lower()
    number = int(match.group(4) or 0)
    stage = {
        "dev": -3,
        "a": -2, "alpha": -2,
        "b": -1, "beta": -1,
        "rc": 0, "pre": 0, "preview": 0,
        "": 1,
        "post": 2,
    }[label]
    return (int(match.group(1) or 0), tuple(release), stage, number)


def _package_result(dist: str, import_name: str, minimum: str, *, required: bool,
                    capabilities: tuple[str, ...]) -> DependencyResult:
    try:
        version = importlib.metadata.version(dist)
    except importlib.metadata.PackageNotFoundError:
        return DependencyResult(
            dist, dist, "python-package", required, "MISSING",
            required_version=f">={minimum}", capabilities=capabilities,
            reason="Python distribution is not installed in the active interpreter.",
            remediation=f"Install the documented WHAXON extra or package containing {dist}.",
        )
    except Exception as exc:  # metadata providers can fail in broken environments
        return DependencyResult(
            dist, dist, "python-package", required, "BROKEN",
            required_version=f">={minimum}", capabilities=capabilities,
            reason=f"Package metadata could not be read ({type(exc).__name__}).",
        )
    if _version_tuple(version) < _version_tuple(minimum):
        status = "INCOMPATIBLE"
        reason = f"Installed version {version} is below required {minimum}."
    else:
        try:
            if importlib.util.find_spec(import_name) is None:
                raise ModuleNotFoundError(import_name)
        except Exception as exc:
            status = "BROKEN"
            reason = f"Package metadata exists but import failed ({type(exc).__name__})."
        else:
            status = "READY"
            reason = "Minimum version is satisfied and the package import specification is resolvable."
    return DependencyResult(
        dist, dist, "python-package", required, status, version,
        required_version=f">={minimum}", capabilities=capabilities,
        reason=reason,
        remediation="" if status == "READY" else f"Upgrade {dist} in the active environment.",
    )


def _environment() -> dict[str, Any]:
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "python_executable": sys.executable,
        "virtual_environment": bool(sys.prefix != getattr(sys, "base_prefix", sys.prefix)),
        "cwd": str(Path.cwd()),
        "path_entries": len(os.environ.get("PATH", "").split(os.pathsep)),
    }


def collect_dependency_report(*, data_dir: Path | None = None,
                               include_optional: bool = True,
                               include_external: bool = True,
                               verify_external: bool = False) -> dict[str, Any]:
    """Return a deterministic, read-only report; no install or network actions."""
    results: list[DependencyResult] = []
    python_version = platform.python_version()
    py_status = (
        "READY" if _version_tuple(python_version) >= _version_tuple("3.11")
        else "INCOMPATIBLE"
    )
    py_reason = (
        "Python runtime satisfies the declared minimum."
        if py_status == "READY"
        else f"Python {python_version} is below the required 3.11 runtime."
    )
    results.append(DependencyResult(
        "python", "Python", "runtime", True, py_status, python_version,
        sys.executable, ">=3.11", ("core", "cli", "web", "tui", "gui"), py_reason,
        "Install Python 3.11 or newer and run WHAXON with that interpreter."
        if py_status != "READY" else "",
    ))
    manifest: dict[str, Any] | None = None
    try:
        manifest = load_dependency_manifest()
        for entry in manifest["dependencies"]:
            if entry.get("kind") != "python-package":
                continue
            if not include_optional and not entry.get("required", False):
                continue
            capabilities = tuple(entry.get("capabilities") or ["core"])
            results.append(_package_result(
                entry["id"], entry.get("import_name", entry["id"]), entry["minimum_version"],
                required=bool(entry.get("required")), capabilities=capabilities,
            ))
    except (OSError, ValueError, TypeError, KeyError) as exc:
        results.append(DependencyResult(
            "dependency-manifest", "Dependency manifest", "resource", True, "BROKEN",
            reason=f"Dependency manifest unavailable or invalid ({type(exc).__name__}).",
            remediation="Restore a valid packaged dependencies.json manifest.",
        ))

    external_probe_specs = {
        item["id"]: item for item in manifest.get("external_tools", [])
    } if manifest is not None else {}
    catalog_path = (Path(data_dir) / "tools.json") if data_dir else (
        Path(__file__).resolve().parents[1] / "data" / "tools.json"
    )
    if include_external and not catalog_path.is_file():
        packaged_catalog = Path(__file__).resolve().parents[1] / "data" / "tools.json"
        if packaged_catalog.is_file():
            catalog_path = packaged_catalog
    if include_external and catalog_path.is_file():
        try:
            raw = json.loads(catalog_path.read_text(encoding="utf-8"))
            tools = raw.get("tools") if isinstance(raw, dict) else None
            if not isinstance(tools, list):
                raise ValueError("tool catalog must contain a tools list")
            for tool in tools:
                if not isinstance(tool, dict):
                    raise ValueError("tool catalog contains a non-object tool entry")
                binary = str(tool.get("binary") or "")
                transport = str(tool.get("transport") or "cli")
                if not binary or transport != "cli":
                    continue
                path = shutil.which(binary)
                candidates = _path_candidates(binary, path)
                identity = _executable_identity(path)
                path_conflict = len(candidates) > 1
                tool_id = str(tool.get("id") or binary)
                status = "DETECTED" if path else "MISSING"
                version = None
                reason = (
                    "Executable resolved on PATH; version and functional behavior are not yet verified."
                    if path else f"Executable '{binary}' was not found on PATH."
                )
                if path and identity is None:
                    status = "BROKEN"
                    reason = "Executable resolved on PATH but its filesystem identity could not be inspected."
                probe = external_probe_specs.get(tool_id)
                # The writable tool catalog may discover binaries, but it must
                # never redirect a trusted probe to a different executable.
                if probe and probe.get("binary") != binary:
                    probe = None
                if path and verify_external:
                    if probe is None:
                        reason = "Executable detected; no trusted version probe is configured."
                    elif identity is None:
                        reason = "Executable identity could not be inspected; trusted version probe was not run."
                    else:
                        try:
                            completed = subprocess.run(
                                [path, *probe["version_args"]], shell=False, check=False,
                                capture_output=True, text=True, timeout=8,
                                stdin=subprocess.DEVNULL,
                            )
                            output = ((completed.stdout or "") + "\\n" + (completed.stderr or ""))[:8192]
                            match = re.search(probe["version_regex"], output, re.IGNORECASE)
                            if completed.returncode == 0 and match:
                                version = match.group(1) if match.lastindex else match.group(0)
                                if path_conflict:
                                    status = "BROKEN"
                                    reason = (
                                        "Trusted version probe succeeded, but multiple distinct executables "
                                        "are present on PATH; resolve the ambiguity before use."
                                    )
                                else:
                                    status = "READY"
                                    reason = "Trusted version probe succeeded."
                            else:
                                status = "BROKEN"
                                reason = (
                                    "Trusted version probe did not confirm the expected version "
                                    f"(exit code {completed.returncode})."
                                )
                        except subprocess.TimeoutExpired:
                            status = "BROKEN"
                            reason = "Trusted version probe timed out after 8 seconds."
                        except OSError as exc:
                            status = "BROKEN"
                            reason = f"Trusted version probe could not execute ({type(exc).__name__})."
                if path_conflict:
                    reason += (
                        f" PATH ambiguity: {len(candidates)} distinct executable candidates were found; "
                        "the first PATH entry is selected. Review the candidate paths before use."
                    )
                results.append(DependencyResult(
                    tool_id, str(tool.get("name") or tool_id), "external-tool", False,
                    status,
                    detected_version=version,
                    detected_path=path,
                    capabilities=(f"tool:{tool_id}",),
                    reason=reason,
                    remediation=(
                        "Review PATH order and remove unintended duplicate executables before use."
                        if path_conflict else
                        ("" if status in {"READY", "DETECTED"} else
                         "Use the platform's trusted package source or official project instructions; "
                         "WHAXON has not attempted an installation.")
                    ),
                    path_candidates=candidates,
                    path_conflict=path_conflict,
                    executable_identity=identity,
                ))
        except (OSError, ValueError, TypeError) as exc:
            results.append(DependencyResult(
                "tool-catalog", "Tool catalog", "resource", True, "BROKEN",
                reason=f"Could not read tool catalog ({type(exc).__name__}).",
            ))
    elif include_external:
        results.append(DependencyResult(
            "tool-catalog", "Tool catalog", "resource", True, "MISSING",
            reason=f"Tool catalog not found at {catalog_path}.",
            remediation="Restore the packaged tools.json resource or initialize the WHAXON data directory.",
        ))

    # Packaged validation payloads are mandatory runtime resources. Check them
    # independently of optional external-tool discovery and never fetch replacements.
    payload_dir = Path(__file__).resolve().parents[1] / "data" / "payloads"
    try:
        payload_files = [item for item in payload_dir.rglob("*") if item.is_file()]
        if not payload_dir.is_dir() or not payload_files:
            raise FileNotFoundError("payload directory is missing or empty")
    except OSError as exc:
        results.append(DependencyResult(
            "validation-payloads", "Validation payloads", "resource", True, "BROKEN",
            reason=f"Packaged validation payloads could not be inspected ({type(exc).__name__}).",
            remediation="Restore the packaged whaxon/data/payloads resources from the release artifact.",
        ))
    else:
        results.append(DependencyResult(
            "validation-payloads", "Validation payloads", "resource", True, "READY",
            reason=f"{len(payload_files)} packaged validation resource file(s) are present.",
        ))

    required_bad = [r for r in results if r.required and r.status != "READY"]
    optional_bad = [r for r in results if not r.required and r.status != "READY"]
    overall = "BLOCKED" if required_bad else ("DEGRADED" if optional_bad else "READY")
    return {
        "schema_version": SCHEMA_VERSION,
        "environment": _environment(),
        "overall_status": overall,
        "summary": {
            "total": len(results),
            "ready": sum(r.status == "READY" for r in results),
            "missing": sum(r.status == "MISSING" for r in results),
            "detected_unverified": sum(r.status == "DETECTED" for r in results),
            "incompatible": sum(r.status == "INCOMPATIBLE" for r in results),
            "broken": sum(r.status == "BROKEN" for r in results),
            "required_blockers": len(required_bad),
            "optional_degraded": len(optional_bad),
        },
        "dependencies": [asdict(r) for r in results],
        "safety": {
            "read_only": True,
            "installation_attempted": False,
            "network_accessed": False,
            "privilege_escalation_attempted": False,
        },
    }
