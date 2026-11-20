"""Versioned, immutable contracts for Engine v2 mission plans.

AI may propose these objects; policy and the scheduler remain responsible for
authorizing and executing them.
"""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass, field
from typing import Any

WORKFLOW_SCHEMA_VERSION = "whaxon.workflow.v1"
_ALLOWED_IMPACTS = {"read_only", "low", "moderate", "high", "critical"}


class _FrozenDict(dict):
    """JSON-serializable dictionary that rejects mutation after construction."""

    def __init__(self, value=()):
        dict.__init__(self, ((key, _freeze(item)) for key, item in dict(value).items()))

    def _immutable(self, *args, **kwargs):
        raise TypeError("workflow contract mappings are immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    clear = _immutable
    pop = _immutable
    popitem = _immutable
    setdefault = _immutable
    update = _immutable

    def __deepcopy__(self, memo):
        return self


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return _FrozenDict(value)
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_freeze(item) for item in value)
    return value


def _require_json_contract(value: Any, *, label: str, depth: int = 0,
                           active: set[int] | None = None) -> None:
    """Validate deterministic JSON before freezing or persisting a contract."""
    if depth > 64:
        raise ValueError(f"{label} exceeds maximum nesting depth")
    if value is None or type(value) in (str, bool, int):
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError(f"{label} must contain only finite numbers")
        return
    if not isinstance(value, (dict, list, tuple)):
        raise TypeError(f"{label} must contain only JSON-compatible values")
    if active is None:
        active = set()
    identity = id(value)
    if identity in active:
        raise ValueError(f"{label} must not contain circular references")
    active.add(identity)
    try:
        if isinstance(value, dict):
            for key, item in value.items():
                if not isinstance(key, str):
                    raise TypeError(f"{label} mapping keys must be strings")
                _require_json_contract(
                    item, label=label, depth=depth + 1, active=active,
                )
        else:
            for item in value:
                _require_json_contract(
                    item, label=label, depth=depth + 1, active=active,
                )
    finally:
        active.remove(identity)


def _canonical(value: Any) -> str:
    _require_json_contract(value, label="workflow contract")
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    )


@dataclass(frozen=True)
class WorkflowTask:
    """One typed node in a mission DAG; it contains no executable shell text."""

    id: str
    capability_id: str
    target: str
    inputs: dict[str, Any] = field(default_factory=dict)
    depends_on: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()
    impact: str = "read_only"
    timeout_s: float = 300.0
    idempotency_key: str = ""

    def __post_init__(self) -> None:
        if any(not isinstance(value, str) or not value.strip() for value in (self.id, self.capability_id, self.target)):
            raise ValueError("task id, capability_id and target are required")
        if self.impact not in _ALLOWED_IMPACTS:
            raise ValueError(f"unsupported task impact: {self.impact}")
        if (
            isinstance(self.timeout_s, bool)
            or not isinstance(self.timeout_s, (int, float))
            or not math.isfinite(self.timeout_s)
            or self.timeout_s <= 0
        ):
            raise ValueError("task timeout_s must be finite and positive")
        if not isinstance(self.depends_on, (list, tuple)) or not isinstance(self.permissions, (list, tuple)):
            raise TypeError("task dependencies and permissions must be arrays")
        if not isinstance(self.idempotency_key, str):
            raise TypeError("task idempotency_key must be a string")
        dependencies = tuple(self.depends_on)
        permissions = tuple(self.permissions)
        if self.id in dependencies or len(set(dependencies)) != len(dependencies):
            raise ValueError("task dependencies must be unique and cannot include itself")
        if any(not isinstance(item, str) or not item.strip() for item in dependencies + permissions):
            raise ValueError("task dependencies and permissions must be non-empty strings")
        object.__setattr__(self, "depends_on", dependencies)
        object.__setattr__(self, "permissions", permissions)
        if not isinstance(self.inputs, dict):
            raise TypeError("task inputs must be an object")
        _require_json_contract(self.inputs, label="task inputs")
        object.__setattr__(self, "inputs", _freeze(self.inputs))

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["depends_on"] = list(self.depends_on)
        value["permissions"] = list(self.permissions)
        return value

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> WorkflowTask:
        if not isinstance(value, dict):
            raise TypeError("workflow task must be an object")
        for key in ("id", "capability_id", "target"):
            if key not in value:
                raise ValueError(f"workflow task missing required field: {key}")
        return cls(
            id=value["id"],
            capability_id=value["capability_id"],
            target=value["target"],
            inputs=value.get("inputs", {}),
            depends_on=value.get("depends_on", ()),
            permissions=value.get("permissions", ()),
            impact=value.get("impact", "read_only"),
            timeout_s=value.get("timeout_s", 300.0),
            idempotency_key=value.get("idempotency_key", ""),
        )


@dataclass(frozen=True)
class WorkflowPlan:
    """Immutable versioned DAG. Its digest binds approvals to exact task content."""

    mission_id: str
    tasks: tuple[WorkflowTask, ...]
    schema_version: str = WORKFLOW_SCHEMA_VERSION
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.schema_version != WORKFLOW_SCHEMA_VERSION:
            raise ValueError(f"unsupported workflow schema: {self.schema_version}")
        if not isinstance(self.tasks, (list, tuple)) or any(
            not isinstance(task, WorkflowTask) for task in self.tasks
        ):
            raise TypeError("plan tasks must be an array of workflow tasks")
        object.__setattr__(self, "tasks", tuple(self.tasks))
        if not isinstance(self.mission_id, str) or not self.mission_id.strip():
            raise ValueError("mission_id is required")
        if not isinstance(self.metadata, dict):
            raise TypeError("plan metadata must be an object")
        _require_json_contract(self.metadata, label="plan metadata")
        object.__setattr__(self, "metadata", _freeze(self.metadata))
        ids = [task.id for task in self.tasks]
        if not ids or len(ids) != len(set(ids)):
            raise ValueError("a plan requires uniquely identified tasks")
        known = set(ids)
        for task in self.tasks:
            missing = set(task.depends_on) - known
            if missing:
                raise ValueError(f"task {task.id} has unknown dependencies: {sorted(missing)}")
        # Kahn's algorithm rejects cycles before a plan can be persisted.
        remaining = {task.id: set(task.depends_on) for task in self.tasks}
        ready = [task_id for task_id, deps in remaining.items() if not deps]
        visited = 0
        while ready:
            current = ready.pop()
            visited += 1
            for task_id, deps in remaining.items():
                if current in deps:
                    deps.remove(current)
                    if not deps:
                        ready.append(task_id)
        if visited != len(remaining):
            raise ValueError("workflow plan contains a dependency cycle")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "mission_id": self.mission_id,
            "metadata": self.metadata,
            "tasks": [task.to_dict() for task in self.tasks],
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(_canonical(self.to_dict()).encode("utf-8")).hexdigest()

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> WorkflowPlan:
        if not isinstance(value, dict):
            raise TypeError("workflow plan must be an object")
        for key in ("mission_id", "tasks"):
            if key not in value:
                raise ValueError(f"workflow plan missing required field: {key}")
        if not isinstance(value["tasks"], list):
            raise TypeError("workflow plan tasks must be an array")
        return cls(
            mission_id=value["mission_id"],
            schema_version=value.get("schema_version", WORKFLOW_SCHEMA_VERSION),
            metadata=value.get("metadata", {}),
            tasks=tuple(WorkflowTask.from_dict(task) for task in value["tasks"]),
        )


@dataclass(frozen=True)
class ApprovalBinding:
    """Approval is valid only for this exact plan/task/policy/expiry tuple."""

    plan_digest: str
    task_id: str
    target: str
    input_digest: str
    policy_version: str
    expires_at: float
    permissions: tuple[str, ...] = ()
    impact: str = "read_only"

    @staticmethod
    def digest_inputs(inputs: dict[str, Any]) -> str:
        return hashlib.sha256(_canonical(inputs).encode("utf-8")).hexdigest()

    def is_valid(self, *, plan_digest: str, task: WorkflowTask,
                 policy_version: str, now: float) -> bool:
        return (
            math.isfinite(self.expires_at)
            and now < self.expires_at
            and self.plan_digest == plan_digest
            and self.task_id == task.id
            and self.target == task.target
            and self.input_digest == self.digest_inputs(task.inputs)
            and self.policy_version == policy_version
            and self.permissions == task.permissions
            and self.impact == task.impact
        )
