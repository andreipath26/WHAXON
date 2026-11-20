"""E2 workflow schema rejects ambiguous or non-JSON task and plan values."""
import pytest

from whaxon.core.workflow import ApprovalBinding, WorkflowPlan, WorkflowTask


@pytest.mark.parametrize("payload", [
    {"rate": float("nan")},
    {"rate": float("inf")},
    {"nested": [{"rate": -float("inf")}]},
    {"not-json": {1, 2}},
    {"bad-key": {1: "numeric map key"}},
    {"nested-key": [{"value": {False: 1}}]},
])
def test_e2_task_rejects_unsafe_or_ambiguous_json_values(payload):
    with pytest.raises((ValueError, TypeError), match="task inputs"):
        WorkflowTask("a", "fixture", "192.0.2.1", inputs=payload)


@pytest.mark.parametrize("metadata", [
    {"rate": float("nan")},
    {"rate": float("-inf")},
    {"value": object()},
    {"children": [{"invalid": {0: "integer key"}}]},
])
def test_e2_plan_rejects_unsafe_metadata_before_digest(metadata):
    task = WorkflowTask("a", "fixture", "192.0.2.1")
    with pytest.raises((ValueError, TypeError), match="plan metadata"):
        WorkflowPlan("mission", (task,), metadata=metadata)


def test_e2_circular_task_input_is_rejected_instead_of_recursing():
    circular = {}
    circular["child"] = circular
    with pytest.raises(ValueError, match="circular"):
        WorkflowTask("a", "fixture", "192.0.2.1", inputs=circular)


def test_e2_plan_metadata_depth_has_explicit_limit():
    nested = {}
    for _ in range(65):
        nested = {"child": nested}
    with pytest.raises(ValueError, match="nesting depth"):
        WorkflowPlan(
            "mission", (WorkflowTask("a", "fixture", "192.0.2.1"),),
            metadata=nested,
        )


def test_e2_shared_references_are_valid_and_stably_canonicalized():
    nested = {"ports": [80, 443]}
    task = WorkflowTask(
        "a", "fixture", "192.0.2.1", inputs={"a": nested, "b": nested},
    )
    plan = WorkflowPlan("mission", (task,))
    restored = WorkflowPlan.from_dict(plan.to_dict())
    assert restored.digest == plan.digest
    assert ApprovalBinding.digest_inputs(task.inputs) == ApprovalBinding.digest_inputs(
        restored.tasks[0].inputs,
    )


def test_e2_approval_input_digest_never_serializes_nan_as_json_extension():
    with pytest.raises(ValueError, match="finite"):
        ApprovalBinding.digest_inputs({"result": float("nan")})
