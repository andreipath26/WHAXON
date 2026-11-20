"""Typed internal contracts for the existing HTTP API.

These models validate values at the Flask boundary without defining routes or
changing the public request and response representation. Request variants model
the existing JSON bodies, including their strict fields and defaults; response
models preserve selected existing serialized shapes.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class WorkflowRunRequest(BaseModel):
    """Execution limits accepted by the existing workflow-run endpoint."""

    model_config = ConfigDict(strict=True, extra="ignore")

    max_tasks: int = Field(default=100, ge=1, le=1000)
    max_attempts: int = Field(default=2, ge=1, le=1000)
    max_concurrency: int = Field(default=4, ge=1, le=1000)


class WorkflowToolProposalRequest(BaseModel):
    """Fixed catalog-tool proposal accepted by the existing V2 route."""

    model_config = ConfigDict(strict=True, extra="forbid")

    kind: Literal["tool"]
    mission_id: str
    id: str
    tool: str
    target: str
    save: bool = False


class WorkflowFindingProposalRequest(BaseModel):
    """Sealed-finding verification or retest proposal request."""

    model_config = ConfigDict(strict=True, extra="forbid")

    kind: Literal["verification"]
    mission_id: str
    id: str
    source_job_id: str
    finding_seq: int = Field(ge=0)
    mode: str
    save: bool = False


class ExecutionLimitsRequest(BaseModel):
    """Tightening-only mission or workflow attempt/concurrency limits."""

    model_config = ConfigDict(strict=True, extra="ignore")

    max_total_attempts: int = Field(ge=1)
    max_concurrency: int = Field(ge=1)


class RateLimitRequest(BaseModel):
    """Positive finite dispatch spacing accepted by existing rate-limit routes."""

    model_config = ConfigDict(strict=True, extra="ignore")

    min_spacing_s: float = Field(gt=0, allow_inf_nan=False)


class DeadlineRequest(BaseModel):
    """Positive finite Unix timestamp accepted by existing deadline routes."""

    model_config = ConfigDict(strict=True, extra="ignore")

    deadline_at: float = Field(gt=0, allow_inf_nan=False)


class MissionCostLimitRequest(BaseModel):
    """Nonnegative integer USD-micro cap accepted by the mission cost route."""

    model_config = ConfigDict(strict=True, extra="ignore")

    max_cost_microusd: int = Field(ge=0)


class WorkflowApprovalGrantRequest(BaseModel):
    """Operator consent input accepted by the existing approval route."""

    model_config = ConfigDict(strict=True, extra="ignore")

    task_key: str
    approval_id: str
    expires_at: float = Field(allow_inf_nan=False)


class WorkflowAttemptReconciliationRequest(BaseModel):
    """Manual reconciliation evidence for one uncertain provider attempt."""

    model_config = ConfigDict(strict=True, extra="ignore")

    attempt_id: str
    disposition: str
    evidence_ref: str
    note: str


class WorkflowPlanReconciliationRequest(BaseModel):
    """Lease timeout used when reconciling stale workflow attempts."""

    model_config = ConfigDict(strict=True, extra="ignore")

    stale_after_s: float = Field(default=60.0, allow_inf_nan=False)


class WorkflowRunAccepted(BaseModel):
    """The unchanged 202 response returned by the workflow-run endpoint."""

    model_config = ConfigDict(strict=True, extra="forbid")

    plan_id: str
    run_request_id: str
    request_status: str
    execution_submitted: bool
    execution_completed: bool
    durable_progress_url: str
    run_request_url: str
    run_snapshot_url: str


class WorkflowEventAcknowledgement(BaseModel):
    """The existing durable-event acknowledgement request shape."""

    model_config = ConfigDict(strict=True, extra="ignore")

    consumer: str
    event_id: int


class WorkflowEventAcknowledgementResult(BaseModel):
    """The unchanged event acknowledgement response shape."""

    model_config = ConfigDict(strict=True, extra="forbid")

    plan_id: str
    consumer_id: str
    last_event_id: int
