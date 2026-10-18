"""Executor ok reflects tool exit code."""

def test_tool_nonzero_exit_marks_result_not_ok():
    """A tool that ran but exited non-zero is ok=False.

    Before this fix the executor set ok=True whenever the tool ran,
    regardless of exit code. nuclei fataling on missing templates was
    reported as success, and the ladder moved to the next phase.
    """
    import asyncio

    from whaxon.ai import ExecutorLimits
    from whaxon.ai.actions import Action
    from whaxon.ai.executor import Executor
    from whaxon.ai.provider import Provider

    class One(Provider):
        name = "one"
        def plan_step(self, goal, history, catalog, scope_summary, step,
                      max_steps, phase="recon", prior_runs=None):
            if step == 1:
                return Action.run_tool("echo", "127.0.0.1", ai_source="one")
            return Action.stop("done", ai_source="one")

    async def run_tool(tool_id, target, extra, job_id):
        return "job1"
    ex = Executor(
        agent=__import__("whaxon.ai.agent", fromlist=["Agent"]).Agent(provider=One()),
        catalog_lookup=lambda tid: {"id": tid},
        scope_check=lambda t: (True, ""),
        run_tool=run_tool,
        get_findings=lambda jid: [],
        catalog_all=lambda: [{"id": "echo"}],
        scope_summary=lambda: {},
        limits=ExecutorLimits(max_steps=5),
        get_job=lambda jid: {"exit_code": 1},
    )
    hist = asyncio.run(ex.run(goal="t", job_id_prefix="j"))
    tool_result = [r for r in hist if r.action.kind == "run_tool"][0]
    assert tool_result.ok is False
    assert "exit" in (tool_result.error or "").lower() or tool_result.error == ""
