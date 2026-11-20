"""Keep legacy direct dispatch callers explicit until each is migrated or retired."""
from __future__ import annotations

import ast
import json
import re
from collections import Counter
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src" / "whaxon"

EXPECTED_CATALOG_TRANSPORTS = {
    "nmap": "cli",
    "nikto": "cli",
    "gobuster": "cli",
    "echo": "cli",
    "sqlmap": "cli",
    "whois": "cli",
    "dig": "cli",
    "nuclei": "cli",
    "commix": "cli",
    "ffuf": "cli",
    "wpscan": "cli",
    "impacket": "cli",
    "theharvester": "cli",
    "dnsrecon": "cli",
    "msf_sysinfo": "msf_session",
    "msf_getuid": "msf_session",
    "msf_hashdump": "msf_session",
    "ssh_cmd": "ssh",
    "smb_shares": "smb",
    "smb_ls": "smb",
    "netexec": "cli",
    "arjun": "cli",
    "hydra": "cli",
    "wmi_exec": "wmi",
}
EXPECTED_V2_TARGET_TYPES = {
    "arjun": ("url",),
    "dig": ("hostname",),
    "dnsrecon": ("hostname",),
    "ffuf": ("url",),
    "gobuster": ("hostname", "ip"),
    "nikto": ("hostname", "ip", "url"),
    "nmap": ("hostname", "ip"),
    "nuclei": ("url",),
    "sqlmap": ("url",),
    "theharvester": ("hostname",),
    "whois": ("hostname", "ip"),
    "wpscan": ("url",),
}
EXPECTED_V2_SEMANTIC_OPERATIONS = {
    "arjun": "web.parameters.discover",
    "dig": "dns.records.query",
    "dnsrecon": "dns.records.enumerate",
    "ffuf": "web.paths.fuzz",
    "gobuster": "web.directories.enumerate",
    "nikto": "web.server.audit",
    "nmap": "network.services.discover",
    "nuclei": "web.templates.assess",
    "sqlmap": "web.sql_injection.assess",
    "theharvester": "osint.domain.contacts.search",
    "whois": "domain.registration.lookup",
    "wpscan": "web.wordpress.audit",
}

# (source path, containing function path, method) -> number of syntactic calls.
# Core/providers.py contains both the catalog bridge's ToolRunner dispatch and
# the separately bounded scheduler-owned validator calls. Keep each service
# entry explicit; neither is a legacy CLI/web caller.
EXPECTED_RUNNER_CALLS = Counter(
    {
        ("ai/executor.py", "_validate_and_run", "run_tool"): 1,
        ("ai/executor.py", "_validate_and_run", "run_in_session"): 1,
        ("ai/providers/llm.py", "_to_action", "run_tool"): 1,
        ("ai/providers/rules.py", "plan_step", "run_tool"): 5,
        ("ai/providers/rules.py", "plan_step", "run_in_session"): 1,
        ("core/ai_bridge.py", "_run_tool", "run_tool"): 1,
        ("core/ai_bridge.py", "build_executor._run_in_session", "run_in_session"): 1,
        ("core/providers.py", "dispatch", "run_tool"): 1,
        ("core/worker.py", "drain_async", "run_tool"): 1,
        ("interfaces/cli/run_cmd.py", "main._go", "run_tool"): 1,
        ("interfaces/cli/run_cmd.py", "main._go", "run_in_session"): 1,
        ("interfaces/gui/main_window.py", "_run_tool", "run_tool"): 2,
        ("interfaces/web/server.py", "_run_job_blocking", "run_tool"): 1,
    }
)

# These services can perform network work without entering ToolRunner. Keep
# their public execution entry points visible separately from runner calls.
EXPECTED_SERVICE_CALLS = Counter(
    {
        ("interfaces/cli/recon_cmd.py", "main", "core.recon.run"): 1,
        ("interfaces/web/server.py", "create_app.api_validate", "v.validate"): 1,
        ("interfaces/web/server.py", "create_app.api_retest", "v.revalidate"): 1,
        ("interfaces/web/server.py", "create_app.msf_run._do_run", "adapter.run_module"): 1,
        ("interfaces/web/server.py", "create_app.msf_session_exec", "client.session_exec"): 1,
        ("core/runner.py", "_run_msf_session", "client.session_exec"): 1,
        ("adapters/msf.py", "run_module", "self._client.execute"): 2,
        ("core/validator.py", "revalidate", "self.validate"): 1,
        ("core/providers.py", "dispatch", "validator.validate"): 1,
        ("core/providers.py", "dispatch", "validator.revalidate"): 1,
    }
)

# Pin every Flask API method/path/handler binding. UI page routes are excluded;
# their ownership is frozen and tracked by the separate UI inventory.
EXPECTED_API_ROUTE_HANDLERS = {
    ('DELETE', '/api/jobs/<job_id>/evidence/<int:seq>'): 'delete_evidence',
    ('DELETE', '/api/msf/sessions/<session_id>/portfwd'): 'pf_del',
    ('GET', '/api/ai/pending'): 'ai_pending_list',
    ('GET', '/api/ai/runs'): 'ai_runs_list',
    ('GET', '/api/ai/runs/<run_id>'): 'ai_run_get',
    ('GET', '/api/ai/runs/<run_id>/stream'): 'ai_run_stream',
    ('GET', '/api/coverage/<job_id>'): 'api_coverage',
    ('GET', '/api/dependencies'): 'api_dependencies_get',
    ('GET', '/api/dependencies/audit'): 'api_dependencies_audit_get',
    ('GET', '/api/dependencies/drift'): 'api_dependencies_drift_get',
    ('GET', '/api/dependencies/history'): 'api_dependencies_history_get',
    ('GET', '/api/dependencies/install/<operation_id>'): 'api_dependencies_install_status',
    ('GET', '/api/health'): 'health_probe',
    ('GET', '/api/health/simple'): 'health_simple',
    ('GET', '/api/history'): 'list_history',
    ('GET', '/api/jobs/<job_id>'): 'get_job',
    ('GET', '/api/jobs/<job_id>/evidence'): 'list_evidence',
    ('GET', '/api/jobs/<job_id>/evidence/<int:seq>/download'): 'download_evidence',
    ('GET', '/api/jobs/<job_id>/findings'): 'get_job_findings',
    ('GET', '/api/jobs/<job_id>/findings.csv'): 'download_findings_csv',
    ('GET', '/api/jobs/<job_id>/findings.json'): 'download_findings_json',
    ('GET', '/api/jobs/<job_id>/output.txt'): 'download_output_txt',
    ('GET', '/api/jobs/<job_id>/report'): 'get_report',
    ('GET', '/api/jobs/<job_id>/stream'): 'stream_job',
    ('GET', '/api/jobs/active'): 'list_active_jobs',
    ('GET', '/api/loot'): 'api_loot',
    ('GET', '/api/msf/modules/<module_type>'): 'msf_list_modules',
    ('GET', '/api/msf/sessions'): 'msf_sessions',
    ('GET', '/api/msf/sessions/<session_id>'): 'msf_session_info',
    ('GET', '/api/msf/sessions/<session_id>/portfwd'): 'pf_list',
    ('GET', '/api/msf/status'): 'msf_status',
    ('GET', '/api/pivot/candidates'): 'api_pivot_candidates',
    ('GET', '/api/pivot/graph'): 'api_pivot_graph',
    ('GET', '/api/pivot/sessions/<session_id>/chain'): 'api_pivot_chain',
    ('GET', '/api/report'): 'api_report',
    ('GET', '/api/scope'): 'get_scope',
    ('GET', '/api/settings'): 'api_settings_get',
    ('GET', '/api/status'): 'api_status',
    ('GET', '/api/tools'): 'list_tools',
    ('GET', '/api/tree'): 'get_tree',
    ('GET', '/api/ui-v2/findings'): 'api_ui_v2_findings',
    ('GET', '/api/v2/capabilities'): 'workflow_v2_capabilities',
    ('POST', '/api/v2/ai/proposals'): 'workflow_v2_ai_proposal',
    ('POST', '/api/v2/workflow-proposals'): 'workflow_v2_workflow_proposal',
    ('GET', '/api/v2/missions'): 'workflow_v2_missions',
    ('GET', '/api/v2/missions/<mission_id>/budget'): 'workflow_v2_mission_budget',
    ('GET', '/api/v2/missions/<mission_id>/cost'): 'workflow_v2_mission_cost',
    ('GET', '/api/v2/missions/<mission_id>/plans'): 'workflow_v2_mission_plans',
    ('GET', '/api/v2/missions/<mission_id>/report'): 'workflow_v2_mission_report',
    ('GET', '/api/v2/missions/<mission_id>/rate-limit'): 'workflow_v2_mission_rate_limit',
    ('GET', '/api/v2/providers'): 'workflow_v2_providers',
    ('GET', '/api/v2/providers/portfolio-audit'): 'workflow_v2_portfolio_audit',
    ('GET', '/api/v2/workflow-runs/<request_id>'): 'workflow_v2_run_request_status',
    ('GET', '/api/v2/workflow-runs/<request_id>/snapshot'): 'workflow_v2_run_snapshot',
    ('GET', '/api/v2/workflow-runs/summary'): 'workflow_v2_run_queue_summary',
    ('GET', '/api/v2/workflows/<plan_id>'): 'workflow_v2_plan_details',
    ('GET', '/api/v2/workflows/<plan_id>/approvals'): 'workflow_v2_approvals',
    ('GET', '/api/v2/approval-queue'): 'workflow_v2_approval_queue',
    ('GET', '/api/v2/workflows/<plan_id>/attempts'): 'workflow_v2_attempts',
    ('GET', '/api/v2/workflows/<plan_id>/audit'): 'workflow_v2_audit',
    ('GET', '/api/v2/workflows/<plan_id>/event-inbox'): 'workflow_v2_event_inbox',
    ('GET', '/api/v2/workflows/<plan_id>/events'): 'workflow_v2_events',
    ('GET', '/api/v2/workflows/<plan_id>/evidence'): 'workflow_v2_evidence',
    ('GET', '/api/v2/workflows/<plan_id>/limits'): 'workflow_v2_limits',
    ('GET', '/api/v2/workflows/<plan_id>/progress'): 'workflow_v2_progress',
    ('GET', '/api/v2/workflows/<plan_id>/report'): 'workflow_v2_plan_report',
    ('GET', '/api/v2/workflows/<plan_id>/audit-snapshot'): 'workflow_v2_audit_snapshot',
    ('GET', '/api/v2/workflows/<plan_id>/readiness'): 'workflow_v2_readiness',
    ('GET', '/api/v2/workflows/<plan_id>/reconciliation'): 'workflow_v2_reconciliation',
    ('GET', '/api/v2/workflows/<plan_id>/resources'): 'workflow_v2_resources',
    ('POST', '/api/ai/run'): 'ai_run',
    ('POST', '/api/ai/runs/<run_id>/answer'): 'ai_run_answer',
    ('POST', '/api/approvals/<job_id>/<int:seq>/resolve'): 'api_approval_resolve',
    ('POST', '/api/bounty/import'): 'import_bounty_program',
    ('POST', '/api/dependencies/install'): 'api_dependencies_install',
    ('POST', '/api/dependencies/install-batch'): 'api_dependencies_install_batch',
    ('POST', '/api/dependencies/install/<operation_id>/cancel'): 'api_dependencies_install_cancel',
    ('POST', '/api/dependencies/plan'): 'api_dependencies_plan',
    ('POST', '/api/dependencies/snapshots'): 'api_dependencies_snapshot_post',
    ('POST', '/api/dependencies/verify'): 'api_dependencies_verify_post',
    ('POST', '/api/import/burp'): 'import_burp',
    ('POST', '/api/jobs/<job_id>/cancel'): 'cancel_job',
    ('POST', '/api/jobs/<job_id>/evidence'): 'add_evidence',
    ('POST', '/api/msf/run'): 'msf_run',
    ('POST', '/api/msf/sessions/<session_id>/exec'): 'msf_session_exec',
    ('POST', '/api/msf/sessions/<session_id>/portfwd'): 'pf_add',
    ('POST', '/api/retest/<job_id>/<int:seq>'): 'api_retest',
    ('POST', '/api/run'): 'run_tool',
    ('POST', '/api/scope'): 'save_scope',
    ('POST', '/api/scope/check'): 'check_scope',
    ('POST', '/api/scope/override'): 'log_override',
    ('POST', '/api/settings'): 'api_settings_post',
    ('POST', '/api/v2/missions'): 'workflow_v2_missions',
    ('POST', '/api/v2/missions/<mission_id>/budget'): 'workflow_v2_mission_budget',
    ('POST', '/api/v2/missions/<mission_id>/cost'): 'workflow_v2_mission_cost',
    ('POST', '/api/v2/missions/<mission_id>/deadline'): 'workflow_v2_mission_deadline',
    ('POST', '/api/v2/missions/<mission_id>/rate-limit'): 'workflow_v2_mission_rate_limit',
    ('POST', '/api/v2/scope/check'): 'check_v2_authoring_scope',
    ('POST', '/api/v2/workflow-runs/<request_id>/cancel'): 'workflow_v2_cancel_run_request',
    ('POST', '/api/v2/workflows'): 'workflow_v2_save_plan',
    ('POST', '/api/v2/workflows/<plan_id>/approvals'): 'workflow_v2_approvals',
    ('POST', '/api/v2/workflows/<plan_id>/approvals/<approval_id>/revoke'): 'workflow_v2_revoke_approval',
    ('POST', '/api/v2/workflows/<plan_id>/cancel'): 'workflow_v2_cancel',
    ('POST', '/api/v2/workflows/<plan_id>/followups'): 'workflow_v2_followups',
    ('POST', '/api/v2/workflows/<plan_id>/deadline'): 'workflow_v2_set_deadline',
    ('POST', '/api/v2/workflows/<plan_id>/event-ack'): 'workflow_v2_event_ack',
    ('POST', '/api/v2/workflows/<plan_id>/limits'): 'workflow_v2_set_limits',
    ('POST', '/api/v2/workflows/<plan_id>/rate-limit'): 'workflow_v2_set_rate_limit',
    ('POST', '/api/v2/workflows/<plan_id>/audit-verify'): 'workflow_v2_audit_verify',
    ('POST', '/api/v2/workflows/<plan_id>/reconcile'): 'workflow_v2_reconcile',
    ('POST', '/api/v2/workflows/<plan_id>/run'): 'workflow_v2_run',
    ('POST', '/api/v2/workflows/attempts/<attempt_id>/cost'): 'workflow_v2_attempt_cost',
    ('POST', '/api/validate/<job_id>/<int:seq>'): 'api_validate',
}

EXPECTED_UI_ROUTE_HANDLERS = {
    "/ui-v2": "ui_v2_home",
    "/ui-v2/dashboard": "ui_v2_home",
    "/ui-v2/run": "ui_v2_run",
    "/ui-v2/findings": "ui_v2_findings",
    "/ui-v2/scope": "ui_v2_scope",
    "/ui-v2/report": "ui_v2_report",
    "/ui-v2/reports": "ui_v2_reports",
    "/ui-v2/history": "ui_v2_history",
    "/ui-v2/diagnostics": "ui_v2_diagnostics",
    "/ui-v2/evidence": "ui_v2_evidence",
    "/ui-v2/ai": "ui_v2_ai",
    "/ui-v2/retest": "ui_v2_retest",
    "/ui-v2/chains": "ui_v2_chains",
    "/ui-v2/adapters": "ui_v2_adapters",
    "/ui-v2/settings": "ui_v2_settings",
    "/ui-v2/audit": "ui_v2_audit",
    "/ui-v2/monitoring": "ui_v2_monitoring",
    "/ui-v2/bas": "ui_v2_bas",
    "/ui-v2/bug-bounty": "ui_v2_bug_bounty",
    "/ui-v2/compliance": "ui_v2_compliance",
    "/ui-v2/ptaas": "ui_v2_ptaas",
    "/ui-v2/threat-intel": "ui_v2_threat_intel",
    "/ui-v2/approvals": "ui_v2_approvals",
}

SERVICE_CALL_NAMES = {item[2] for item in EXPECTED_SERVICE_CALLS}


def _dotted_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else None
    return None


class _RunnerCallVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.functions: list[str] = []
        self.calls: Counter[tuple[str, str, str]] = Counter()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.functions.append(node.name)
        self.generic_visit(node)
        self.functions.pop()

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute) and node.func.attr in {
            "run_tool",
            "run_in_session",
        }:
            scope = ".".join(self.functions)
            self.calls[(self.path, scope, node.func.attr)] += 1
        self.generic_visit(node)


class _ServiceCallVisitor(_RunnerCallVisitor):
    def __init__(self, path: str) -> None:
        super().__init__(path)
        self.service_calls: Counter[tuple[str, str, str]] = Counter()

    def visit_Call(self, node: ast.Call) -> None:
        call_name = _dotted_name(node.func)
        if call_name in SERVICE_CALL_NAMES:
            scope = ".".join(self.functions)
            self.service_calls[(self.path, scope, call_name)] += 1
        self.generic_visit(node)


def _runner_call_inventory() -> Counter[tuple[str, str, str]]:
    calls: Counter[tuple[str, str, str]] = Counter()
    for source in sorted(SOURCE_ROOT.rglob("*.py")):
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        visitor = _RunnerCallVisitor(source.relative_to(SOURCE_ROOT).as_posix())
        visitor.visit(tree)
        calls.update(visitor.calls)
    return calls


def test_legacy_and_v2_runner_dispatch_callsites_are_explicit() -> None:
    actual = _runner_call_inventory()
    assert actual == EXPECTED_RUNNER_CALLS, (
        "Execution callsites changed. Review the Engine V2 caller inventory, classify "
        "each addition as legacy or scheduler-authorized V2, then update this map. "
        f"Unexpected: {actual - EXPECTED_RUNNER_CALLS}; "
        f"missing: {EXPECTED_RUNNER_CALLS - actual}"
    )


def test_recon_validation_and_retest_service_callsites_are_explicit() -> None:
    actual: Counter[tuple[str, str, str]] = Counter()
    for source in sorted(SOURCE_ROOT.rglob("*.py")):
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        visitor = _ServiceCallVisitor(source.relative_to(SOURCE_ROOT).as_posix())
        visitor.visit(tree)
        actual.update(visitor.service_calls)

    assert actual == EXPECTED_SERVICE_CALLS, (
        "Recon/validation/retest service callsites changed. Review the Engine V2 "
        "service inventory, classification, and authorization boundary before "
        "updating this map. "
        f"Unexpected: {actual - EXPECTED_SERVICE_CALLS}; "
        f"missing: {EXPECTED_SERVICE_CALLS - actual}"
    )


def test_api_route_methods_and_handlers_are_explicit() -> None:
    server = SOURCE_ROOT / "interfaces" / "web" / "server.py"
    tree = ast.parse(server.read_text(encoding="utf-8"), filename=str(server))
    actual: dict[tuple[str, str], str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            func = decorator.func
            if (
                not isinstance(func, ast.Attribute)
                or not isinstance(func.value, ast.Name)
                or func.value.id != "app"
                or not decorator.args
            ):
                continue
            if func.attr in {"get", "post", "put", "patch", "delete"}:
                route = ast.literal_eval(decorator.args[0])
                methods = [func.attr.upper()]
            elif func.attr == "route":
                route = ast.literal_eval(decorator.args[0])
                methods = next(
                    (ast.literal_eval(item.value) for item in decorator.keywords
                     if item.arg == "methods"),
                    ["GET"],
                )
            else:
                continue
            for method in methods:
                key = (method.upper(), route)
                if route.startswith("/api/"):
                    actual[key] = node.name

    assert actual == EXPECTED_API_ROUTE_HANDLERS, (
        "API method/handler bindings changed. Review the G01 route ownership and "
        "authorization map before updating it. "
        f"Unexpected: {actual.keys() - EXPECTED_API_ROUTE_HANDLERS.keys()}; "
        f"missing: {EXPECTED_API_ROUTE_HANDLERS.keys() - actual.keys()}; "
        f"changed: {[key for key in actual.keys() & EXPECTED_API_ROUTE_HANDLERS.keys() if actual[key] != EXPECTED_API_ROUTE_HANDLERS[key]]}"
    )


def test_ui_route_crosswalk_is_explicit_and_matches_g01_documentation() -> None:
    server = SOURCE_ROOT / "interfaces" / "web" / "server.py"
    tree = ast.parse(server.read_text(encoding="utf-8"), filename=str(server))
    actual = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not decorator.args:
                continue
            func = decorator.func
            if (
                not isinstance(func, ast.Attribute)
                or not isinstance(func.value, ast.Name)
                or func.value.id != "app"
            ):
                continue
            if func.attr == "get":
                route, methods = ast.literal_eval(decorator.args[0]), ["GET"]
            elif func.attr == "route":
                route = ast.literal_eval(decorator.args[0])
                methods = next(
                    (ast.literal_eval(item.value) for item in decorator.keywords
                     if item.arg == "methods"),
                    ["GET"],
                )
            else:
                continue
            if route.startswith("/ui-v2") and "GET" in methods:
                actual[route] = node.name
    assert actual == EXPECTED_UI_ROUTE_HANDLERS

    inventory = (
        Path(__file__).resolve().parents[1]
        / "docs"
        / "ENGINE_V2_LEGACY_EXECUTION_INVENTORY.md"
    ).read_text(encoding="utf-8")
    start = inventory.index("The UI route aliases below are recorded")
    end = inventory.index("#### Exact Flask API method/path/handler census", start)
    documented = {
        route: handler
        for route, handler in re.findall(
            r"^\| `GET` \| `([^`]+)` \| `([^`]+)` \|",
            inventory[start:end],
            re.MULTILINE,
        )
    }
    assert documented == EXPECTED_UI_ROUTE_HANDLERS


def test_catalog_transports_and_v2_admission_are_explicit() -> None:
    catalog = json.loads(
        (SOURCE_ROOT / "data" / "tools.json").read_text(encoding="utf-8")
    )
    actual_transports = {
        tool["id"]: tool.get("transport", "cli") for tool in catalog["tools"]
    }
    assert actual_transports == EXPECTED_CATALOG_TRANSPORTS

    from whaxon.core.providers import _CATALOG_TARGETS, SEMANTIC_OPERATION_IDS

    assert _CATALOG_TARGETS == EXPECTED_V2_TARGET_TYPES
    assert SEMANTIC_OPERATION_IDS == EXPECTED_V2_SEMANTIC_OPERATIONS

def test_api_route_census_matches_documented_g01_inventory():
    """Keep the exact route/handler source census synchronized with G01 docs."""
    inventory = (
        Path(__file__).resolve().parents[1]
        / "docs"
        / "ENGINE_V2_LEGACY_EXECUTION_INVENTORY.md"
    ).read_text(encoding="utf-8")
    marker = "#### Exact Flask API method/path/handler census"
    start = inventory.index(marker)
    end = inventory.index("| Route group | Paths and owner", start)
    section = inventory[start:end]
    documented = {
        (method, path): handler
        for method, path, handler in re.findall(
            r"^\| `(GET|POST|PUT|PATCH|DELETE)` \| `([^`]+)` \| `([^`]+)` \|",
            section,
            re.MULTILINE,
        )
    }
    assert documented == EXPECTED_API_ROUTE_HANDLERS


def test_catalog_and_v2_operation_crosswalk_are_documented():
    inventory_path = (
        Path(__file__).resolve().parents[1]
        / "docs"
        / "ENGINE_V2_LEGACY_EXECUTION_INVENTORY.md"
    )
    inventory = inventory_path.read_text(encoding="utf-8")
    catalog_start = inventory.index("| Catalog IDs | V2 status | Transport and reason |")
    catalog_end = inventory.index(
        "Exact V2 operation aliases and declared target types:", catalog_start,
    )
    documented_catalog = {}
    for line in inventory[catalog_start:catalog_end].splitlines():
        if not line.startswith("| `"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        for tool_id in re.findall(r"`([^`]+)`", cells[0]):
            documented_catalog[tool_id] = (cells[1], cells[2])

    admitted = set(EXPECTED_V2_TARGET_TYPES)
    not_admitted = {"commix", "echo", "hydra", "impacket", "netexec"}
    unsupported = set(EXPECTED_CATALOG_TRANSPORTS) - admitted - not_admitted
    expected_catalog = {
        tool_id: (
            "Admitted",
            "`cli` → `local_process`, provider-bound; target-type allowlist applies.",
        )
        for tool_id in admitted
    }
    expected_catalog.update({
        tool_id: (
            "Not admitted",
            "`cli`; no Engine V2 provider admission. Some have legacy adapters.",
        )
        for tool_id in not_admitted
    })
    transport_reasons = {
        "msf_session": "`msf_session`; requires a separately accepted session provider.",
        "smb": "`smb`; requires a separately accepted session provider.",
        "ssh": "`ssh`; no registered adapter in the inspected runtime.",
        "wmi": "`wmi`; requires a separately accepted session provider.",
    }
    expected_catalog.update({
        tool_id: (
            "Unsupported in V2",
            transport_reasons[EXPECTED_CATALOG_TRANSPORTS[tool_id]],
        )
        for tool_id in unsupported
    })
    assert documented_catalog == expected_catalog

    operation_start = inventory.index(
        "| Tool | Compatibility capability | Semantic capability | Target types |",
    )
    operation_end = inventory.index("The built-in adapter registry", operation_start)
    documented_operations = {}
    for line in inventory[operation_start:operation_end].splitlines():
        match = re.match(
            r"^\| `([^`]+)` \| `([^`]+)` \| `([^`]+)` \| ([^|]+) \|$",
            line,
        )
        if match:
            tool_id, capability_id, operation_id, raw_targets = match.groups()
            target_names = {"URL": "url", "Hostname": "hostname", "IP": "ip"}
            target_types = tuple(
                target_names[target.strip()] for target in raw_targets.split(",")
            )
            documented_operations[tool_id] = (
                capability_id, operation_id, target_types,
            )
    expected_operations = {
        tool_id: (f"tool.{tool_id}", operation_id, EXPECTED_V2_TARGET_TYPES[tool_id])
        for tool_id, operation_id in EXPECTED_V2_SEMANTIC_OPERATIONS.items()
    }
    assert documented_operations == expected_operations

