/* WHAXON web UI. Talks to the Flask JSON API. */

const $ = (sel) => document.querySelector(sel);

let state = {
  tools: [],
  selectedToolId: null,
  currentJobId: null,
  eventSource: null,
  _running: false,
};

/* ---------- Catalog ---------- */

async function loadCatalog() {
  const res = await fetch("/api/tools");
  const tools = await res.json();
  state.tools = tools;
  const root = $("#catalog");
  root.innerHTML = "";
  const byCategory = {};
  for (const t of tools) (byCategory[t.category] ??= []).push(t);
  for (const cat of Object.keys(byCategory).sort()) {
    const catEl = document.createElement("div");
    catEl.className = "category";
    catEl.textContent = cat;
    root.appendChild(catEl);
    for (const t of byCategory[cat]) {
      const el = document.createElement("div");
      el.className = "tool";
      el.dataset.toolId = t.id;
      el.innerHTML = t.name + "<span class='binary'>" + t.binary + "</span>";
      el.addEventListener("click", () => selectTool(t.id));
      root.appendChild(el);
    }
  }
}

function selectTool(toolId) {
  state.selectedToolId = toolId;
  for (const el of document.querySelectorAll("#catalog .tool")) {
    el.classList.toggle("selected", el.dataset.toolId === toolId);
  }
  const t = state.tools.find((x) => x.id === toolId);
  $("#selected-label").textContent = t ? "selected: " + t.name + " \u2192 " + t.binary : "selected: (none)";
  $("#target").focus();
}

/* ---------- History ---------- */

async function loadHistory() {
  try {
    const res = await fetch("/api/history");
    if (!res.ok) return;
    const jobs = await res.json();
    const root = $("#history");
    if (!root) return;
    root.innerHTML = "";
    if (jobs.length === 0) {
      root.innerHTML = "<div class='hint'>no jobs yet</div>";
      return;
    }
    for (const j of jobs) {
      const el = document.createElement("div");
      el.className = "history-item";
      const ok = j.status === "finished" && j.exit_code === 0;
      el.innerHTML = (ok ? "&#9679;" : "&#9675;") + " <strong>" + j.tool + "</strong> <span class='hint'>" + j.target + "</span>";
      el.addEventListener("click", () => showHistoryJob(j.id));
      root.appendChild(el);
    }
  } catch (e) {}
}

async function showHistoryJob(jobId) {
  if (state.eventSource) { state.eventSource.close(); state.eventSource = null; }
  state.currentJobId = null;
  finishJob();
  clearOutput();
  clearFindings();
  const res = await fetch("/api/jobs/" + jobId);
  if (!res.ok) { setStatus("cannot load " + jobId); return; }
  const job = await res.json();
  appendLine("history: " + job.id + " - " + job.tool + " \u2192 " + job.target, "meta");
  for (const l of (job.lines || [])) {
    appendLine(l.text, l.stream === "stderr" ? "stderr" : null);
  }
  appendLine("< job " + job.id + " " + job.status + " - exit=" + job.exit_code, "meta");
  setStatus("viewing past job " + job.id);
  fetchFindings(jobId);
}

/* ---------- Running ---------- */

async function runTool() {
  if (state.currentJobId) { setStatus("a job is already running"); return; }
  if (state._running) return;
  state._running = true;
  setTimeout(() => { state._running = false; }, 300);
  if (!state.selectedToolId) { setStatus("select a tool first"); return; }
  const target = $("#target").value.trim();
  const extraArgs = $("#extra") ? $("#extra").value.trim() : "";
  if (!target) { setStatus("enter a target first"); return; }
  clearOutput();
  clearFindings();
  const res = await fetch("/api/run", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ tool_id: state.selectedToolId, target, extra_args: extraArgs }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    appendLine("error: " + (err.error || res.statusText), "stderr");
    setStatus("failed to start job");
    return;
  }
  const { job_id } = await res.json();
  state.currentJobId = job_id;
  setStatus("running " + job_id + "\u2026");
  $("#run").disabled = true;
  $("#cancel").disabled = false;
  startStream(job_id);
}

function startStream(jobId) {
  if (state.eventSource) state.eventSource.close();
  const es = new EventSource("/api/jobs/" + jobId + "/stream");
  state.eventSource = es;
  es.onmessage = (evt) => {
    let data;
    try { data = JSON.parse(evt.data); } catch { return; }
    if (data.type === "status") {
      if (data.tool) setStatus("running " + jobId + " \u2014 " + data.tool + " \u2192 " + data.target);
    } else if (data.type === "line") {
      appendLine(data.text, data.stream === "stderr" ? "stderr" : null);
    } else if (data.type === "finished") {
      appendLine("< job " + jobId + " finished \u2014 exit=" + data.exit_code, "meta");
      setStatus("done \u2014 exit " + data.exit_code);
      es.close(); state.eventSource = null;
      fetchFindings(jobId);
      finishJob();
    } else if (data.type === "failed") {
      appendLine("! job " + jobId + " failed \u2014 " + data.error, "stderr");
      setStatus("failed \u2014 " + data.error);
      es.close(); state.eventSource = null;
      finishJob();
    }
  };
  es.onerror = () => {
    es.close(); state.eventSource = null;
    if (state.currentJobId === jobId) { setStatus("stream closed"); finishJob(); }
  };
}

function finishJob() {
  state.currentJobId = null;
  $("#run").disabled = false;
  $("#cancel").disabled = true;
  loadHistory();
}

async function cancelJob() {
  if (!state.currentJobId) return;
  const id = state.currentJobId;
  if (state.eventSource) { state.eventSource.close(); state.eventSource = null; }
  await fetch("/api/jobs/" + id + "/cancel", { method: "POST" }).catch(() => {});
  appendLine("cancelled " + id, "meta");
  finishJob();
}

/* ---------- Findings ---------- */

async function fetchFindings(jobId) {
  try {
    const res = await fetch("/api/jobs/" + jobId + "/findings");
    if (!res.ok) { renderFindings([]); return; }
    const findings = await res.json();
    renderFindings(findings);
  } catch (e) { renderFindings([]); }
}

function clearFindings() {
  const el = $("#findings");
  if (el) el.innerHTML = "";
}

function renderFindings(findings) {
  const el = $("#findings");
  if (!el) return;
  el.innerHTML = "";
  if (!findings || findings.length === 0) return;
  const hdr = document.createElement("h2");
  hdr.style.marginTop = "16px";
  hdr.textContent = "Findings (" + findings.length + ")";
  el.appendChild(hdr);
  const table = document.createElement("table");
  table.className = "findings-table";
  const head = document.createElement("tr");
  for (const label of ["Severity", "Kind", "Detail"]) {
    const th = document.createElement("th");
    th.textContent = label;
    head.appendChild(th);
  }
  table.appendChild(head);
  for (const f of findings) {
    const tr = document.createElement("tr");
    tr.className = "sev-" + (f.severity || "info");
    const sev = document.createElement("td");
    sev.textContent = f.severity || "info";
    tr.appendChild(sev);
    const kind = document.createElement("td");
    kind.textContent = f.kind || "";
    tr.appendChild(kind);
    const detail = document.createElement("td");
    const d = f.data || {};
    if (f.kind === "open_port") {
      detail.textContent = d.port + "/" + d.protocol + " " + (d.service || "") + " (" + d.state + ")";
    } else if (f.kind === "web_issue") {
      detail.textContent = (d.path ? d.path + " " : "") + (d.message || "");
    } else if (f.kind === "found_path") {
      detail.textContent = d.path + " (Status: " + d.status + ")";
    } else {
      detail.textContent = JSON.stringify(d);
    }
    tr.appendChild(detail);
    table.appendChild(tr);
  }
  el.appendChild(table);
}

/* ---------- Output helpers ---------- */

function clearOutput() { $("#output").innerHTML = ""; }

function appendLine(text, cls) {
  const el = document.createElement("div");
  el.className = "line" + (cls ? " " + cls : "");
  el.textContent = text;
  $("#output").appendChild(el);
  $("#output").scrollTop = $("#output").scrollHeight;
}

function setStatus(text) { $("#status").textContent = text; }

/* ---------- Wire up ---------- */

window.addEventListener("DOMContentLoaded", () => {
  loadCatalog().catch((e) => setStatus("failed to load catalog: " + e));
  loadHistory();
  $("#run").addEventListener("click", runTool);
  $("#cancel").addEventListener("click", cancelJob);
  $("#target").addEventListener("keydown", (e) => { if (e.key === "Enter") runTool(); });
  const extraEl = $("#extra");
  if (extraEl) {
    extraEl.addEventListener("keydown", (e) => { if (e.key === "Enter") runTool(); });
  }
});
