/* WHAXON web UI. Talks to the Flask JSON API. */

const $ = (sel) => document.querySelector(sel);

let state = {
  tools: [],
  selectedToolId: null,
  currentJobId: null,
  eventSource: null,
};

/* ---------- Catalog ---------- */

async function loadCatalog() {
  const res = await fetch("/api/tools");
  const tools = await res.json();
  state.tools = tools;

  const root = $("#catalog");
  root.innerHTML = "";

  const byCategory = {};
  for (const t of tools) {
    (byCategory[t.category] ??= []).push(t);
  }

  for (const cat of Object.keys(byCategory).sort()) {
    const catEl = document.createElement("div");
    catEl.className = "category";
    catEl.textContent = cat;
    root.appendChild(catEl);

    for (const t of byCategory[cat]) {
      const el = document.createElement("div");
      el.className = "tool";
      el.dataset.toolId = t.id;
      el.innerHTML = `${t.name}<span class="binary">${t.binary}</span>`;
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
  $("#selected-label").textContent = t ? `selected: ${t.name} → ${t.binary}` : "selected: (none)";
  $("#target").focus();
}

/* ---------- Running ---------- */

async function runTool() {
  if (state.currentJobId) {
    setStatus("a job is already running");
    return;
  }
  if (!state.selectedToolId) {
    setStatus("select a tool first");
    return;
  }
  const target = $("#target").value.trim();
  if (!target) {
    setStatus("enter a target first");
    return;
  }

  clearOutput();
  const res = await fetch("/api/run", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ tool_id: state.selectedToolId, target }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    appendLine(`error: ${err.error || res.statusText}`, "stderr");
    setStatus("failed to start job");
    return;
  }
  const { job_id } = await res.json();
  state.currentJobId = job_id;
  setStatus(`running ${job_id}…`);
  $("#run").disabled = true;
  $("#cancel").disabled = false;
  startStream(job_id);
}

function startStream(jobId) {
  if (state.eventSource) { state.eventSource.close(); }
  const es = new EventSource(`/api/jobs/${jobId}/stream`);
  state.eventSource = es;

  es.onmessage = (evt) => {
    let data;
    try { data = JSON.parse(evt.data); } catch { return; }

    if (data.type === "status") {
      if (data.tool) setStatus(`running ${jobId} — ${data.tool} → ${data.target}`);
    } else if (data.type === "line") {
      appendLine(data.text, data.stream === "stderr" ? "stderr" : null);
    } else if (data.type === "finished") {
      appendLine(`< job ${jobId} finished — exit=${data.exit_code}`, "meta");
      setStatus(`done — exit ${data.exit_code}`);
      es.close(); state.eventSource = null; finishJob();
    } else if (data.type === "failed") {
      appendLine(`! job ${jobId} failed — ${data.error}`, "stderr");
      setStatus(`failed — ${data.error}`);
      es.close(); state.eventSource = null; finishJob();
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
}

async function cancelJob() {
  if (!state.currentJobId) return;
  const id = state.currentJobId;
  if (state.eventSource) { state.eventSource.close(); state.eventSource = null; }
  await fetch(`/api/jobs/${id}/cancel`, { method: "POST" }).catch(() => {});
  appendLine(`cancelled ${id}`, "meta");
  finishJob();
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
  loadCatalog().catch((e) => setStatus(`failed to load catalog: ${e}`));
  $("#run").addEventListener("click", runTool);
  $("#cancel").addEventListener("click", cancelJob);
  $("#target").addEventListener("keydown", (e) => {
    if (e.key === "Enter") runTool();
  });
});
