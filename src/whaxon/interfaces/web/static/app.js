/* BACKFORGE web UI. Talks to the Flask JSON API. */

const $ = (sel) => document.querySelector(sel);

let state = {
  tools: [],
  selectedToolId: null,
  currentJobId: null,
  pollTimer: null,
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
  pollJob(job_id);
}

async function pollJob(jobId) {
  let seen = 0;
  const tick = async () => {
    if (state.currentJobId !== jobId) return;
    try {
      const res = await fetch(`/api/jobs/${jobId}`);
      if (!res.ok) return;
      const job = await res.json();
      const lines = job.lines || [];
      for (let i = seen; i < lines.length; i++) {
        const l = lines[i];
        appendLine(l.text, l.stream === "stderr" ? "stderr" : null);
      }
      seen = lines.length;

      if (job.status === "finished") {
        appendLine(`< job ${job.id} finished — exit=${job.exit_code}`, "meta");
        setStatus(`done — exit ${job.exit_code}`);
        finishJob();
        return;
      }
      if (job.status === "failed") {
        appendLine(`! job ${job.id} failed — ${job.error}`, "stderr");
        setStatus(`failed — ${job.error}`);
        finishJob();
        return;
      }
      state.pollTimer = setTimeout(tick, 500);
    } catch (e) {
      appendLine(`poll error: ${e}`, "stderr");
      state.pollTimer = setTimeout(tick, 1500);
    }
  };
  tick();
}

function finishJob() {
  state.currentJobId = null;
  $("#run").disabled = false;
  $("#cancel").disabled = true;
}

async function cancelJob() {
  if (!state.currentJobId) return;
  const id = state.currentJobId;
  await fetch(`/api/jobs/${id}/cancel`, { method: "POST" }).catch(() => {});
  appendLine(`cancelling ${id}…`, "meta");
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
