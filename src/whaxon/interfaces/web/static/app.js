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
      const available = t.available !== false;
      el.className = "tool" + (available ? "" : " unavailable");
      el.dataset.toolId = t.id;
      el.dataset.available = available ? "1" : "0";
      el.dataset.package = t.package || "";
      if (available) {
        el.innerHTML = t.name + "<span class='binary'>" + t.binary + "</span>";
      } else {
        el.innerHTML = t.name + "<span class='binary'>not installed</span><span class='install-hint' title='Install command'>" +
          (t.package ? "apt install " + t.package : "install manually") + "</span>";
      }
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

async function uploadBurp(file) {
  const status = document.getElementById("import-status");
  const btn = document.getElementById("burp-upload");
  if (status) status.textContent = "uploading...";
  if (btn) btn.disabled = true;

  const fd = new FormData();
  fd.append("file", file);

  try {
    const res = await fetch("/api/import/burp", { method: "POST", body: fd });
    const data = await res.json();
    if (!res.ok) {
      if (status) status.textContent = "error: " + (data.error || res.statusText);
      return;
    }
    if (status) status.textContent = "imported " + data.count + " findings (job " + data.job_id + ")";
    await loadHistory();
    setTimeout(() => showHistoryJob(data.job_id), 300);
  } catch (e) {
    if (status) status.textContent = "error: " + e;
  } finally {
    if (btn) btn.disabled = false;
  }
}

function wireBurpUpload() {
  const btn = document.getElementById("burp-upload");
  const file = document.getElementById("burp-file");
  if (!btn || !file) return;
  btn.addEventListener("click", () => file.click());
  file.addEventListener("change", () => {
    if (file.files && file.files[0]) uploadBurp(file.files[0]);
    file.value = "";
  });
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
  const el = document.getElementById('findings');
  if (!el) return;
  el.innerHTML = '';
  if (!findings || findings.length === 0) return;

  const hdr = document.createElement('h2');
  hdr.style.marginTop = '8px';
  hdr.textContent = 'Findings (' + findings.length + ')';
  el.appendChild(hdr);

  const table = document.createElement('table');
  table.className = 'findings-table';

  const head = document.createElement('tr');
  for (const label of ['Sev', 'Kind', 'CVSS', 'CWE', 'Detail']) {
    const th = document.createElement('th');
    th.textContent = label;
    head.appendChild(th);
  }
  table.appendChild(head);

  findings.forEach((f, idx) => {
    const d = f.data || {};
    const tr = document.createElement('tr');
    tr.className = 'sev-' + (f.severity || 'info') + ' finding-row';
    tr.dataset.idx = idx;

    const tdSev = document.createElement('td');
    tdSev.textContent = f.severity || 'info';
    tr.appendChild(tdSev);

    const tdKind = document.createElement('td');
    tdKind.textContent = f.kind || '';
    tr.appendChild(tdKind);

    const tdCvss = document.createElement('td');
    tdCvss.textContent = f.cvss != null ? f.cvss : '';
    tr.appendChild(tdCvss);

    const tdCwe = document.createElement('td');
    tdCwe.textContent = f.cwe || '';
    tr.appendChild(tdCwe);

    const tdDetail = document.createElement('td');
    if (f.kind === 'open_port') {
      tdDetail.textContent = d.port + '/' + d.protocol + ' ' + (d.service || '') + (d.version ? ' ' + d.version : '');
    } else if (f.kind === 'web_issue') {
      tdDetail.textContent = (d.path ? d.path + ' ' : '') + (d.message || '');
    } else if (f.kind === 'found_path') {
      tdDetail.textContent = d.path + ' (Status: ' + d.status + ')';
    } else {
      tdDetail.textContent = JSON.stringify(d);
    }
    tr.appendChild(tdDetail);

    table.appendChild(tr);

    const detailTr = document.createElement('tr');
    detailTr.className = 'detail-row';
    detailTr.style.display = 'none';
    const detailTd = document.createElement('td');
    detailTd.colSpan = 5;
    const parts = [];
    if (f.impact) parts.push('<div class="finding-section"><strong>Impact:</strong> ' + escapeHtml(f.impact) + '</div>');
    if (f.remediation) parts.push('<div class="finding-section"><strong>Remediation:</strong> ' + escapeHtml(f.remediation) + '</div>');
    if (f.references && f.references.length) parts.push('<div class="finding-section"><strong>Refs:</strong> ' + f.references.map(escapeHtml).join(', ') + '</div>');
    if (f.raw_line) parts.push('<div class="finding-section raw"><code>' + escapeHtml(f.raw_line) + '</code></div>');
    const sug = suggestFor(f);
    let sugHtml = '';
    if (sug.length) {
      sugHtml = '<div class="finding-section suggest-row"><strong>Next steps:</strong> ';
      sugHtml += sug.map((s, i) => {
        const tool = state.tools.find((x) => x.id === s.tool);
        const ok = tool && tool.available !== false;
        const cls = ok ? "suggest-btn" : "suggest-btn suggest-disabled";
        const title = ok ? "" : " title='Not installed — install: " + (tool && tool.package ? "apt install " + tool.package : "manual install") + "'";
        const label = ok ? s.label : s.label + " (not installed)";
        return '<button class="' + cls + '" data-idx="' + i + '"' + title + '>' + escapeHtml(label) + '</button>';
      }).join('');
      sugHtml += '</div>';
    }
    detailTd.innerHTML = parts.join('') + sugHtml || '<em>no additional detail</em>';
    detailTr.appendChild(detailTd);
    table.appendChild(detailTr);

    // Bind AFTER the buttons are in the DOM
    detailTd.querySelectorAll('.suggest-btn').forEach((btn) => {
      btn.addEventListener('click', (ev) => {
        ev.stopPropagation();
        ev.preventDefault();
        const idx = parseInt(btn.dataset.idx, 10);
        const chosen = sug[idx];
        console.log('SUGGEST CLICKED', idx, chosen);
        if (chosen) applySuggestion(chosen);
      });
    });

    tr.addEventListener('click', (ev) => {
      if (ev.target.closest('.suggest-btn')) return;
      detailTr.style.display = detailTr.style.display === 'none' ? 'table-row' : 'none';
    });
  });

  el.appendChild(table);
}

function suggestFor(finding) {
  const out = [];
  const d = finding.data || {};
  const cur = (document.getElementById("target") && document.getElementById("target").value) || "";
  const target = d.host || cur;

  const tgt = { target: target };

  if (finding.kind === "open_port") {
    const port = d.port;
    const svc = (d.service || "").toLowerCase();
    if (svc === "http" || svc === "https" || port === 80 || port === 443 || svc === "commplex-link") {
      out.push({ label: "Nikto on port " + port, tool: "nikto", extra: "", target: target });
      out.push({ label: "Gobuster", tool: "gobuster", extra: "", target: target });
    } else if (svc === "mysql" || svc === "postgresql" || svc === "redis") {
      out.push({ label: "Nmap -sV on " + port, tool: "nmap", extra: "-sV -p " + port, target: target });
    } else {
      out.push({ label: "Nmap -sV on " + port, tool: "nmap", extra: "-sV -p " + port });
    }
  } else if (finding.kind === "web_issue") {
    const name = (d.name || "").toLowerCase();
    if (name.includes("sql")) {
      out.push({ label: "SQLmap against " + (d.path || "/"), tool: "sqlmap", extra: "", target: target });
    } else if (name.includes("wordpress") || name.includes("wp-")) {
      out.push({ label: "WPScan", tool: "wpscan", extra: "", target: target });
    } else {
      out.push({ label: "Nuclei templates", tool: "nuclei", extra: "", target: target });
    }
    out.push({ label: "Gobuster on " + (d.path || "/"), tool: "gobuster", extra: "", target: target });
  } else if (finding.kind === "found_path") {
    out.push({ label: "Nuclei templates", tool: "nuclei", extra: "" });
  } else if (finding.kind === "vulnerability") {
    out.push({ label: "Verify with nmap -sV", tool: "nmap", extra: "-sV", target: target });
  }
  return out;
}

function applySuggestion(s) {
  state.selectedToolId = s.tool;
  for (const el of document.querySelectorAll("#catalog .tool")) {
    el.classList.toggle("selected", el.dataset.toolId === s.tool);
  }
  const t = state.tools.find((x) => x.id === s.tool);
  const lbl = document.getElementById("selected-label");
  if (lbl) lbl.textContent = t ? "selected: " + t.name + " \u2192 " + t.binary : "selected: (none)";
  const targetEl = document.getElementById("target");
  if (targetEl && s.target) targetEl.value = s.target;
  const extraEl = document.getElementById("extra");
  if (extraEl) extraEl.value = s.extra || "";
  setStatus("prepared " + s.tool + " \u2014 press Run to execute");
  window.scrollTo({ top: 0, behavior: "smooth" });
  const target = document.getElementById("target");
  if (target) target.focus();
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c] || c));
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
  wireBurpUpload();
  $("#run").addEventListener("click", runTool);
  $("#cancel").addEventListener("click", cancelJob);
  $("#target").addEventListener("keydown", (e) => { if (e.key === "Enter") runTool(); });
  const extraEl = $("#extra");
  if (extraEl) {
    extraEl.addEventListener("keydown", (e) => { if (e.key === "Enter") runTool(); });
  }
});
