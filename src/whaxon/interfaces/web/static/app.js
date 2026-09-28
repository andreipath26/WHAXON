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

  const available = tools.filter((t) => t.available !== false);
  const missing = tools.filter((t) => t.available === false);

  const byCategory = {};
  for (const t of available) {
    (byCategory[t.category] ??= []).push(t);
  }

  const renderRow = (t, unavailable) => {
    const el = document.createElement("div");
    el.className = "tool" + (unavailable ? " unavailable" : "");
    el.dataset.toolId = t.id;
    el.title = t.binary || t.id;
    const showBinary = t.binary && t.binary !== t.id && !t.binary.endsWith("/" + t.id);
    if (unavailable) {
      el.innerHTML = t.name +
        "<span class='row-meta'>" + (t.package ? "apt install " + t.package : "not installed") + "</span>";
    } else if (showBinary) {
      el.innerHTML = t.name + "<span class='row-meta'>" + t.binary + "</span>";
    } else {
      el.textContent = t.name;
    }
    el.addEventListener("click", () => selectTool(t.id));
    return el;
  };

  for (const cat of Object.keys(byCategory).sort()) {
    const header = document.createElement("div");
    header.className = "category";
    header.innerHTML = "<span class='dot'></span>" + cat;
    root.appendChild(header);
    for (const t of byCategory[cat]) {
      root.appendChild(renderRow(t, false));
    }
  }

  if (missing.length) {
    const header = document.createElement("div");
    header.className = "category category-missing";
    header.innerHTML = "<span class='dot'></span>Not Installed";
    root.appendChild(header);
    for (const t of missing) {
      root.appendChild(renderRow(t, true));
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

async function scopeCheck(target) {
  try {
    const res = await fetch("/api/scope/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target }),
    });
    if (!res.ok) return { allowed: true };
    return await res.json();
  } catch (e) {
    return { allowed: true };
  }
}

async function logOverride(target, tool) {
  try {
    await fetch("/api/scope/override", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, tool }),
    });
  } catch (e) {}
}

let pendingRun = null;

function showScopeModal(target, tool, match) {
  const m = document.getElementById("scope-modal");
  if (!m) return;
  document.getElementById("scope-target").textContent = target;
  document.getElementById("scope-reason").textContent = match.reason || "not in scope";
  document.getElementById("scope-rule").textContent = match.matched_rule || "(none)";
  document.getElementById("scope-engagement").textContent =
    (state.scopeInfo && state.scopeInfo.engagement) || "(unnamed)";
  m.style.display = "flex";
  pendingRun = { target, tool };
}

function hideScopeModal() {
  const m = document.getElementById("scope-modal");
  if (m) m.style.display = "none";
  pendingRun = null;
}

async function loadScopeInfo() {
  try {
    const res = await fetch("/api/scope");
    if (res.ok) state.scopeInfo = await res.json();
  } catch (e) {}
}

async function fetchScopeEnforcement() {
  // Called before running; if scope disabled, skip silently
  await loadScopeInfo();
}

async function loadTree() {
  try {
    const res = await fetch("/api/tree");
    if (!res.ok) return;
    const data = await res.json();
    const root = document.getElementById("tree");
    if (!root) return;
    root.innerHTML = "";

    const targets = data.targets || [];
    if (!targets.length) {
      root.innerHTML = "<div class='hint'>no targets with findings yet</div>";
      return;
    }

    for (const t of targets) {
      const entry = document.createElement("details");
      entry.className = "tree-target";

      const summary = document.createElement("summary");
      summary.innerHTML = "<span class='tree-name'>" + escapeHtml(t.target) + "</span>" +
        "<span class='tree-meta'>" + t.job_count + " jobs &middot; " + t.finding_count + " findings</span>";
      entry.appendChild(summary);

      // Group findings by kind
      const byKind = {};
      for (const f of t.findings) {
        (byKind[f.kind] ??= []).push(f);
      }

      for (const kind of Object.keys(byKind).sort()) {
        const items = byKind[kind];
        const kindRow = document.createElement("div");
        kindRow.className = "tree-kind";
        kindRow.textContent = kind + " (" + items.length + ")";
        entry.appendChild(kindRow);

        for (const f of items) {
          const row = document.createElement("div");
          row.className = "tree-finding sev-" + (f.severity || "info");
          row.dataset.target = t.target;

          const sig = f.signature || "";
          const cnt = f.count > 1 ? " <span class='tree-count'>x" + f.count + "</span>" : "";
          const cvss = f.cvss != null ? " <span class='tree-cvss'>CVSS " + f.cvss + "</span>" : "";
          row.innerHTML = "<span class='tree-sev'>" + (f.severity || "info") + "</span> " +
            "<span class='tree-sig'>" + escapeHtml(sig) + "</span>" + cnt + cvss;

          row.addEventListener("click", () => {
            showTreeFinding(t, f);
          });
          entry.appendChild(row);
        }
      }

      // Jobs list
      const jobsRow = document.createElement("div");
      jobsRow.className = "tree-kind";
      jobsRow.textContent = "jobs (" + t.job_count + ")";
      entry.appendChild(jobsRow);
      for (const j of t.jobs.slice(0, 8)) {
        const jr = document.createElement("div");
        jr.className = "tree-job";
        jr.dataset.jobId = j.id;
        jr.innerHTML = "<span class='tree-tool'>" + escapeHtml(j.tool) + "</span> " +
          "<span class='tree-status'>" + escapeHtml(j.status) + "</span>";
        jr.addEventListener("click", (ev) => {
          ev.stopPropagation();
          showHistoryJob(j.id);
        });
        entry.appendChild(jr);
      }

      root.appendChild(entry);
    }
  } catch (e) {
    console.log("tree error", e);
  }
}

function showTreeFinding(target, finding) {
  const out = document.getElementById("output");
  if (!out) return;
  const wrap = document.getElementById("output-wrap");
  if (wrap) wrap.setAttribute("open", "");
  clearOutput();
  clearFindings();
  appendLine("target: " + target.target, "meta");
  appendLine("finding: " + finding.signature + "  severity=" + finding.severity, "meta");
  if (finding.impact) appendLine("impact: " + finding.impact);
  if (finding.remediation) appendLine("remediation: " + finding.remediation);
  if (finding.raw_line) appendLine("raw: " + finding.raw_line, "meta");
  setStatus("showing finding from " + target.target);
}

function switchView(name) {
  for (const tab of document.querySelectorAll(".view-tab")) {
    tab.classList.toggle("active", tab.dataset.view === name);
  }
  for (const pane of document.querySelectorAll(".view-pane")) {
    pane.classList.toggle("active", pane.id === "view-" + name);
  }
  if (name === "tree") loadTree();
  if (name === "loot") loadLoot();
  if (name === "chain") loadChain();
}

function wireViewTabs() {
  for (const tab of document.querySelectorAll(".view-tab")) {
    tab.addEventListener("click", () => switchView(tab.dataset.view));
  }
}

async function refreshMsfIndicator() {
  try {
    const status = await fetch("/api/msf/status").then((r) => r.json());
    const dot = document.getElementById("msf-dot");
    const label = document.getElementById("msf-label");
    const count = document.getElementById("msf-sessions");
    if (dot) dot.className = "msf-dot " + (status.up ? "up" : "down");
    if (label) {
      label.textContent = status.up
        ? "Metasploit: " + (status.version || "up")
        : "Metasploit: offline";
    }
    if (count) {
      const sessions = await fetch("/api/msf/sessions").then((r) => r.json());
      count.textContent = String(sessions.live_count || 0);
    }
  } catch (e) {}
}

/* ---------- Session console ---------- */

let currentSessionId = null;

async function refreshSessionList() {
  try {
    const res = await fetch("/api/msf/sessions");
    if (!res.ok) return;
    const data = await res.json();
    const list = document.getElementById("msf-session-list");
    if (!list) return;
    list.innerHTML = "";
    const live = data.live || {};
    const ids = Object.keys(live);
    if (!ids.length) {
      return;
    }
    for (const sid of ids) {
      const info = live[sid] || {};
      const host = info.target_host || info.tunnel_peer || "?";
      const el = document.createElement("div");
      el.className = "msf-session-item";
      el.dataset.sessionId = sid;
      el.innerHTML = "<strong>#" + sid + "</strong> <span class='hint'>" + escapeHtml(host) + "</span>";
      el.addEventListener("click", () => openSessionConsole(sid, host));
      list.appendChild(el);
    }
  } catch (e) {}
}

async function openSessionConsole(sessionId, host) {
  currentSessionId = sessionId;
  // Hide the findings/output pane, show console
  const consoleEl = document.getElementById("session-console");
  const outputWrap = document.getElementById("output-wrap");
  const findingsEl = document.getElementById("findings");
  const statusEl = document.getElementById("status");
  if (consoleEl) consoleEl.style.display = "block";
  if (outputWrap) outputWrap.style.display = "none";
  if (findingsEl) findingsEl.style.display = "none";
  if (statusEl) statusEl.style.display = "none";

  const title = document.getElementById("console-title");
  if (title) title.textContent = "session #" + sessionId + " @ " + (host || "?");

  const out = document.getElementById("console-output");
  if (out) out.innerHTML = "";
  appendConsole("opened session #" + sessionId, "meta");
  // Auto-run sysinfo on open
  await sendConsoleCommand("sysinfo");
}

function closeSessionConsole() {
  currentSessionId = null;
  const consoleEl = document.getElementById("session-console");
  const outputWrap = document.getElementById("output-wrap");
  const findingsEl = document.getElementById("findings");
  const statusEl = document.getElementById("status");
  if (consoleEl) consoleEl.style.display = "none";
  if (outputWrap) outputWrap.style.display = "";
  if (findingsEl) findingsEl.style.display = "";
  if (statusEl) statusEl.style.display = "";
}

function appendConsole(text, cls) {
  const out = document.getElementById("console-output");
  if (!out) return;
  const line = document.createElement("div");
  line.className = "console-line" + (cls ? " " + cls : "");
  line.textContent = text;
  out.appendChild(line);
  out.scrollTop = out.scrollHeight;
}

async function sendConsoleCommand(command) {
  if (!currentSessionId) return;
  const out = document.getElementById("console-output");
  const input = document.getElementById("console-input");
  const send = document.getElementById("console-send");
  if (input) input.value = "";
  appendConsole("$ " + command, "cmd");
  if (send) send.disabled = true;
  appendConsole("…", "meta");

  try {
    const res = await fetch("/api/msf/sessions/" + currentSessionId + "/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ command }),
    });
    const data = await res.json();
    // Remove the "…" placeholder
    if (out && out.lastChild && out.lastChild.classList.contains("meta")) {
      out.removeChild(out.lastChild);
    }
    if (!res.ok) {
      appendConsole("error: " + (data.error || res.statusText), "err");
      return;
    }
    const output = data.output || "(no output)";
    for (const line of output.split("\n")) {
      appendConsole(line);
    }
  } catch (e) {
    appendConsole("network error: " + e, "err");
  } finally {
    if (send) send.disabled = false;
    if (input) input.focus();
  }
}

function wireSessionConsole() {
  const input = document.getElementById("console-input");
  const send = document.getElementById("console-send");
  const closeBtn = document.getElementById("console-close");
  if (input) {
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") sendConsoleCommand(input.value.trim());
    });
  }
  if (send) {
    send.addEventListener("click", () => {
      const v = input ? input.value.trim() : "";
      if (v) sendConsoleCommand(v);
    });
  }
  if (closeBtn) {
    closeBtn.addEventListener("click", closeSessionConsole);
  }
  document.querySelectorAll(".quick-btn").forEach((btn) => {
    btn.addEventListener("click", () => sendConsoleCommand(btn.dataset.cmd));
  });
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
  // Pre-flight scope check
  await loadScopeInfo();
  if (state.scopeInfo && state.scopeInfo.enabled) {
    const check = await scopeCheck(target);
    if (!check.allowed) {
      showScopeModal(target, state.selectedToolId, check);
      return;
    }
  }

  clearOutput();
  clearFindings();
  const res = await fetch("/api/run", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ tool_id: state.selectedToolId, target, extra_args: extraArgs }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    const msg = err.error || res.statusText;
    if (msg && msg.toLowerCase().includes("out of scope")) {
      showScopeModal(target, state.selectedToolId, { reason: msg, matched_rule: "" });
      return;
    }
    appendLine("error: " + msg, "stderr");
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
  if (document.getElementById("view-tree") && document.getElementById("view-tree").classList.contains("active")) { loadTree(); }
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
  const copyBtn = document.createElement('button');
  copyBtn.textContent = 'Copy as JSON';
  copyBtn.style.marginLeft = '12px';
  copyBtn.style.fontSize = '12px';
  copyBtn.onclick = () => {
    navigator.clipboard.writeText(JSON.stringify(findings, null, 2));
    copyBtn.textContent = 'Copied!';
    setTimeout(() => { copyBtn.textContent = 'Copy as JSON'; }, 1500);
  };
  hdr.appendChild(copyBtn);
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
    } else if (f.kind === 'env_var') {
      tdDetail.textContent = d.name + ' = ' + d.value;
    } else if (f.kind === 'sysinfo' || f.kind === 'platform') {
      tdDetail.textContent = (d.field || 'platform') + ': ' + (d.value || d.platform || '');
    } else if (f.kind === 'ntlm_hash') {
      tdDetail.textContent = d.user + ' (uid ' + d.uid + ')  LM=' + d.lm_hash + '  NT=' + d.nt_hash;
    } else if (f.kind === 'service') {
      tdDetail.textContent = d.port + '/' + d.proto + '  ' + d.state + '  ' + d.name;
    } else if (f.kind === 'msf_session') {
      tdDetail.textContent = 'session ' + d.session_id + ' on ' + (d.host || '?') + '  (' + (d.session_type || '') + ')';
    } else if (f.kind === 'msf_module_started') {
      tdDetail.textContent = d.module_type + '/' + d.module_path + ' job=' + d.job_id;
    } else if (f.raw_line) {
      tdDetail.textContent = f.raw_line;
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

function wireScopeModal() {
  const cancel = document.getElementById("scope-cancel");
  const override = document.getElementById("scope-override");
  if (cancel) {
    cancel.addEventListener("click", () => {
      hideScopeModal();
      setStatus("cancelled \u2014 target out of scope");
    });
  }
  if (override) {
    override.addEventListener("click", async () => {
      if (!pendingRun) { hideScopeModal(); return; }
      const { target, tool } = pendingRun;
      await logOverride(target, tool);
      hideScopeModal();
      setStatus("override logged \u2014 running " + tool);
      clearOutput();
      clearFindings();
      const extraArgs = ($("#extra") && $("#extra").value.trim()) || "";
      const res = await fetch("/api/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tool_id: tool, target, extra_args: extraArgs, allow_out_of_scope: true,
        }),
      });
      if (!res.ok) {
        setStatus("failed to start job after override");
        return;
      }
      const { job_id } = await res.json();
      state.currentJobId = job_id;
      setStatus("running " + job_id + "\u2026");
      $("#run").disabled = true;
      $("#cancel").disabled = false;
      startStream(job_id);
    });
  }
}

/* ---------- Theme ---------- */
function _preferredDark() {
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
}
function applyTheme(pref) {
  const dark = pref === "dark" || (pref === "system" && _preferredDark());
  document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
  document.querySelectorAll(".theme-toggle button").forEach((b) => {
    b.classList.toggle("active", b.dataset.themeValue === pref);
  });
}
function setThemePref(pref) {
  try { localStorage.setItem("whaxon-theme", pref); } catch (e) {}
  applyTheme(pref);
  fetch("/api/settings", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ theme: pref }),
  }).catch(function () {});
}
function wireThemeToggle() {
  var pref = "system";
  try { pref = localStorage.getItem("whaxon-theme") || "system"; } catch (e) {}
  applyTheme(pref);
  // authoritative source: server settings
  fetch("/api/settings", { credentials: "same-origin" })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (d) {
      if (d && d.theme) {
        try { localStorage.setItem("whaxon-theme", d.theme); } catch (e) {}
        applyTheme(d.theme);
      }
    })
    .catch(function () {});
  document.querySelectorAll(".theme-toggle button").forEach(function (b) {
    b.addEventListener("click", function () { setThemePref(b.dataset.themeValue); });
  });
  if (window.matchMedia) {
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", function () {
      var cur = "system";
      try { cur = localStorage.getItem("whaxon-theme") || "system"; } catch (e) {}
      if (cur === "system") applyTheme("system");
    });
  }
}


window.addEventListener("DOMContentLoaded", () => {
  wireThemeToggle();
  loadCatalog().catch((e) => setStatus("failed to load catalog: " + e));
  loadHistory();
  wireBurpUpload();
  wireReportDownload();
  wireScopeModal();
  wireViewTabs();
  refreshMsfIndicator();
  wireSessionConsole();
  setInterval(refreshMsfIndicator, 10000);
  setInterval(refreshSessionList, 10000);
  $("#run").addEventListener("click", runTool);
  $("#cancel").addEventListener("click", cancelJob);
  $("#target").addEventListener("keydown", (e) => { if (e.key === "Enter") runTool(); });
  const extraEl = $("#extra");
  if (extraEl) {
    extraEl.addEventListener("keydown", (e) => { if (e.key === "Enter") runTool(); });
  }
});

async function loadLoot() {
  const el = document.getElementById('loot');
  if (!el) return;
  el.innerHTML = '<div class="hint">loading loot…</div>';
  try {
    const res = await fetch('/api/loot');
    const data = await res.json();
    if (!data.loot || data.loot.length === 0) {
      el.innerHTML = '<div class="hint">no loot findings yet</div>';
      return;
    }
    const byKind = {};
    for (const f of data.loot) {
      (byKind[f.kind] = byKind[f.kind] || []).push(f);
    }
    let html = '<h2 style="margin-top:8px">Loot (' + data.count + ')</h2>';
    for (const kind of Object.keys(byKind).sort()) {
      html += '<h3 style="margin-top:12px">' + kind + ' (' + byKind[kind].length + ')</h3>';
      html += '<table class="findings-table"><tr><th>Detail</th><th>Job</th></tr>';
      for (const f of byKind[kind]) {
        const d = f.data || {};
        let detail = '';
        if (kind === 'env_var') detail = d.name + ' = ' + d.value;
        else if (kind === 'sysinfo' || kind === 'platform') detail = (d.field || 'platform') + ': ' + (d.value || d.platform || '');
        else if (kind === 'ntlm_hash') detail = d.user + '  NT=' + d.nt_hash;
        else if (kind === 'service') detail = d.port + '/' + d.proto + '  ' + d.state + '  ' + d.name;
        else if (kind === 'msf_session') detail = 'session ' + d.session_id + ' on ' + d.host;
        else detail = f.raw_line || JSON.stringify(d);
        html += '<tr><td>' + detail + '</td><td>' + (f._job_id || '') + '</td></tr>';
      }
      html += '</table>';
    }
    el.innerHTML = html;
  } catch (e) {
    el.innerHTML = '<div class="hint">error: ' + e.message + '</div>';
  }
}


/* ---------- Report download ---------- */
function wireReportDownload() {
  const btn = document.getElementById("report-download");
  if (!btn) return;
  btn.addEventListener("click", () => {
    const _a = document.createElement("a");
    _a.href = "/api/report?format=md";
    _a.download = "whaxon-report.md";
    document.body.appendChild(_a);
    _a.click();
    _a.remove();
  });
}


/* ---------- Safety banner ---------- */
async function refreshSafetyBanner() {
  const el = document.getElementById("safety-banner");
  if (!el) return;
  try {
    const s = await fetch("/api/status").then((r) => r.json());
    const parts = [];
    if (!s.scope_enabled) {
      parts.push('<span class="pill">SCOPE DISABLED</span> every target is allowed');
    } else {
      parts.push('<span class="pill ok">SCOPE ON</span> engagement: <b>' + escapeHtml(s.engagement) + '</b>');
    }
    if (s.default_creds) {
      parts.push('<span class="pill">DEFAULT CREDS</span> change WHAXON_AUTH_USER / WHAXON_AUTH_PASS');
    }
    if (s.autochain) {
      parts.push('<span class="pill">AUTOCHAIN</span> post modules run automatically after exploits');
    }
    if (!s.msf_up) {
      parts.push('<span class="pill">MSF OFFLINE</span>');
    }
    el.innerHTML = parts.join('&nbsp;&nbsp;|&nbsp;&nbsp;');
    el.style.display = "flex";
  } catch (e) {
    el.style.display = "none";
  }
}

async function loadChain() {
  const el = document.getElementById('chain');
  if (el === null) return;
  el.innerHTML = '<div class="hint">loading chain...</div>';
  try {
    const res = await fetch('/api/pivot/graph');
    const data = await res.json();
    const edges = data.edges || [];
    if (edges.length === 0) {
      el.innerHTML = '<div class="hint">no pivot activity yet.</div>';
      return;
    }
    const byRoot = {};
    for (const e of edges) {
      if (e.relation === 'from_exploit') {
        const root = e.parent.id || '(unknown)';
        if (byRoot[root] === undefined) byRoot[root] = { children: [] };
        byRoot[root].children.push(e);
      }
    }
    for (const root of Object.keys(byRoot)) {
      const sess = new Set(byRoot[root].children.map(c => c.child.id));
      for (const e of edges) {
        if (e.relation !== 'from_exploit' && sess.has(e.parent.id)) {
          byRoot[root].children.push(e);
        }
      }
    }
    let html = '<h2>Pivot chain (' + edges.length + ' edges)</h2>';
    for (const root of Object.keys(byRoot)) {
      const g = byRoot[root];
      html += '<div class="chain-root">';
      html += '<div class="chain-node chain-exploit">exploit job ' + escapeHtml(root) + '</div>';
      for (const c of g.children) {
        const cls = 'chain-node chain-' + c.child.kind;
        const ev = c.evidence ? ' <span class="chain-evidence">(' + escapeHtml(c.evidence) + ')</span>' : '';
        html += '<div class="chain-edge">&rarr; <span class="' + cls + '">' + escapeHtml(c.child.kind + ' ' + c.child.id) + ev + '</span></div>';
      }
      html += '</div>';
    }
    el.innerHTML = html;
  } catch (e) {
    el.innerHTML = '<div class="hint">error: ' + e.message + '</div>';
  }
}