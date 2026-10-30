(function () {
  const app = document.getElementById('app');
  const palette = document.getElementById('palette');
  const paletteInput = document.getElementById('palette-input');
  const slideover = document.getElementById('slideover');
  const notifPanel = document.getElementById('notif-panel');
  const kbdLegend = document.getElementById('kbd-legend');
  const bulkBar = document.getElementById('bulk-bar');
  const bulkCount = document.getElementById('bulk-count');
  const selectAll = document.getElementById('select-all');

  // page navigation
  document.querySelectorAll('.sb-item[data-page]').forEach(item => {
    item.addEventListener('click', () => {
      const p = item.dataset.page;
      document.querySelectorAll('.page').forEach(el => el.classList.remove('active'));
      const target = document.getElementById('page-' + p) || document.getElementById('page-findings');
      target.classList.add('active');
      document.querySelectorAll('.sb-item').forEach(i => i.classList.remove('active'));
      item.classList.add('active');
      document.getElementById('crumb-here').textContent = p.charAt(0).toUpperCase() + p.slice(1);
    });
  });

  // sidebar collapse
  document.getElementById('collapse-btn').addEventListener('click', () => app.classList.toggle('collapsed'));

  // density
  document.querySelectorAll('.density-toggle button').forEach(btn => {
    btn.addEventListener('click', () => {
      document.body.dataset.density = btn.dataset.density;
      document.querySelectorAll('.density-toggle button').forEach(b => b.classList.remove('on'));
      btn.classList.add('on');
    });
  });

  // findings slide-over
  document.querySelectorAll('#findings-table tbody tr').forEach(row => {
    row.addEventListener('click', (e) => {
      if (e.target.closest('.checkbox-col') || e.target.closest('.copy-btn')) return;
      document.querySelectorAll('#findings-table tbody tr').forEach(r => r.classList.remove('selected'));
      row.classList.add('selected');
      slideover.classList.add('open');
      document.getElementById('so-title').textContent = row.querySelector('.title').textContent;
    });
  });
  window.closeSlideover = () => slideover.classList.remove('open');

  // bulk selection
  function updateBulk() {
    const checked = document.querySelectorAll('#findings-table .row-cb:checked').length;
    bulkCount.textContent = checked;
    bulkBar.classList.toggle('on', checked > 0);
  }
  document.querySelectorAll('#findings-table .row-cb').forEach(cb => cb.addEventListener('change', updateBulk));
  if (selectAll) selectAll.addEventListener('change', () => {
    document.querySelectorAll('#findings-table .row-cb').forEach(cb => cb.checked = selectAll.checked);
    updateBulk();
  });

  // copy buttons
  document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const text = btn.closest('td').querySelector('.target, .mono')?.textContent?.trim();
      if (text) navigator.clipboard?.writeText(text);
    });
  });

  // palette
  document.getElementById('palette-trigger').addEventListener('click', () => { palette.classList.add('open'); paletteInput.focus(); });

  // notifications
  document.getElementById('notif-trigger').addEventListener('click', e => { e.stopPropagation(); notifPanel.classList.toggle('open'); });

  // shortcuts
  document.getElementById('help-trigger').addEventListener('click', () => kbdLegend.classList.add('open'));

  // workspace
  document.querySelector('.sb-workspace').addEventListener('click', () => document.getElementById('ws-modal').classList.add('open'));

  // table sort


  // chips
  document.querySelectorAll('.chip').forEach(c => c.addEventListener('click', () => c.classList.toggle('on')));

  // accordion
  document.querySelectorAll('.acc-head').forEach(h => h.addEventListener('click', () => h.parentElement.classList.toggle('open')));

  // graph nodes
  document.querySelectorAll('.asg-node').forEach(node => {
    node.addEventListener('click', () => {
      document.querySelectorAll('.sb-item').forEach(i => i.classList.remove('active'));
      document.querySelector('.sb-item[data-page="findings"]')?.classList.add('active');
      document.querySelectorAll('.page').forEach(el => el.classList.remove('active'));
      document.getElementById('page-findings').classList.add('active');
      document.getElementById('crumb-here').textContent = 'Findings';
    });
  });

  // outside click closes
  document.addEventListener('click', e => {
    if (!notifPanel.contains(e.target) && e.target.id !== 'notif-trigger') notifPanel.classList.remove('open');
  });

  // keyboard
  document.addEventListener('keydown', e => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') { e.preventDefault(); palette.classList.toggle('open'); if (palette.classList.contains('open')) paletteInput.focus(); }
    if ((e.metaKey || e.ctrlKey) && e.key === 'b') { e.preventDefault(); app.classList.toggle('collapsed'); }
    if (e.key === 'Escape') { palette.classList.remove('open'); closeSlideover(); notifPanel.classList.remove('open'); kbdLegend.classList.remove('open'); document.querySelectorAll('.scope-modal, .confirm-modal, .ws-modal').forEach(m => m.classList.remove('open')); }
    if (e.key === '?' && document.activeElement.tagName !== 'INPUT') kbdLegend.classList.toggle('open');
  });

  palette.addEventListener('click', e => { if (e.target === palette) palette.classList.remove('open'); });
  document.getElementById('ws-modal').addEventListener('click', e => { if (e.target.id === 'ws-modal') e.target.classList.remove('open'); });
})();


// ---- Scope page wiring ----
(function () {
  const rulesEl = document.getElementById('scope-rules');
  const countEl = document.getElementById('scope-count');
  const inputEl = document.getElementById('scope-check-input');
  const btnEl = document.getElementById('scope-check-btn');
  const resultEl = document.getElementById('scope-check-result');
  if (!rulesEl || !countEl) return;

  function row(label, value) {
    const d = document.createElement('div');
    d.className = 'kv';
    const k = document.createElement('span');
    k.className = 'k';
    k.textContent = label;
    const v = document.createElement('span');
    v.className = 'v';
    v.textContent = value;
    d.appendChild(k);
    d.appendChild(v);
    return d;
  }

  function classify(rule) {
    if (rule.includes('/')) return 'Network';
    if (/^\[[0-9a-fA-F:]+\]$/.test(rule) || /^[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,}$/.test(rule)) return 'Address';
    if (/:[0-9]+$/.test(rule)) return 'Host:port';
    if (/^[0-9.]+$/.test(rule)) return 'Address';
    return 'Host';
  }

  function render(data) {
    rulesEl.innerHTML = '';
    const eng = data.engagement || '(unnamed)';
    rulesEl.appendChild(row('Engagement', eng));
    const list = data.in_scope || [];
    countEl.textContent = list.length;
    list.forEach(rule => rulesEl.appendChild(row(classify(rule), rule)));
    const out = data.out_of_scope || [];
    out.forEach(rule => {
      const d = row('Excluded', rule);
      d.querySelector('.v').style.color = 'var(--critical)';
      rulesEl.appendChild(d);
    });
    if (data.notes) {
      const n = document.createElement('div');
      n.style.marginTop = '12px';
      n.style.fontSize = 'var(--t-xs)';
      n.style.color = 'var(--text-mute)';
      n.style.fontFamily = 'var(--font-mono)';
      n.textContent = data.notes;
      rulesEl.appendChild(n);
    }
  }

  function loadScope() {
    fetch('/api/scope')
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(data => render(data))
      .catch(err => {
        rulesEl.innerHTML = '';
        rulesEl.appendChild(row('Error', 'Failed to load scope: ' + err));
        countEl.textContent = '—';
      });
  }

  function showResult(html, kind) {
    resultEl.innerHTML = '';
    const d = document.createElement('div');
    d.style.marginTop = '16px';
    d.style.padding = '12px';
    d.style.borderRadius = 'var(--r-md)';
    d.style.fontSize = 'var(--t-sm)';
    if (kind === 'ok') {
      d.style.background = 'var(--low-dim)';
      d.style.color = 'var(--low)';
    } else if (kind === 'denied') {
      d.style.background = 'var(--critical-dim)';
      d.style.color = 'var(--critical)';
    } else {
      d.style.background = 'var(--bg-elev-2)';
      d.style.color = 'var(--text-dim)';
    }
    d.textContent = html;
    resultEl.appendChild(d);
  }

  function checkScope() {
    const target = (inputEl.value || '').trim();
    if (!target) {
      showResult('Enter a target first.', 'warn');
      return;
    }
    btnEl.disabled = true;
    fetch('/api/scope/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: target })
    })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(data => {
        if (data.allowed || data.in_scope) {
          const reason = data.reason || data.matched_rule || 'matched in-scope rule';
          showResult('✓ ' + target + ' is in scope (' + reason + ')', 'ok');
        } else {
          const reason = data.reason || 'no matching in-scope rule';
          showResult('✗ ' + target + ' is not in scope (' + reason + ')', 'denied');
        }
      })
      .catch(err => showResult('Check failed: ' + err, 'warn'))
      .finally(() => { btnEl.disabled = false; });
  }

  if (btnEl) btnEl.addEventListener('click', checkScope);
  if (inputEl) inputEl.addEventListener('keydown', e => { if (e.key === 'Enter') checkScope(); });

  const scopeNav = document.querySelector('.sb-item[data-page="scope"]');
  if (scopeNav) scopeNav.addEventListener('click', loadScope);

  document.addEventListener('DOMContentLoaded', loadScope);
  if (document.readyState !== 'loading') loadScope();
})();


// ---- Findings page wiring ----
(function () {
  const tbody = document.getElementById('findings-tbody');
  if (!tbody) return;

  let sortKey = 'severity';
  let sortAsc = true;

  document.addEventListener('whaxon:findings-resort', () => {
    renderTable(sortRows(window._whaxonFindings || [], sortKey, sortAsc));
  });

  document.querySelectorAll('.tbl thead th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      const key = th.dataset.sort;
      if (key === sortKey) sortAsc = !sortAsc;
      else { sortKey = key; sortAsc = true; }
      document.querySelectorAll('.tbl thead th').forEach(x => { x.classList.remove('sorted'); const s = x.querySelector('.sort'); if (s) s.textContent = '·'; });
      th.classList.add('sorted');
      const s = th.querySelector('.sort'); if (s) s.textContent = sortAsc ? '▴' : '▾';
      document.dispatchEvent(new CustomEvent('whaxon:findings-resort'));
    });
  });
  const summaryEl = document.getElementById('findings-summary');
  const donutSummary = document.getElementById('donut-summary');

  const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
  const SEV_PILL = {
    critical: 'pill-critical',
    high: 'pill-high',
    medium: 'pill-medium',
    low: 'pill-low',
    info: 'pill-info'
  };
  const SEV_LABEL = {
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
    info: 'Info'
  };

  function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  }

  function renderKpis(sev) {
    setText('kpi-critical', sev.critical || 0);
    setText('kpi-high', sev.high || 0);
    setText('kpi-medium', sev.medium || 0);
    setText('kpi-low', (sev.low || 0) + (sev.info || 0));
    setText('legend-critical', sev.critical || 0);
    setText('legend-high', sev.high || 0);
    setText('legend-medium', sev.medium || 0);
    setText('legend-low', (sev.low || 0) + (sev.info || 0));
  }

  function renderDonut(sev) {
    const total = (sev.critical || 0) + (sev.high || 0) + (sev.medium || 0) + (sev.low || 0) + (sev.info || 0);
    const map = [
      ['donut-critical', sev.critical || 0],
      ['donut-high', sev.high || 0],
      ['donut-medium', sev.medium || 0],
      ['donut-low', (sev.low || 0) + (sev.info || 0)]
    ];
    if (total === 0) {
      map.forEach(([id]) => {
        const c = document.getElementById(id);
        if (c) c.setAttribute('stroke-dasharray', '0 100');
      });
      return;
    }
    let offset = 25;
    map.forEach(([id, count]) => {
      const pct = (count / total) * 100;
      const c = document.getElementById(id);
      if (c) {
        c.setAttribute('stroke-dasharray', pct.toFixed(2) + ' ' + (100 - pct).toFixed(2));
        c.setAttribute('stroke-dashoffset', offset.toFixed(2));
      }
      offset -= pct;
    });
  }

  function flattenFindings(jobs) {
    const out = [];
    (jobs || []).forEach(entry => {
      const job = entry.job || {};
      (entry.findings || []).forEach(f => {
        out.push({
          severity: (f.severity || 'info').toLowerCase(),
          title: f.title || f.kind || f.raw_line || '(finding)',
          target: job.target || f.target || '',
          source: f.source || job.tool || '',
          status: f.verification_status || f.status || 'candidate',
          verified_by: f.verified_by || 'engine',
          job_id: job.id || '',
          seq: f.seq || 0,
          _raw: f,
          _job: job
        });
      });
    });
    out.sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
    return out;
  }

  function renderTable(findings) {
    tbody.innerHTML = '';
    findings.forEach(f => {
      const tr = document.createElement('tr');
      const pillCls = SEV_PILL[f.severity] || 'pill-info';
      const sevLabel = SEV_LABEL[f.severity] || 'Info';
      const statusCls = f.status === 'verified' ? 'pill-success' : 'pill-accent';
      const statusLabel = f.status === 'verified' ? 'Verified' : 'Candidate';
      tr.innerHTML =
        '<td class="checkbox-col"><input type="checkbox" class="cb row-cb"></td>' +
        '<td><span class="pill ' + pillCls + '"><span class="dot"></span>' + sevLabel + '</span></td>' +
        '<td><span class="title"></span></td>' +
        '<td><span class="target"></span></td>' +
        '<td><span class="mono"></span></td>' +
        '<td><span class="pill ' + statusCls + '">' + statusLabel + '</span></td>';
      tr.querySelector('.title').textContent = f.title;
      tr.querySelector('.target').textContent = f.target;
      tr.querySelector('.mono').textContent = f.source;
      tr.dataset.severity = f.severity;
      tr.dataset.title = f.title;
      tr.dataset.target = f.target;
      tr.dataset.source = f.source;
      tr.dataset.status = f.status;
      if (f._raw && f._raw.raw_line) tr.dataset.rawLine = f._raw.raw_line;
      if (f._raw && f._raw.data) {
        if (f._raw.data.description) tr.dataset.description = f._raw.data.description;
        if (f._raw.data.remediation) tr.dataset.remediation = f._raw.data.remediation;
      }
      tr.addEventListener('click', e => {
        if (e.target.closest('.checkbox-col')) return;
        openSlideover(tr);
      });
      tbody.appendChild(tr);
    });
  }

  function openSlideover(tr) {
    const so = document.getElementById('slideover');
    if (!so) return;
    const sev = tr.dataset.severity || 'info';
    const sevEl = document.getElementById('so-sev');
    if (sevEl) {
      sevEl.className = 'pill ' + (SEV_PILL[sev] || 'pill-info');
      sevEl.innerHTML = '<span class="dot"></span>' + (SEV_LABEL[sev] || 'Info');
    }
    const titleEl = document.getElementById('so-title');
    if (titleEl) titleEl.textContent = tr.dataset.title || '';
    const metaEl = document.getElementById('so-meta');
    if (metaEl) metaEl.textContent = [tr.dataset.target, tr.dataset.source].filter(Boolean).join(' · ');

    const descSection = document.getElementById('so-desc-section');
    const descEl = document.getElementById('so-desc');
    if (tr.dataset.description) { descEl.textContent = tr.dataset.description; descSection.style.display = ''; }
    else { descSection.style.display = 'none'; }

    const evSection = document.getElementById('so-evidence-section');
    const evEl = document.getElementById('so-evidence');
    if (tr.dataset.rawLine) { evEl.textContent = tr.dataset.rawLine; evSection.style.display = ''; }
    else { evSection.style.display = 'none'; }

    const remSection = document.getElementById('so-remediation-section');
    const remEl = document.getElementById('so-remediation');
    if (tr.dataset.remediation) { remEl.textContent = tr.dataset.remediation; remSection.style.display = ''; }
    else { remSection.style.display = 'none'; }

    // Validate / Retest buttons (§34.2 step 5)
    const jobId = tr.dataset.jobId || '';
    const seq = tr.dataset.seq || '0';
    const valBtn = document.getElementById('so-validate');
    const retBtn = document.getElementById('so-retest');
    if (valBtn && retBtn && jobId && seq !== undefined) {
      valBtn.style.display = '';
      retBtn.style.display = '';
      const st = tr.dataset.status || 'candidate';
      // Validate only makes sense on unverified. Retest only on verified.
      valBtn.disabled = st !== 'candidate';
      retBtn.disabled = st !== 'verified';
      valBtn.onclick = () => postAction('validate', jobId, seq, valBtn);
      retBtn.onclick = () => postAction('retest', jobId, seq, retBtn);
    } else if (valBtn && retBtn) {
      valBtn.style.display = 'none';
      retBtn.style.display = 'none';
    }
    so.classList.add('open');
  }

  async function postAction(kind, jobId, seq, btn) {
    const original = btn.textContent;
    btn.disabled = true;
    btn.textContent = '...';
    try {
      const r = await fetch('/api/' + kind + '/' + encodeURIComponent(jobId) + '/' + seq, { method: 'POST' });
      const data = await r.json();
      if (!r.ok) {
        alert((data.error || 'error') + (data.verification_status ? ' (current: ' + data.verification_status + ')' : ''));
      } else {
        // Update the slide-over and re-render the row.
        const tr = document.querySelector('#findings-tbody tr.selected');
        if (tr) {
          tr.dataset.status = data.status;
          const statusCell = tr.querySelector('.pill');
          // Find the status cell by class (last pill in the row)
          const cells = tr.querySelectorAll('td');
          if (cells.length >= 6) {
            const last = cells[5].querySelector('.pill');
            if (last) {
              const MAP = {
                verified: ['pill-success', 'Verified'],
                candidate: ['pill-accent', 'Candidate'],
                refuted: ['pill-neutral', 'Refuted'],
                fixed: ['pill-low', 'Fixed'],
                still_vulnerable: ['pill-critical', 'Still Vulnerable']
              };
              const [cls, label] = MAP[data.status] || ['pill-accent', data.status];
              last.className = 'pill ' + cls;
              last.textContent = label;
            }
          }
        }
        alert(kind + ': ' + data.status + '\n' + data.reason);
      }
    } catch (e) {
      alert(kind + ' failed: ' + e);
    } finally {
      btn.disabled = false;
      btn.textContent = original;
    }
  }

  function sortRows(rows, key, asc) {
    const copy = rows.slice();
    if (key === 'severity') {
      copy.sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
    } else {
      copy.sort((a, b) => (a[key] || '').localeCompare(b[key] || ''));
    }
    if (!asc) copy.reverse();
    return copy;
  }

  function loadFindings() {
    fetch('/api/report?format=json')
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(data => {
        const sev = data.severity_counts || {};
        const jobCount = data.job_count || 0;
        const findingCount = data.finding_count || 0;
        const categories = SEV_ORDER.filter(s => (sev[s] || 0) > 0).length;

        renderKpis(sev);
        renderDonut(sev);

        if (summaryEl) {
          summaryEl.textContent = findingCount + ' findings across ' + jobCount + ' jobs';
        }
        if (donutSummary) {
          donutSummary.textContent = findingCount + ' total · ' + jobCount + ' jobs · ' + categories + ' categories';
        }

        const rows = flattenFindings(data.jobs);
        window._whaxonFindings = rows;
        renderTable(sortRows(rows, sortKey, sortAsc));
      })
      .catch(err => {
        tbody.innerHTML = '<tr><td colspan="6" style="padding:16px; color:var(--critical);">Failed to load findings: ' + err + '</td></tr>';
      });
  }

  document.addEventListener('DOMContentLoaded', loadFindings);
  if (document.readyState !== 'loading') loadFindings();
})();


// ---- Run page wiring ----
(function () {
  const catalogEl = document.getElementById('run-catalog');
  if (!catalogEl) return;

  const countEl = document.getElementById('run-catalog-count');
  const targetEl = document.getElementById('run-target');
  const extraEl = document.getElementById('run-extra');
  const runBtn = document.getElementById('run-btn');
  const cancelBtn = document.getElementById('run-cancel-btn');
  const scopePill = document.getElementById('run-scope-pill');
  const outputEl = document.getElementById('run-output');
  const jobIdEl = document.getElementById('run-job-id');
  const recentEl = document.getElementById('run-recent-jobs');

  let selectedTool = null;
  let currentJob = null;
  let eventSource = null;

  function showScopePill(kind, text) {
    if (!scopePill) return;
    scopePill.className = 'pill ' + (kind === 'ok' ? 'pill-success' : 'pill-danger');
    scopePill.innerHTML = '<span class="dot"></span>' + text;
    scopePill.style.display = '';
  }

  function hideScopePill() {
    if (scopePill) scopePill.style.display = 'none';
  }

  function appendLine(stream, text) {
    if (!outputEl) return;
    const span = document.createElement('span');
    span.className = 'ln' + (stream === 'stderr' ? ' err' : '');
    span.textContent = text;
    outputEl.appendChild(span);
    outputEl.scrollTop = outputEl.scrollHeight;
  }

  function clearOutput() {
    if (outputEl) outputEl.innerHTML = '';
  }

  function renderCatalog(tools) {
    catalogEl.innerHTML = '';
    (tools || []).forEach(tool => {
      const item = document.createElement('div');
      item.className = 'tool-item';
      item.dataset.toolId = tool.id;
      const icon = document.createElement('span');
      icon.className = 'ticon';
      icon.textContent = (tool.name || tool.id || '?').charAt(0).toLowerCase();
      const name = document.createTextNode(tool.name || tool.id);
      const tid = document.createElement('span');
      tid.className = 'tid';
      tid.textContent = tool.id;
      item.appendChild(icon);
      item.appendChild(name);
      item.appendChild(tid);
      item.addEventListener('click', () => {
        catalogEl.querySelectorAll('.tool-item').forEach(i => i.classList.remove('on'));
        item.classList.add('on');
        selectedTool = tool.id;
        runBtn.textContent = '▶ Run ' + (tool.name || tool.id);
      });
      catalogEl.appendChild(item);
    });
    if (countEl) countEl.textContent = (tools || []).length + ' tools';
  }

  function renderRecent(jobs) {
    if (!recentEl) return;
    recentEl.innerHTML = '';
    (jobs || []).slice(0, 8).forEach(job => {
      const tr = document.createElement('tr');
      const tool = document.createElement('td');
      tool.innerHTML = '<span class="mono"></span>';
      tool.querySelector('.mono').textContent = job.tool || '—';
      const target = document.createElement('td');
      target.textContent = job.target || '—';
      const status = document.createElement('td');
      const statusCls = job.status === 'finished' ? 'pill-success' :
                        job.status === 'failed' ? 'pill-danger' :
                        job.status === 'running' ? 'pill-accent' : 'pill-neutral';
      status.innerHTML = '<span class="pill ' + statusCls + '"></span>';
      status.querySelector('.pill').textContent = job.status || '—';
      const findings = document.createElement('td');
      findings.style.textAlign = 'right';
      findings.innerHTML = '<span class="mono"></span>';
      findings.querySelector('.mono').textContent = (job.findings_count || 0) + ' findings';
      tr.appendChild(tool); tr.appendChild(target); tr.appendChild(status); tr.appendChild(findings);
      recentEl.appendChild(tr);
    });
  }

  function loadCatalog() {
    fetch('/api/tools')
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(data => {
        const tools = Array.isArray(data) ? data : (data.tools || []);
        renderCatalog(tools);
      })
      .catch(err => { if (countEl) countEl.textContent = 'load failed'; });
  }

  function loadRecent() {
    fetch('/api/history')
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(data => {
        const jobs = Array.isArray(data) ? data : (data.jobs || []);
        renderRecent(jobs);
      })
      .catch(() => {});
  }

  function closeStream() {
    if (eventSource) { eventSource.close(); eventSource = null; }
  }

  function setRunning(running) {
    if (runBtn) runBtn.disabled = running;
    if (cancelBtn) cancelBtn.disabled = !running;
  }

  function openStream(jobId) {
    closeStream();
    const es = new EventSource('/api/jobs/' + jobId + '/stream');
    eventSource = es;
    es.onmessage = (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch (_) { return; }
      if (msg.type === 'line') {
        appendLine(msg.stream, msg.text);
      } else if (msg.type === 'finished') {
        appendLine('stdout', '[finished, exit ' + msg.exit_code + ']');
        setRunning(false);
        closeStream();
        loadRecent();
      } else if (msg.type === 'failed') {
        appendLine('stderr', '[failed: ' + (msg.error || 'unknown') + ']');
        setRunning(false);
        closeStream();
        loadRecent();
      }
    };
    es.onerror = () => {
      closeStream();
      setRunning(false);
    };
  }

  function runJob() {
    const target = (targetEl.value || '').trim();
    if (!selectedTool) { alert('Pick a tool first.'); return; }
    if (!target) { alert('Enter a target.'); return; }
    clearOutput();
    hideScopePill();
    setRunning(true);
    fetch('/api/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool_id: selectedTool,
        target: target,
        extra_args: (extraEl.value || '').trim(),
      }),
    })
      .then(r => r.json().then(body => ({ ok: r.ok, status: r.status, body })))
      .then(({ ok, status, body }) => {
        if (!ok) {
          setRunning(false);
          if (status === 403) showScopePill('denied', 'Out of scope');
          appendLine('stderr', body.error || ('error ' + status));
          return;
        }
        currentJob = body.job_id;
        if (jobIdEl) jobIdEl.textContent = 'Job ' + currentJob;
        openStream(currentJob);
      })
      .catch(err => {
        setRunning(false);
        appendLine('stderr', 'Request failed: ' + err);
      });
  }

  function cancelJob() {
    if (!currentJob) return;
    fetch('/api/jobs/' + currentJob + '/cancel', { method: 'POST' })
      .then(() => { setRunning(false); closeStream(); })
      .catch(() => {});
  }

  if (runBtn) runBtn.addEventListener('click', runJob);
  if (cancelBtn) cancelBtn.addEventListener('click', cancelJob);

  // ---- Approvals (§4.4) ----
  const approvalsList = document.getElementById('approvals-list');
  const approvalsOwner = document.getElementById('approvals-owner');
  const approvalsSummary = document.getElementById('approvals-summary');
  const approvalsBadge = document.getElementById('approvals-badge');

  async function loadApprovals() {
    if (!approvalsList) return;
    const owner = (approvalsOwner && approvalsOwner.value || '').trim();
    const qs = owner ? ('?owner=' + encodeURIComponent(owner)) : '';
    try {
      const rows = await (await fetch('/api/ai/pending' + qs)).json();
      if (approvalsBadge) {
        approvalsBadge.textContent = String(rows.length);
        approvalsBadge.style.display = rows.length ? '' : 'none';
      }
      if (approvalsSummary) {
        approvalsSummary.textContent = rows.length + ' run' + (rows.length === 1 ? '' : 's') + ' awaiting a decision';
      }
      if (!rows.length) {
        approvalsList.innerHTML = '<div class="card-sub" style="padding:24px;">No pending approvals.</div>';
        return;
      }
      approvalsList.innerHTML = rows.map(r => {
        const q = r.pending_question || {};
        const rationale = (q.rationale || '(no rationale)').replace(/</g, '&lt;');
        const conf = (typeof q.confidence === 'number') ? q.confidence.toFixed(2) : '—';
        const phase = (q.proposed_phase || '');
        const ownerLabel = r.owner || 'local';
        return '<div class="card" data-run="' + r.id + '" style="margin-bottom:12px;">' +
          '<div class="card-title">' + rationale + '</div>' +
          '<div class="card-sub">run ' + r.id + ' · owner ' + ownerLabel + ' · confidence ' + conf +
            (phase ? (' · proposed phase <b>' + phase + '</b>') : '') + '</div>' +
          '<div style="display:flex;gap:8px;margin-top:12px;align-items:center;">' +
            '<input class="form-input" data-answer-input placeholder="answer (e.g. y, no, notes)" style="flex:1;">' +
            '<button class="btn btn-primary btn-sm" data-answer-btn>Answer</button>' +
          '</div>' +
        '</div>';
      }).join('');
      approvalsList.querySelectorAll('.card[data-run]').forEach(card => {
        const btn = card.querySelector('[data-answer-btn]');
        const input = card.querySelector('[data-answer-input]');
        btn.addEventListener('click', async () => {
          const runId = card.dataset.run;
          const answer = (input.value || '').trim();
          if (!answer) { input.focus(); return; }
          btn.disabled = true;
          try {
            const r = await fetch('/api/ai/runs/' + encodeURIComponent(runId) + '/answer', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({answer: answer, user: owner || 'web'})
            });
            if (r.ok || r.status === 409) { await loadApprovals(); }
            else { btn.disabled = false; }
          } catch (_e) { btn.disabled = false; }
        });
      });
    } catch (_e) {
      if (approvalsSummary) approvalsSummary.textContent = 'Failed to load approvals';
    }
  }

  const approvalsRefresh = document.getElementById('approvals-refresh');
  if (approvalsRefresh) approvalsRefresh.addEventListener('click', loadApprovals);
  if (approvalsOwner) approvalsOwner.addEventListener('keydown', e => { if (e.key === 'Enter') loadApprovals(); });
  document.querySelectorAll('.sb-item[data-page="approvals"]').forEach(el => {
    el.addEventListener('click', loadApprovals);
  });

  document.addEventListener('DOMContentLoaded', () => { loadCatalog(); loadRecent(); });
  if (document.readyState !== 'loading') { loadCatalog(); loadRecent(); }
})();

// ---- Coverage page wiring (§34.2 step 4) ----
(function () {
  const tbody = document.getElementById('coverage-tbody');
  if (!tbody) return;
  const countEl = document.getElementById('coverage-count');
  const summaryEl = document.getElementById('coverage-summary');

  function render(gaps) {
    if (!gaps || gaps.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" style="padding:16px; color:var(--text-dim);">No coverage gaps recorded for this engagement.</td></tr>';
      if (countEl) countEl.textContent = '0';
      if (summaryEl) summaryEl.textContent = 'Every step either ran or was not attempted.';
      return;
    }
    const KIND_PILL = {
      scope_blocked: 'pill-warning',
      binary_missing: 'pill-neutral',
      timeout: 'pill-medium',
      auth_required: 'pill-accent',
      waf_blocked: 'pill-critical',
    };
    tbody.innerHTML = '';
    gaps.forEach(g => {
      const tr = document.createElement('tr');
      const cls = KIND_PILL[g.kind] || 'pill-info';
      tr.innerHTML =
        '<td><span class="pill ' + cls + '">' + g.kind + '</span></td>' +
        '<td><span class="mono"></span></td>' +
        '<td><span class="target"></span></td>' +
        '<td><span class="title"></span></td>';
      tr.querySelector('.mono').textContent = g.tool_id;
      tr.querySelector('.target').textContent = g.target;
      tr.querySelector('.title').textContent = g.detail;
      tbody.appendChild(tr);
    });
    if (countEl) countEl.textContent = String(gaps.length);
    if (summaryEl) summaryEl.textContent = gaps.length + ' skipped step(s) across the engagement.';
  }

  function loadCoverage() {
    fetch('/api/report?format=json')
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(data => {
        const jobs = data.jobs || [];
        const all = [];
        jobs.forEach(entry => {
          (entry.coverage || []).forEach(c => all.push(c));
        });
        render(all);
      })
      .catch(err => {
        tbody.innerHTML = '<tr><td colspan="4" style="padding:16px; color:var(--critical);">Failed to load coverage: ' + err + '</td></tr>';
      });
  }

  document.addEventListener('DOMContentLoaded', loadCoverage);
  if (document.readyState !== 'loading') loadCoverage();
})();

// ---- Pending findings review (§34.2 step 6) ----
(function () {
  const list = document.getElementById('pending-findings-list');
  if (!list) return;
  const countEl = document.getElementById('pending-findings-count');

  async function loadPending() {
    try {
      const data = await (await fetch('/api/report?format=json')).json();
      const pending = [];
      (data.jobs || []).forEach(entry => {
        const job = entry.job || {};
        (entry.findings || []).forEach(f => {
          if ((f.verification_status || 'candidate') === 'candidate') {
            pending.push({ job, f });
          }
        });
      });
      if (countEl) countEl.textContent = String(pending.length);
      if (!pending.length) {
        list.innerHTML = '<div class="card-sub" style="padding:12px;">No findings waiting for human review.</div>';
        return;
      }
      list.innerHTML = pending.slice(0, 50).map(({ job, f }) => {
        const title = (f.title || f.kind || f.raw_line || '(finding)').replace(/</g, '&lt;');
        const target = (job.target || '').replace(/</g, '&lt;');
        return '<div class="card" data-job="' + job.id + '" data-seq="' + (f.seq || 0) + '" style="margin-bottom:8px;">' +
          '<div class="card-title">' + title + '</div>' +
          '<div class="card-sub">job ' + job.id + ' · seq ' + (f.seq || 0) + ' · target ' + target + ' · ' + (f.severity || 'info') + '</div>' +
          '<div style="display:flex;gap:8px;margin-top:8px;">' +
            '<button class="btn btn-primary btn-sm" data-resolve="verified">Mark Verified</button>' +
            '<button class="btn btn-ghost btn-sm" data-resolve="refuted">Mark Refuted</button>' +
          '</div>' +
        '</div>';
      }).join('');
      list.querySelectorAll('.card[data-job]').forEach(card => {
        card.querySelectorAll('[data-resolve]').forEach(btn => {
          btn.addEventListener('click', async () => {
            const jobId = card.dataset.job;
            const seq = card.dataset.seq;
            const status = btn.dataset.resolve;
            btn.disabled = true;
            try {
              const r = await fetch('/api/approvals/' + encodeURIComponent(jobId) + '/' + seq + '/resolve', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({status: status, user: 'web'}),
              });
              if (r.ok) {
                await loadPending();
              } else {
                const data = await r.json();
                alert('Failed: ' + (data.error || r.status));
                btn.disabled = false;
              }
            } catch (e) {
              alert('Failed: ' + e);
              btn.disabled = false;
            }
          });
        });
      });
    } catch (e) {
      list.innerHTML = '<div class="card-sub" style="padding:12px; color:var(--critical);">Failed to load: ' + e + '</div>';
    }
  }

  document.querySelectorAll('.sb-item[data-page="approvals"]').forEach(el => {
    el.addEventListener('click', loadPending);
  });
  document.addEventListener('DOMContentLoaded', loadPending);
  if (document.readyState !== 'loading') loadPending();
})();

// ---- Report page wiring (§34.4 step 1) ----
(function () {
  const MD = document.getElementById('report-md');
  const HTML = document.getElementById('report-html');
  const PDF = document.getElementById('report-pdf');
  if (!MD && !HTML && !PDF) return;

  async function download(fmt, btn) {
    const original = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Generating…';
    try {
      const r = await fetch('/api/report?format=' + fmt + '&engagement=default');
      if (!r.ok) {
        const err = await r.text();
        alert('Report failed: ' + (err || r.status));
        return;
      }
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'whaxon-report.' + fmt;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) {
      alert('Report failed: ' + e);
    } finally {
      btn.disabled = false;
      btn.textContent = original;
    }
  }

  if (MD) MD.addEventListener('click', () => download('md', MD));
  if (HTML) HTML.addEventListener('click', () => download('html', HTML));
  if (PDF) PDF.addEventListener('click', () => download('pdf', PDF));
})();

// ---- Retest page wiring (live queue) ----
(function () {
  const tbody = document.getElementById('retest-tbody');
  if (!tbody) return;
  const countEl = document.getElementById('retest-count');
  const summaryEl = document.getElementById('retest-summary');

  async function load() {
    try {
      const data = await (await fetch('/api/report?format=json')).json();
      const rows = [];
      (data.jobs || []).forEach(entry => {
        const job = entry.job || {};
        (entry.findings || []).forEach(f => {
          if (f.verification_status === 'verified') {
            rows.push({ job, f });
          }
        });
      });
      if (countEl) countEl.textContent = String(rows.length);
      if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="6" style="padding:16px; color:var(--text-dim);">No verified findings yet. Validate a finding first.</td></tr>';
        if (summaryEl) summaryEl.textContent = 'Nothing to retest.';
        return;
      }
      if (summaryEl) summaryEl.textContent = rows.length + ' verified finding(s) available for retest.';
      tbody.innerHTML = '';
      rows.forEach(({ job, f }) => {
        const tr = document.createElement('tr');
        tr.innerHTML =
          '<td><span class="title"></span></td>' +
          '<td><span class="pill pill-' + (f.severity || 'info') + ' no-border"><span class="dot"></span>' + (f.severity || 'info') + '</span></td>' +
          '<td><span class="target"></span></td>' +
          '<td><span class="mono"></span></td>' +
          '<td><span class="pill pill-success">Verified</span></td>' +
          '<td><button class="btn btn-sm btn-primary">Retest</button></td>';
        tr.querySelector('.title').textContent = f.title || f.kind || '(finding)';
        tr.querySelector('.target').textContent = job.target || '';
        tr.querySelector('.mono').textContent = f.source || job.tool || '';
        const btn = tr.querySelector('button');
        btn.addEventListener('click', async () => {
          btn.disabled = true;
          btn.textContent = 'Retesting…';
          try {
            const r = await fetch('/api/retest/' + encodeURIComponent(job.id) + '/' + f.seq, { method: 'POST' });
            const body = await r.json();
            if (!r.ok) { alert('Retest failed: ' + (body.error || r.status)); }
            else { alert('Retest: ' + body.status + '\n' + body.reason); }
            await load();
          } catch (e) { alert('Retest failed: ' + e); }
          finally { btn.disabled = false; btn.textContent = 'Retest'; }
        });
        tbody.appendChild(tr);
      });
    } catch (e) {
      tbody.innerHTML = '<tr><td colspan="6" style="padding:16px; color:var(--critical);">Failed to load: ' + e + '</td></tr>';
    }
  }

  document.querySelectorAll('.sb-item[data-page="retest"]').forEach(el => el.addEventListener('click', load));
  document.addEventListener('DOMContentLoaded', load);
  if (document.readyState !== 'loading') load();
})();

// ---- Sessions page wiring ----
(function () {
  const tbody = document.getElementById('sessions-tbody');
  if (!tbody) return;
  const summary = document.getElementById('sessions-summary');

  function cell(value, className) {
    const td = document.createElement('td');
    const span = document.createElement('span');
    if (className) span.className = className;
    span.textContent = value == null ? '' : String(value);
    td.appendChild(span);
    return td;
  }

  function addConsole(row, sessionId) {
    const existing = row.nextElementSibling;
    if (existing && existing.classList.contains('session-console')) {
      existing.remove();
      return;
    }
    tbody.querySelectorAll('.session-console').forEach(el => el.remove());
    const panel = document.createElement('tr');
    panel.className = 'session-console';
    const td = document.createElement('td');
    td.colSpan = 5;
    const wrap = document.createElement('div');
    wrap.className = 'session-console-panel';
    const label = document.createElement('label');
    label.className = 'form-label';
    label.textContent = 'Command for session ' + sessionId;
    const form = document.createElement('form');
    form.className = 'session-console-form';
    const input = document.createElement('input');
    input.className = 'form-input';
    input.type = 'text';
    input.required = true;
    input.autocomplete = 'off';
    input.placeholder = 'Enter an operator-approved session command';
    const button = document.createElement('button');
    button.className = 'btn btn-primary btn-sm';
    button.type = 'submit';
    button.textContent = 'Execute';
    const output = document.createElement('pre');
    output.className = 'session-console-output';
    output.setAttribute('aria-live', 'polite');
    output.textContent = 'Commands run only when you submit them.';
    form.append(input, button);
    wrap.append(label, form, output);
    td.appendChild(wrap);
    panel.appendChild(td);
    row.after(panel);
    input.focus();

    form.addEventListener('submit', async event => {
      event.preventDefault();
      const command = input.value.trim();
      if (!command) return;
      button.disabled = true;
      button.textContent = 'Executing…';
      output.textContent = '$ ' + command + '\\nRunning…';
      try {
        const response = await fetch('/api/msf/sessions/' + encodeURIComponent(sessionId) + '/exec', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({command}),
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || ('HTTP ' + response.status));
        output.textContent = '$ ' + result.command + '\\n' + (result.output || '(no output)');
      } catch (error) {
        output.textContent = 'Command failed: ' + error;
      } finally {
        button.disabled = false;
        button.textContent = 'Execute';
      }
    });
  }

  async function load() {
    if (summary) summary.textContent = 'Loading live and stored sessions…';
    try {
      const response = await fetch('/api/msf/sessions');
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const data = await response.json();
      const live = Object.entries(data.live || {}).map(([sid, info]) => ({sid, info, status: 'live'}));
      const stored = (data.stored || []).map(session => ({
        sid: session.id,
        info: session.info || session,
        status: session.status || 'stored',
      }));
      const entries = live.concat(stored);
      tbody.replaceChildren();
      if (summary) summary.textContent = live.length + ' live · ' + stored.length + ' stored session(s)';
      if (!entries.length) {
        const row = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 5;
        td.className = 'card-sub';
        td.textContent = 'No live or stored sessions are available.';
        row.appendChild(td);
        tbody.appendChild(row);
        return;
      }
      entries.forEach(({sid, info, status}) => {
        const row = document.createElement('tr');
        row.appendChild(cell(sid, 'mono'));
        row.appendChild(cell((info && (info.target_host || info.host || info.tunnel_peer)) || '—', 'target'));
        row.appendChild(cell((info && info.type) || '—', 'pill pill-accent'));
        row.appendChild(cell((info && (info.info || info.platform)) || '—', 'mono'));
        const action = document.createElement('td');
        const badge = document.createElement('span');
        badge.className = 'pill ' + (status === 'live' ? 'pill-success' : 'pill-neutral');
        badge.textContent = status;
        action.appendChild(badge);
        if (status === 'live') {
          const button = document.createElement('button');
          button.type = 'button';
          button.className = 'btn btn-sm btn-ghost';
          button.textContent = 'Interact';
          button.style.marginLeft = '8px';
          button.addEventListener('click', () => addConsole(row, sid));
          action.appendChild(button);
        }
        row.appendChild(action);
        tbody.appendChild(row);
      });
    } catch (error) {
      tbody.replaceChildren();
      const row = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 5;
      td.className = 'card-sub';
      td.textContent = 'Could not load sessions: ' + error;
      row.appendChild(td);
      tbody.appendChild(row);
      if (summary) summary.textContent = 'Session service unavailable.';
    }
  }

  document.querySelectorAll('.sb-item[data-page="sessions"]').forEach(el => el.addEventListener('click', load));
  document.addEventListener('DOMContentLoaded', load);
  if (document.readyState !== 'loading') load();
})();

// ---- Catalog page wiring ----
(function () {
  const tbody = document.getElementById('catalog-tbody');
  if (!tbody) return;
  const summaryEl = document.getElementById('catalog-summary');

  async function load() {
    try {
      const tools = await (await fetch('/api/tools')).json();
      const arr = tools.tools || tools || [];
      if (summaryEl) summaryEl.textContent = arr.length + ' tools in the catalog.';
      if (!arr.length) {
        tbody.innerHTML = '<tr><td colspan="5" style="padding:16px; color:var(--text-dim);">No tools in catalog.</td></tr>';
        return;
      }
      tbody.innerHTML = '';
      arr.forEach(tool => {
        const tr = document.createElement('tr');
        tr.innerHTML =
          '<td><span class="mono"></span></td>' +
          '<td><span class="pill pill-neutral"></span></td>' +
          '<td><span class="mono"></span></td>' +
          '<td></td>' +
          '<td><span class="mono"></span></td>';
        const monos = tr.querySelectorAll('.mono');
        monos[0].textContent = tool.id || '';
        tr.querySelector('.pill').textContent = tool.category || '';
        monos[1].textContent = tool.binary || '';
        monos[2].textContent = tool.package || '';
        tbody.appendChild(tr);
      });
    } catch (e) {
      tbody.innerHTML = '<tr><td colspan="5" style="padding:16px; color:var(--critical);">Failed to load: ' + e + '</td></tr>';
    }
  }

  document.querySelectorAll('.sb-item[data-page="catalog"]').forEach(el => el.addEventListener('click', load));
  document.addEventListener('DOMContentLoaded', load);
  if (document.readyState !== 'loading') load();
})();

// ---- Scope override modal ----
(function () {
  const btn = document.getElementById('scope-override-btn');
  if (!btn) return;
  btn.addEventListener('click', async () => {
    // The scope modal was opened by the run page when scope refused.
    // Read the pending target from the modal's sm-card text if needed,
    // or from the run-target input.
    const modal = document.getElementById('scope-modal');
    const targetEl = document.getElementById('run-target');
    const target = (targetEl && targetEl.value) || '';
    if (!target) { alert('No target to override.'); return; }
    btn.disabled = true;
    try {
      const r = await fetch('/api/scope/override', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ target: target, tool: '' })
      });
      if (r.ok) {
        if (modal) modal.classList.remove('open');
        alert('Override logged for ' + target);
      } else {
        const data = await r.json();
        alert('Override failed: ' + (data.error || r.status));
      }
    } catch (e) { alert('Override failed: ' + e); }
    finally { btn.disabled = false; }
  });
})();


// ---- Attack Surface graph ----
(function () {
  const svg = document.getElementById('attack-surface-graph');
  if (!svg) return;

  const NS = 'http://www.w3.org/2000/svg';
  const summary = document.getElementById('graph-summary');
  const count = document.getElementById('graph-count');
  const empty = document.getElementById('graph-empty');
  const selection = document.getElementById('graph-selection');
  const refresh = document.getElementById('graph-refresh');
  const container = document.getElementById('graph-container');

  function element(name, attrs, text) {
    const node = document.createElementNS(NS, name);
    Object.entries(attrs || {}).forEach(([key, value]) => node.setAttribute(key, String(value)));
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function key(node) {
    return String(node.kind || 'unknown') + ':' + String(node.id || '');
  }

  function render(payload) {
    const edges = Array.isArray(payload && payload.edges) ? payload.edges : [];
    const nodesByKey = new Map();
    edges.forEach(edge => {
      if (!edge || !edge.parent || !edge.child) return;
      nodesByKey.set(key(edge.parent), edge.parent);
      nodesByKey.set(key(edge.child), edge.child);
    });
    const nodes = Array.from(nodesByKey.values()).sort((a, b) => key(a).localeCompare(key(b)));
    svg.replaceChildren();
    if (count) count.textContent = edges.length + ' edge' + (edges.length === 1 ? '' : 's');
    if (summary) summary.textContent = nodes.length + ' node' + (nodes.length === 1 ? '' : 's') + ' · ' + edges.length + ' relationship' + (edges.length === 1 ? '' : 's');
    if (empty) empty.style.display = edges.length ? 'none' : '';
    if (container) container.style.display = edges.length ? '' : 'none';
    if (!edges.length) {
      if (selection) selection.textContent = 'There are no recorded pivot relationships to inspect yet.';
      return;
    }

    const cx = 400, cy = 270;
    const radius = nodes.length === 1 ? 0 : Math.min(210, Math.max(100, 45 * nodes.length));
    const positions = new Map();
    nodes.forEach((node, index) => {
      const angle = nodes.length === 1 ? 0 : (-Math.PI / 2) + (2 * Math.PI * index / nodes.length);
      positions.set(key(node), {
        x: cx + Math.cos(angle) * radius,
        y: cy + Math.sin(angle) * radius,
      });
    });

    edges.forEach(edge => {
      const from = positions.get(key(edge.parent));
      const to = positions.get(key(edge.child));
      if (!from || !to) return;
      svg.appendChild(element('line', {
        x1: from.x, y1: from.y, x2: to.x, y2: to.y,
        class: 'graph-edge',
      }));
      const mx = (from.x + to.x) / 2, my = (from.y + to.y) / 2;
      svg.appendChild(element('text', {
        x: mx, y: my - 7, class: 'graph-edge-label',
        'text-anchor': 'middle',
      }, edge.relation || 'related'));
    });

    nodes.forEach(node => {
      const pos = positions.get(key(node));
      const group = element('g', {
        class: 'graph-node graph-node-' + String(node.kind || 'unknown').replace(/[^a-z0-9_-]/gi, ''),
        tabindex: '0', role: 'button', 'aria-label': key(node),
      });
      group.appendChild(element('circle', {cx: pos.x, cy: pos.y, r: 24}));
      const label = String(node.id || node.kind || 'unknown');
      const shortLabel = label.length > 26 ? label.slice(0, 23) + '…' : label;
      group.appendChild(element('text', {
        x: pos.x, y: pos.y + 42, 'text-anchor': 'middle', class: 'graph-node-label',
      }, shortLabel));
      const inspect = () => {
        const related = edges.filter(edge => key(edge.parent) === key(node) || key(edge.child) === key(node));
        if (selection) {
          selection.textContent = key(node) + ' · ' + related.length + ' relationship(s): ' +
            related.map(edge => edge.relation + ' → ' +
              (key(edge.parent) === key(node) ? key(edge.child) : key(edge.parent))).join('; ');
        }
      };
      group.addEventListener('click', inspect);
      group.addEventListener('keydown', event => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          inspect();
        }
      });
      svg.appendChild(group);
    });
  }

  async function load() {
    if (refresh) { refresh.disabled = true; refresh.textContent = 'Refreshing…'; }
    if (summary) summary.textContent = 'Loading graph…';
    try {
      const response = await fetch('/api/pivot/graph');
      if (!response.ok) throw new Error('HTTP ' + response.status);
      render(await response.json());
    } catch (error) {
      svg.replaceChildren();
      if (container) container.style.display = 'none';
      if (empty) empty.style.display = '';
      if (summary) summary.textContent = 'Could not load attack surface graph.';
      if (count) count.textContent = 'Unavailable';
      if (selection) selection.textContent = 'Graph request failed: ' + error;
    } finally {
      if (refresh) { refresh.disabled = false; refresh.textContent = 'Refresh'; }
    }
  }

  if (refresh) refresh.addEventListener('click', load);
  document.querySelectorAll('.sb-item[data-page="graph"]').forEach(item => item.addEventListener('click', load));
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', load, {once: true});
  else load();
})();
