(function () {
  const app = document.getElementById('app');
  const palette = document.getElementById('palette');
  const paletteInput = document.getElementById('palette-input');
  const paletteResults = document.getElementById('palette-results');
  let paletteActions = [];
  const slideover = document.getElementById('slideover');
  const kbdLegend = document.getElementById('kbd-legend');
  const bulkBar = document.getElementById('bulk-bar');
  const bulkCount = document.getElementById('bulk-count');
  const selectAll = document.getElementById('select-all');
  const findingsTbody = document.getElementById('findings-tbody');
  const bulkClear = document.getElementById('bulk-clear');

  // Engagement and MSF status in the persistent shell.
  fetch('/api/scope')
    .then(response => response.ok ? response.json() : Promise.reject(response.status))
    .then(scope => {
      const name = scope.engagement || 'default';
      const side = document.getElementById('engagement-name');
      const crumb = document.getElementById('crumb-engagement');
      if (side) side.textContent = name;
      if (crumb) crumb.textContent = name;
    })
    .catch(() => {
      const side = document.getElementById('engagement-name');
      const crumb = document.getElementById('crumb-engagement');
      if (side) side.textContent = 'Unavailable';
      if (crumb) crumb.textContent = 'Engagement unavailable';
    });
  fetch('/api/msf/status')
    .then(response => response.ok ? response.json() : Promise.reject(response.status))
    .then(status => {
      const pill = document.getElementById('msf-pill');
      if (!pill) return;
      pill.textContent = status.up ? 'MSF · connected' : 'MSF · offline';
      pill.classList.toggle('connected', !!status.up);
    })
    .catch(() => {
      const pill = document.getElementById('msf-pill');
      if (pill) pill.textContent = 'MSF · unavailable';
    });

  // Engagement workflow progress is derived from current stored data, never demo counts.
  Promise.all([
    fetch('/api/scope').then(response => response.ok ? response.json() : Promise.reject(response.status)),
    fetch('/api/report?format=json').then(response => response.ok ? response.json() : Promise.reject(response.status)),
  ]).then(([scope, report]) => {
    const jobs = Array.isArray(report.jobs) ? report.jobs : [];
    const findings = jobs.flatMap(entry => Array.isArray(entry.findings) ? entry.findings : []);
    const targets = new Set(jobs.map(entry => (entry.job || {}).target).filter(Boolean));
    const verified = findings.filter(f => f.verification_status === 'verified').length;
    const stages = [
      ['scope', scope.enabled ? (scope.in_scope || []).length + ' rule(s)' : 'disabled', !!scope.enabled],
      ['target', targets.size + ' target(s)', targets.size > 0],
      ['run', (report.job_count || jobs.length) + ' job(s)', jobs.length > 0],
      ['findings', (report.finding_count || findings.length) + ' finding(s)', findings.length > 0],
      ['report', jobs.length ? 'ready' : 'not ready', jobs.length > 0],
      ['retest', verified + ' verified', verified > 0],
    ];
    stages.forEach(([name, value, done]) => {
      const label = document.getElementById('stage-' + name + '-value');
      const bar = document.getElementById('stage-' + name + '-bar');
      const stageEl = document.getElementById('stage-' + name);
      if (label) label.textContent = value;
      if (bar) bar.style.width = done ? '100%' : '0%';
      if (stageEl) stageEl.classList.toggle('done', !!done);
    });
  }).catch(() => {
    document.querySelectorAll('#engagement-stages .frac').forEach(el => { el.textContent = 'unavailable'; });
  });

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
  if (findingsTbody) findingsTbody.addEventListener('change', e => {
    if (e.target.matches('.row-cb')) updateBulk();
  });
  if (bulkClear) bulkClear.addEventListener('click', () => {
    document.querySelectorAll('#findings-table .row-cb').forEach(cb => { cb.checked = false; });
    if (selectAll) selectAll.checked = false;
    updateBulk();
  });
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

  // Searchable command palette: pages, installed tools, and loaded findings.
  function closePalette() {
    palette.classList.remove('open');
  }

  function addPaletteGroup(label) {
    const group = document.createElement('div');
    group.className = 'palette-group';
    group.textContent = label;
    paletteResults.appendChild(group);
  }

  function addPaletteItem(label, detail, action) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'palette-item';
    button.setAttribute('role', 'option');
    button.textContent = detail ? label + ' · ' + detail : label;
    button.addEventListener('click', () => {
      closePalette();
      action();
    });
    paletteResults.appendChild(button);
    paletteActions.push(action);
  }

  function renderPaletteResults() {
    if (!paletteResults) return;
    const query = (paletteInput.value || '').trim().toLowerCase();
    paletteResults.replaceChildren();
    paletteActions = [];
    if (!query) {
      addPaletteGroup('Search');
      const hint = document.createElement('div');
      hint.className = 'palette-item';
      hint.textContent = 'Type to search pages, tools, and loaded findings.';
      paletteResults.appendChild(hint);
      return;
    }

    const pages = Array.from(document.querySelectorAll('.sb-item[data-page]'))
      .filter(item => item.offsetParent !== null)
      .map(item => ({slug: item.dataset.page, label: (item.querySelector('.label-text') || item).textContent.trim()}))
      .filter(item => item.label.toLowerCase().includes(query) || item.slug.includes(query));
    if (pages.length) {
      addPaletteGroup('Pages');
      pages.slice(0, 8).forEach(item => addPaletteItem(item.label, 'Open page', () => {
        document.querySelector('.sb-item[data-page="' + item.slug + '"]')?.click();
      }));
    }

    const tools = (window._whaxonTools || []).filter(tool =>
      String(tool.name || '').toLowerCase().includes(query) ||
      String(tool.id || '').toLowerCase().includes(query) ||
      String(tool.category || '').toLowerCase().includes(query)
    );
    if (tools.length) {
      addPaletteGroup('Tools');
      tools.slice(0, 8).forEach(tool => addPaletteItem(tool.name || tool.id, tool.category || tool.id, () => {
        document.querySelector('.sb-item[data-page="run"]')?.click();
        window.setTimeout(() => {
          const item = Array.from(document.querySelectorAll('#run-catalog .tool-item'))
            .find(node => node.dataset.toolId === tool.id);
          if (item) item.click();
        }, 0);
      }));
    }

    const findings = (window._whaxonFindings || []).filter(f =>
      [f.title, f.target, f.source, f.severity, f.status].some(value => String(value || '').toLowerCase().includes(query))
    );
    if (findings.length) {
      addPaletteGroup('Findings');
      findings.slice(0, 8).forEach(f => addPaletteItem(f.title, f.target || f.severity, () => {
        document.querySelector('.sb-item[data-page="findings"]')?.click();
        document.querySelector('#findings-filters [data-filter="all"]')?.click();
        window.setTimeout(() => {
          const row = Array.from(document.querySelectorAll('#findings-tbody tr')).find(node =>
            node.dataset.jobId === String(f.job_id) && node.dataset.seq === String(f.seq)
          );
          if (row) row.click();
        }, 0);
      }));
    }

    if (!pages.length && !tools.length && !findings.length) {
      const none = document.createElement('div');
      none.className = 'palette-item';
      none.textContent = 'No matching pages, tools, or findings.';
      paletteResults.appendChild(none);
    }
  }

  function openPalette() {
    palette.classList.add('open');
    paletteInput.value = '';
    renderPaletteResults();
    paletteInput.focus();
  }

  document.getElementById('palette-trigger').addEventListener('click', openPalette);
  paletteInput.addEventListener('input', renderPaletteResults);
  paletteInput.addEventListener('keydown', event => {
    if (event.key === 'Enter' && paletteActions.length) {
      event.preventDefault();
      paletteActions[0]();
      closePalette();
    }
  });

  // shortcuts
  document.getElementById('help-trigger').addEventListener('click', () => kbdLegend.classList.add('open'));

  // workspace
  // Workspace switching is not implemented in this single-user edition; do not open mock data.

  // table sort


  // chips
  // Filter chips are wired by their owning page; no generic toggle-only behavior.

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

  // Keyboard shortcuts shown in the help legend.
  let goPrefix = false;
  document.addEventListener('keydown', e => {
    const key = e.key.toLowerCase();
    const active = document.activeElement;
    const typing = active && (/INPUT|TEXTAREA|SELECT/.test(active.tagName) || active.isContentEditable);

    if ((e.metaKey || e.ctrlKey) && key === 'k') {
      e.preventDefault();
      palette.classList.contains('open') ? closePalette() : openPalette();
      return;
    }
    if ((e.metaKey || e.ctrlKey) && key === 'b') {
      e.preventDefault();
      app.classList.toggle('collapsed');
      return;
    }
    if (e.key === 'Escape') {
      closePalette();
      closeSlideover();
      kbdLegend.classList.remove('open');
      document.querySelectorAll('.scope-modal').forEach(modal => modal.classList.remove('open'));
      goPrefix = false;
      return;
    }
    if (typing) return;
    if (e.key === '?' ) { kbdLegend.classList.toggle('open'); return; }
    if (e.key === '/') { e.preventDefault(); openPalette(); return; }
    if (goPrefix) {
      goPrefix = false;
      const pages = {f: 'findings', r: 'run', p: 'report'};
      if (pages[key]) {
        document.querySelector('.sb-item[data-page="' + pages[key] + '"]')?.click();
        e.preventDefault();
      }
      return;
    }
    if (key === 'g') { goPrefix = true; e.preventDefault(); return; }
    if (key === 'd') {
      const compact = document.body.dataset.density !== 'compact';
      document.querySelector('.density-toggle button[data-density="' + (compact ? 'compact' : 'comfortable') + '"]')?.click();
      e.preventDefault();
      return;
    }
    if (key === 'n') {
      document.querySelector('.sb-item[data-page="run"]')?.click();
      window.setTimeout(() => document.getElementById('run-target')?.focus(), 0);
      e.preventDefault();
    }
  });

  palette.addEventListener('click', e => { if (e.target === palette) closePalette(); });
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

  let activeFilter = 'all';

  document.addEventListener('whaxon:findings-resort', () => {
    applyFindingsView();
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
      const STATUS_PILL = {
        verified: ['pill-success', 'Verified'],
        candidate: ['pill-accent', 'Candidate'],
        refuted: ['pill-neutral', 'Refuted'],
        fixed: ['pill-low', 'Fixed'],
        still_vulnerable: ['pill-critical', 'Still Vulnerable'],
        inconclusive: ['pill-warning', 'Inconclusive'],
      };
      const [statusCls, statusLabel] = STATUS_PILL[f.status] || ['pill-neutral', String(f.status || 'Unknown')];
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
      tr.dataset.jobId = f.job_id;
      tr.dataset.seq = String(f.seq);
      if (f._raw && f._raw.raw_line) tr.dataset.rawLine = f._raw.raw_line;
      if (f._raw && f._raw.data) {
        if (f._raw.data.description) tr.dataset.description = f._raw.data.description;
        if (f._raw.data.remediation) tr.dataset.remediation = f._raw.data.remediation;
      }
      tr.addEventListener('click', e => {
        if (e.target.closest('.checkbox-col')) return;
        document.querySelectorAll('#findings-tbody tr').forEach(row => row.classList.remove('selected'));
        tr.classList.add('selected');
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
                still_vulnerable: ['pill-critical', 'Still Vulnerable'],
                inconclusive: ['pill-warning', 'Inconclusive']
              };
              const [cls, label] = MAP[data.status] || ['pill-accent', data.status];
              last.className = 'pill ' + cls;
              last.textContent = label;
            }
          }
        }
        alert(kind + ': ' + data.status + '\n' + data.reason);
        loadFindings();
        const panel = document.getElementById('slideover');
        if (panel) panel.classList.remove('open');
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
      copy.sort((a, b) => String(a[key] || '').localeCompare(String(b[key] || '')));
    }
    if (!asc) copy.reverse();
    return copy;
  }

  function renderTargetSummary(rows) {
    const summary = document.getElementById('findings-target-summary');
    const list = document.getElementById('findings-target-list');
    if (!summary || !list) return;
    const counts = new Map();
    rows.forEach(f => counts.set(f.target || '(unknown target)', (counts.get(f.target || '(unknown target)') || 0) + 1));
    const targets = Array.from(counts.entries()).sort((a, b) => a[0].localeCompare(b[0]));
    summary.textContent = targets.length + ' distinct target(s) represented by ' + rows.length + ' finding(s).';
    list.replaceChildren();
    targets.slice(0, 8).forEach(([target, count]) => {
      const row = document.createElement('div');
      row.className = 'kv';
      const name = document.createElement('span');
      name.className = 'k';
      name.textContent = target;
      const total = document.createElement('span');
      total.className = 'v';
      total.textContent = count + ' finding(s)';
      row.append(name, total);
      list.appendChild(row);
    });
    if (!targets.length) list.textContent = 'No targets recorded yet.';
  }

  function applyFindingsView() {
    const rows = window._whaxonFindings || [];
    const counts = {
      all: rows.length,
      critical: rows.filter(f => f.severity === 'critical').length,
      high: rows.filter(f => f.severity === 'high').length,
      medium: rows.filter(f => f.severity === 'medium').length,
      low: rows.filter(f => f.severity === 'low' || f.severity === 'info').length,
      verified: rows.filter(f => f.status === 'verified').length,
      candidate: rows.filter(f => f.status === 'candidate').length,
    };
    Object.entries(counts).forEach(([name, value]) => {
      const el = document.getElementById('filter-count-' + name);
      if (el) el.textContent = String(value);
    });
    const visible = activeFilter === 'all' ? rows : rows.filter(f =>
      activeFilter === 'low' ? (f.severity === 'low' || f.severity === 'info') :
      activeFilter === 'verified' || activeFilter === 'candidate' ? f.status === activeFilter :
      f.severity === activeFilter
    );
    renderTable(sortRows(visible, sortKey, sortAsc));
    const jobCount = new Set(rows.map(row => row.job_id).filter(Boolean)).size;
    if (summaryEl) summaryEl.textContent = visible.length + ' of ' + rows.length + ' findings shown across ' + jobCount + ' jobs';
  }

  function loadFindings() {
    fetch('/api/report?format=json')
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(data => {
        const sev = data.severity_counts || {};
        const jobCount = data.job_count || 0;
        const findingCount = data.finding_count || 0;
        const findingsBadge = document.getElementById('findings-badge');
        if (findingsBadge) findingsBadge.textContent = String(findingCount);
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
        renderTargetSummary(rows);
        applyFindingsView();
      })
      .catch(err => {
        tbody.innerHTML = '<tr><td colspan="6" style="padding:16px; color:var(--critical);">Failed to load findings: ' + err + '</td></tr>';
      });
  }

  document.querySelectorAll('#findings-filters [data-filter]').forEach(button => {
    button.addEventListener('click', () => {
      activeFilter = button.dataset.filter || 'all';
      document.querySelectorAll('#findings-filters [data-filter]').forEach(item => item.classList.toggle('on', item === button));
      applyFindingsView();
    });
  });

  const exportButton = document.getElementById('findings-export');
  if (exportButton) exportButton.addEventListener('click', () => {
    const rows = window._whaxonFindings || [];
    const fields = ['severity', 'title', 'target', 'source', 'status', 'job_id', 'seq'];
    const quote = value => '"' + String(value == null ? '' : value).replace(/"/g, '""') + '"';
    const csv = [fields.join(','), ...rows.map(row => fields.map(field => quote(row[field])).join(','))].join('\n');
    const url = URL.createObjectURL(new Blob([csv], {type: 'text/csv;charset=utf-8'}));
    const link = document.createElement('a');
    link.href = url;
    link.download = 'whaxon-findings.csv';
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  });

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
    window._whaxonTools = tools || [];
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
        window._whaxonSelectedTool = tool.id;
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
          if (status === 403) {
            showScopePill('denied', 'Out of scope');
            const modal = document.getElementById('scope-modal');
            const target = document.getElementById('scope-modal-target');
            const tool = document.getElementById('scope-modal-tool');
            const engagement = document.getElementById('scope-modal-engagement');
            const message = document.getElementById('scope-modal-message');
            const logButton = document.getElementById('scope-override-btn');
            if (logButton) { logButton.disabled = false; logButton.textContent = 'Log blocked attempt'; }
            if (target) target.textContent = targetEl.value || '';
            if (tool) tool.textContent = selectedTool || '';
            if (engagement) engagement.textContent = document.getElementById('engagement-name')?.textContent || 'default';
            if (message) message.textContent = 'The run remains blocked. Update the engagement scope through the approved scope configuration before retrying.';
            if (modal) modal.classList.add('open');
          }
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
      const badge = document.getElementById('coverage-badge');
      if (badge) badge.textContent = '0';
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
    const badge = document.getElementById('coverage-badge');
    if (badge) badge.textContent = String(gaps.length);
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
  const summary = document.getElementById('report-summary');
  if (!MD && !HTML && !PDF && !summary) return;

  async function loadSummary() {
    if (!summary) return;
    summary.textContent = 'Loading report data…';
    try {
      const response = await fetch('/api/report?format=json');
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const data = await response.json();
      const jobs = Array.isArray(data.jobs) ? data.jobs : [];
      const findings = jobs.reduce((total, entry) =>
        total + (Array.isArray(entry.findings) ? entry.findings.length : 0), 0);
      const verified = jobs.reduce((total, entry) =>
        total + (Array.isArray(entry.findings) ? entry.findings.filter(f => f.verification_status === 'verified').length : 0), 0);
      summary.textContent = (data.job_count || jobs.length) + ' job(s) · ' +
        findings + ' finding(s) · ' + verified + ' verified finding(s). Generated reports include evidence and recorded coverage gaps.';
    } catch (error) {
      summary.textContent = 'Could not load engagement report data: ' + error;
    }
  }

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
      URL.revokeObjectURL(url);
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
  document.querySelectorAll('.sb-item[data-page="report"]').forEach(item => item.addEventListener('click', loadSummary));
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', loadSummary, {once: true});
  else loadSummary();
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
          '<td><span class="pill"></span></td>' +
          '<td><span class="mono"></span></td>';
        const monos = tr.querySelectorAll('.mono');
        monos[0].textContent = tool.id || '';
        tr.querySelector('.pill').textContent = tool.category || '';
        monos[1].textContent = tool.binary || '';
        const adapterPill = tr.querySelectorAll('.pill')[1];
        adapterPill.classList.add(tool.adapter ? 'pill-success' : 'pill-neutral');
        adapterPill.textContent = tool.adapter ? 'Available' : 'Not registered';
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

// ---- Scope blocked-attempt logging ----
(function () {
  const btn = document.getElementById('scope-override-btn');
  const cancel = document.getElementById('scope-modal-cancel');
  const modal = document.getElementById('scope-modal');
  const message = document.getElementById('scope-modal-message');
  if (cancel && modal) cancel.addEventListener('click', () => modal.classList.remove('open'));
  if (!btn) return;
  btn.addEventListener('click', async () => {
    const target = (document.getElementById('run-target')?.value || '').trim();
    if (!target) {
      if (message) message.textContent = 'No target is available to log.';
      return;
    }
    btn.disabled = true;
    try {
      const response = await fetch('/api/scope/override', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({target, tool: window._whaxonSelectedTool || ''}),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || ('HTTP ' + response.status));
      if (message) message.textContent = 'Blocked attempt logged. This does not authorize execution; update scope before retrying.';
      btn.textContent = 'Logged';
      btn.disabled = true;
    } catch (error) {
      if (message) message.textContent = 'Could not log blocked attempt: ' + error;
      btn.disabled = false;
    }
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
