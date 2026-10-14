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
          status: f.status || 'candidate',
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

    so.classList.add('open');
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
