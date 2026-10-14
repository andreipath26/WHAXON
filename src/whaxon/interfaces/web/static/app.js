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
  document.querySelectorAll('.tbl thead th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      document.querySelectorAll('.tbl thead th').forEach(x => { x.classList.remove('sorted'); const s = x.querySelector('.sort'); if (s) s.textContent = '·'; });
      th.classList.add('sorted');
      const s = th.querySelector('.sort'); if (s) s.textContent = '▾';
    });
  });

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
