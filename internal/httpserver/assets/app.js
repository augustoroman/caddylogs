// caddylogs dashboard — single-file vanilla JS.

const state = {
  filter: { include: {}, exclude: {}, time_from: null, time_to: null },
  topN: 10,
  rowsOffset: 0,
  rowsBuffer: [], // live events appended client-side between refreshes
  maxLiveRows: 200,
  view: 'dynamic', // "dynamic" | "static" | "malicious"
};

// --- helpers ---
function fmtInt(n) { return (n || 0).toLocaleString(); }
function fmtBytes(n) {
  if (!n) return '0 B';
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0; let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return v.toFixed(v < 10 ? 1 : 0) + ' ' + u[i];
}
function fmtDuration(ms) {
  if (ms == null) return '';
  if (ms < 1) return '<1ms';
  if (ms < 1000) return ms + 'ms';
  return (ms / 1000).toFixed(1) + 's';
}
function fmtTs(tsStr) {
  const d = new Date(tsStr);
  return d.toISOString().replace('T', ' ').slice(0, 19);
}
function statusClass(n) {
  if (n >= 500) return 'status-5';
  if (n >= 400) return 'status-4';
  if (n >= 300) return 'status-3';
  return 'status-2';
}
function escapeHTML(s) {
  if (s == null) return '';
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}
function truncate(s, n) {
  s = s || '';
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}
function deepCopyFilter(f) {
  return {
    include: Object.fromEntries(Object.entries(f.include || {}).map(([k, v]) => [k, [...v]])),
    exclude: Object.fromEntries(Object.entries(f.exclude || {}).map(([k, v]) => [k, [...v]])),
    time_from: f.time_from,
    time_to: f.time_to,
  };
}

// --- filter chip rendering + mutation ---
const PRETTY_DIM = {
  ip: 'IP', host: 'host', uri: 'URI', status: 'status', status_class: 'status',
  method: 'method', referer: 'referrer', browser: 'browser', os: 'OS',
  device: 'device', country: 'country', city: 'city', proto: 'proto',
  is_bot: 'bot', is_local: 'local',
};
function renderChips() {
  const c = document.getElementById('chips');
  c.innerHTML = '';
  const add = (dim, val, excl) => {
    const el = document.createElement('span');
    el.className = 'chip' + (excl ? ' excl' : '');
    el.innerHTML = `<span class="dim">${escapeHTML(PRETTY_DIM[dim] || dim)}${excl ? ' ≠' : ' ='}</span>
                    <span class="val">${escapeHTML(truncate(String(val), 50))}</span>
                    <span class="x" title="Remove filter">×</span>`;
    el.querySelector('.x').addEventListener('click', () => {
      const bucket = excl ? state.filter.exclude : state.filter.include;
      bucket[dim] = (bucket[dim] || []).filter(v => v !== val);
      if (bucket[dim].length === 0) delete bucket[dim];
      refreshAll();
    });
    c.appendChild(el);
  };
  for (const [dim, vals] of Object.entries(state.filter.include || {})) {
    for (const v of vals) add(dim, v, false);
  }
  for (const [dim, vals] of Object.entries(state.filter.exclude || {})) {
    for (const v of vals) add(dim, v, true);
  }
  if (state.filter.time_from || state.filter.time_to) {
    const el = document.createElement('span');
    el.className = 'chip';
    const from = state.filter.time_from ? fmtTs(state.filter.time_from) : '∞';
    const to = state.filter.time_to ? fmtTs(state.filter.time_to) : '∞';
    el.innerHTML = `<span class="dim">time</span>
                    <span class="val">${escapeHTML(from)} → ${escapeHTML(to)}</span>
                    <span class="x" title="Remove filter">×</span>`;
    el.querySelector('.x').addEventListener('click', () => {
      state.filter.time_from = null;
      state.filter.time_to = null;
      refreshAll();
    });
    c.appendChild(el);
  }
}
function addFilter(dim, val, excl) {
  const bucket = excl ? state.filter.exclude : state.filter.include;
  bucket[dim] = bucket[dim] || [];
  if (!bucket[dim].includes(val)) bucket[dim].push(val);
  refreshAll();
}

// --- API calls ---
async function postJSON(url, body) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`${url}: ${r.status}`);
  return r.json();
}
async function getJSON(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${url}: ${r.status}`);
  return r.json();
}

// --- rendering ---
function renderOverview(ov) {
  const el = document.getElementById('overview');
  const span = ov.first && ov.last ? `${fmtTs(ov.first)} → ${fmtTs(ov.last)}` : '';
  el.innerHTML = `
    <div class="stat"><div class="label">Hits</div><div class="value">${fmtInt(ov.hits)}</div></div>
    <div class="stat"><div class="label">Visitors</div><div class="value">${fmtInt(ov.visitors)}</div></div>
    <div class="stat"><div class="label">Bandwidth</div><div class="value">${fmtBytes(ov.bytes)}</div></div>
    <div class="stat"><div class="label">Span</div><div class="value sub">${escapeHTML(span)}</div></div>
  `;
}

function renderStatusClass(sc) {
  const el = document.getElementById('status-class-bars');
  el.innerHTML = '';
  const total = Object.values(sc || {}).reduce((a, b) => a + b, 0) || 1;
  const order = ['2xx', '3xx', '4xx', '5xx', '1xx', 'other'];
  for (const k of order) {
    const n = sc?.[k] || 0;
    if (!n) continue;
    const pct = (n / total) * 100;
    const d = document.createElement('div');
    d.className = `sb s${k}`;
    d.style.flex = `${n} ${n} 0`;
    d.title = `${k}: ${fmtInt(n)} (${pct.toFixed(1)}%)`;
    d.textContent = pct >= 4 ? `${k} ${fmtInt(n)}` : '';
    d.addEventListener('click', () => addFilter('status_class', k, false));
    el.appendChild(d);
  }
}

function renderTimeline(buckets) {
  const svg = document.getElementById('timeline-chart');
  const w = svg.clientWidth || 800;
  const h = 160;
  svg.setAttribute('viewBox', `0 0 ${w} ${h}`);
  svg.innerHTML = '';
  if (!buckets || buckets.length === 0) return;
  const maxHits = Math.max(...buckets.map(b => b.hits));
  const barW = Math.max(1, w / buckets.length);
  const ns = 'http://www.w3.org/2000/svg';
  buckets.forEach((b, i) => {
    const x = i * barW;
    const bh = (b.hits / maxHits) * (h - 20);
    const rect = document.createElementNS(ns, 'rect');
    rect.setAttribute('class', 'tl-bar');
    rect.setAttribute('x', x.toFixed(2));
    rect.setAttribute('y', (h - bh).toFixed(2));
    rect.setAttribute('width', Math.max(1, barW - 1).toFixed(2));
    rect.setAttribute('height', bh.toFixed(2));
    const t = document.createElementNS(ns, 'title');
    t.textContent = `${fmtTs(b.start)}: ${fmtInt(b.hits)} hits, ${fmtInt(b.visitors)} visitors`;
    rect.appendChild(t);
    svg.appendChild(rect);
  });
  // Brush overlay for range selection.
  let brushStart = null, brushEl = null;
  const toBucketIdx = (clientX) => {
    const r = svg.getBoundingClientRect();
    const x = clientX - r.left;
    return Math.max(0, Math.min(buckets.length - 1, Math.floor((x / r.width) * buckets.length)));
  };
  svg.addEventListener('mousedown', (e) => {
    brushStart = toBucketIdx(e.clientX);
    brushEl = document.createElementNS(ns, 'rect');
    brushEl.setAttribute('class', 'tl-brush');
    brushEl.setAttribute('y', 0);
    brushEl.setAttribute('height', h);
    svg.appendChild(brushEl);
  });
  svg.addEventListener('mousemove', (e) => {
    if (brushStart == null) return;
    const cur = toBucketIdx(e.clientX);
    const lo = Math.min(brushStart, cur);
    const hi = Math.max(brushStart, cur);
    brushEl.setAttribute('x', (lo * barW).toFixed(2));
    brushEl.setAttribute('width', ((hi - lo + 1) * barW).toFixed(2));
  });
  svg.addEventListener('mouseup', (e) => {
    if (brushStart == null) return;
    const cur = toBucketIdx(e.clientX);
    const lo = Math.min(brushStart, cur);
    const hi = Math.max(brushStart, cur);
    brushStart = null;
    if (brushEl) { brushEl.remove(); brushEl = null; }
    if (hi <= lo) return; // click, not drag
    const bucketStart = buckets[lo].start;
    const bucketEnd = buckets[Math.min(buckets.length - 1, hi + 1)]?.start || null;
    state.filter.time_from = bucketStart;
    state.filter.time_to = bucketEnd;
    refreshAll();
  });
  svg.addEventListener('mouseleave', () => {
    if (brushEl) { brushEl.remove(); brushEl = null; }
    brushStart = null;
  });
}

const DYNAMIC_PANELS = [
  { name: 'ip', title: 'Top IPs', dim: 'ip' },
  { name: 'uri', title: 'Top URIs', dim: 'uri' },
  { name: 'country', title: 'Top Countries', dim: 'country' },
  { name: 'city', title: 'Top Cities', dim: 'city' },
  { name: 'referer', title: 'Top Referrers', dim: 'referer' },
  { name: 'browser', title: 'Top Browsers', dim: 'browser' },
  { name: 'os', title: 'Top OS', dim: 'os' },
  { name: 'device', title: 'Top Devices', dim: 'device' },
  { name: 'not_found', title: '404s — Not Found', dim: 'uri' },
  { name: 'server_error', title: '5xx Errors', dim: 'uri' },
  { name: 'slow', title: 'Slow Requests (max)', dim: 'uri', extraCol: 'max_ms' },
  { name: 'host', title: 'Top Hosts', dim: 'host' },
  { name: 'method', title: 'Methods', dim: 'method' },
];
const MALICIOUS_PANELS = [
  { name: 'ip', title: 'Top attacker IPs', dim: 'ip' },
  { name: 'malicious_reason', title: 'Flag reasons', dim: 'malicious_reason' },
  { name: 'uri', title: 'Top targeted URIs', dim: 'uri' },
  { name: 'country', title: 'Top countries', dim: 'country' },
  { name: 'city', title: 'Top cities', dim: 'city' },
  { name: 'browser', title: 'UAs', dim: 'browser' },
  { name: 'os', title: 'OS', dim: 'os' },
  { name: 'host', title: 'Targeted hosts', dim: 'host' },
  { name: 'method', title: 'Methods', dim: 'method' },
  { name: 'status', title: 'Response status', dim: 'status' },
  { name: 'referer', title: 'Referrers (spoofed)', dim: 'referer' },
];
function currentPanelDefs() {
  return state.view === 'malicious' ? MALICIOUS_PANELS : DYNAMIC_PANELS;
}

// PANEL_PAGE_SIZE governs how many rows "Show more" fetches per click.
const PANEL_PAGE_SIZE = 25;

function renderPanels(panels) {
  const container = document.getElementById('panels');
  container.innerHTML = '';
  const defs = currentPanelDefs();
  defs.forEach(def => {
    const initialRows = panels[def.name] || [];
    const sec = document.createElement('section');
    sec.className = 'panel';
    sec.dataset.panel = def.name;
    const headers = def.extraCol === 'max_ms'
      ? `<tr><th data-col="key">${escapeHTML(def.dim)}<span class="col-resize"></span></th><th data-col="hits" class="right">hits<span class="col-resize"></span></th><th data-col="max" class="right">max ms<span class="col-resize"></span></th><th data-col="bar"></th></tr>`
      : `<tr><th data-col="key">${escapeHTML(def.dim)}<span class="col-resize"></span></th><th data-col="hits" class="right">hits<span class="col-resize"></span></th><th data-col="bar"></th></tr>`;
    sec.innerHTML = `
      <div class="panel-title">${escapeHTML(def.title)} <span class="muted panel-count">${initialRows.length}</span></div>
      <table class="panel-table" data-panel="${def.name}">
        <thead>${headers}</thead>
        <tbody></tbody>
      </table>
      <div class="panel-footer">
        <span class="panel-status">showing ${initialRows.length}</span>
        <button class="btn panel-more" type="button">show more</button>
      </div>
    `;
    container.appendChild(sec);
    // Per-panel paging state lives on the section DOM node so it survives
    // rerenders of unrelated panels.
    sec._pg = {
      rows: [],              // all rows loaded so far
      offset: 0,             // next offset to fetch
      exhausted: false,      // server returned a short page
      initialLoaded: false,  // whether initialRows have been installed
      def: def,
    };
    appendPanelRows(sec, initialRows);
    sec._pg.offset = initialRows.length;
    sec._pg.initialLoaded = true;
    if (initialRows.length < state.topN) {
      sec._pg.exhausted = true; // dashboard fanout already returned fewer than topN -> no more
    }
    updatePanelFooter(sec);

    const moreBtn = sec.querySelector('.panel-more');
    moreBtn.addEventListener('click', () => loadMorePanel(sec));

    installColumnResize(sec.querySelector('table.panel-table'));
    restoreColumnWidths(sec.querySelector('table.panel-table'), def.name);
  });
}

function appendPanelRows(sec, rows) {
  const def = sec._pg.def;
  const tbody = sec.querySelector('tbody');
  if (sec._pg.rows.length === 0 && rows.length === 0) {
    const cols = def.extraCol === 'max_ms' ? 4 : 3;
    tbody.innerHTML = `<tr><td colspan="${cols}" class="panel-empty">no data</td></tr>`;
    return;
  }
  if (sec._pg.rows.length === 0) {
    tbody.innerHTML = ''; // clear any "no data" placeholder
  }
  sec._pg.rows = sec._pg.rows.concat(rows);
  // Recompute max over ALL rows loaded so bar widths stay comparable.
  const maxHits = Math.max(...sec._pg.rows.map(r => r.hits || 0)) || 1;
  // Rebuild bars on already-rendered rows proportionally (keeps scale honest
  // when a late page has a larger hit value than earlier ones).
  tbody.querySelectorAll('.bar').forEach((barEl, i) => {
    const row = sec._pg.rows[i];
    if (!row) return;
    barEl.style.width = (((row.hits || 0) / maxHits) * 100).toFixed(1) + '%';
  });
  rows.forEach(r => {
    const tr = document.createElement('tr');
    tr.dataset.val = r.key || '(none)';
    tr.dataset.dim = def.dim;
    tr.setAttribute('title', 'click to filter, shift-click to exclude');
    const barWidth = ((r.hits || 0) / maxHits) * 100;
    const extra = def.extraCol === 'max_ms'
      ? `<td class="right" title="max ${escapeHTML(fmtDuration(r.max_ms))}, avg ${escapeHTML(fmtDuration(r.avg_ms))}">${escapeHTML(fmtDuration(r.max_ms))}</td>`
      : '';
    const val = r.key || '(none)';
    const hitsTip = `${fmtInt(r.hits)} hits · ${fmtInt(r.visitors)} visitors · ${fmtBytes(r.bytes)}`;
    tr.innerHTML = `
      <td class="key-cell" title="${escapeHTML(val)}">${escapeHTML(val)}</td>
      <td class="right hits-cell" title="${escapeHTML(hitsTip)}">${fmtInt(r.hits)}</td>
      ${extra}
      <td class="bar-cell"><div class="bar" style="width:${barWidth.toFixed(1)}%"></div></td>`;
    tr.addEventListener('click', (e) => {
      if (e.target.closest('.col-resize')) return;
      const v = tr.dataset.val;
      const d = tr.dataset.dim;
      if (!v || v === '(none)') return;
      addFilter(d, v, e.shiftKey);
    });
    tbody.appendChild(tr);
  });
}

function updatePanelFooter(sec) {
  const status = sec.querySelector('.panel-status');
  const btn = sec.querySelector('.panel-more');
  const count = sec._pg.rows.length;
  sec.querySelector('.panel-count').textContent = count;
  status.textContent = `showing ${count}` + (sec._pg.exhausted ? ' (all)' : '');
  btn.disabled = !!sec._pg.exhausted;
  btn.textContent = sec._pg.exhausted ? 'no more' : `show ${PANEL_PAGE_SIZE} more`;
}

async function loadMorePanel(sec) {
  if (sec._pg.exhausted) return;
  const btn = sec.querySelector('.panel-more');
  btn.disabled = true;
  btn.textContent = 'loading…';
  try {
    const body = {
      filter: viewFilter(state.filter, state.view),
      table: viewTable(state.view),
      panel: sec._pg.def.name,
      offset: sec._pg.offset,
      limit: PANEL_PAGE_SIZE,
    };
    if (sec._pg.def.extraCol === 'max_ms') body.order_by = 'max_dur';
    const r = await postJSON('/api/panel', body);
    const rows = r.rows || [];
    appendPanelRows(sec, rows);
    sec._pg.offset += rows.length;
    if (!r.has_more || rows.length === 0) {
      sec._pg.exhausted = true;
    }
  } catch (e) {
    console.error('panel more:', e);
  }
  updatePanelFooter(sec);
}

// --- column resize + width persistence ---
function installColumnResize(table) {
  const ths = table.querySelectorAll('thead th');
  ths.forEach((th, i) => {
    const handle = th.querySelector('.col-resize');
    if (!handle) return;
    handle.addEventListener('mousedown', (e) => {
      e.preventDefault();
      e.stopPropagation();
      const startX = e.clientX;
      const startW = th.getBoundingClientRect().width;
      handle.classList.add('resizing');
      th.classList.add('resizing');
      const onMove = (ev) => {
        const delta = ev.clientX - startX;
        const newW = Math.max(30, startW + delta);
        th.style.width = newW + 'px';
      };
      const onUp = () => {
        handle.classList.remove('resizing');
        th.classList.remove('resizing');
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
        saveColumnWidths(table);
      };
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    });
  });
}
function saveColumnWidths(table) {
  const panel = table.dataset.panel;
  if (!panel) return;
  const widths = [...table.querySelectorAll('thead th')].map(th => th.style.width || '');
  try { localStorage.setItem('cl_cols_' + panel, JSON.stringify(widths)); } catch {}
}
function restoreColumnWidths(table, panelName) {
  try {
    const raw = localStorage.getItem('cl_cols_' + panelName);
    if (!raw) return;
    const widths = JSON.parse(raw);
    const ths = table.querySelectorAll('thead th');
    widths.forEach((w, i) => { if (w && ths[i]) ths[i].style.width = w; });
  } catch {}
}

function renderRows(rows, append) {
  const body = document.getElementById('rows-body');
  if (!append) body.innerHTML = '';
  rows.forEach(r => appendRow(r));
  document.getElementById('rows-count').textContent = body.children.length + ' shown';
}
function appendRow(r) {
  const body = document.getElementById('rows-body');
  const tr = document.createElement('tr');
  tr.className = 'row-clickable';
  const ua = r.browser && r.os ? `${r.browser} / ${r.os}` : (r.user_agent || '');
  const dur = Math.round((r.duration || 0) / 1e6);
  tr.innerHTML = `
    <td>${escapeHTML(fmtTs(r.ts))}</td>
    <td class="${statusClass(r.status)}">${r.status}</td>
    <td>${escapeHTML(r.method || '')}</td>
    <td>${escapeHTML(truncate(r.host || '', 20))}</td>
    <td title="${escapeHTML(r.uri || '')}">${escapeHTML(truncate(r.uri || '', 60))}</td>
    <td>${escapeHTML(r.ip || '')}</td>
    <td>${escapeHTML(r.country || '')}</td>
    <td title="${escapeHTML(r.user_agent || '')}">${escapeHTML(truncate(ua, 30))}</td>
    <td class="right">${dur}</td>
  `;
  tr.addEventListener('click', (e) => {
    // Clicking a cell filters by that cell's value.
    const cellIdx = [...tr.children].indexOf(e.target.closest('td'));
    const map = { 1: ['status', r.status], 2: ['method', r.method],
                  3: ['host', r.host], 4: ['uri', r.uri], 5: ['ip', r.ip],
                  6: ['country', r.country] };
    if (map[cellIdx] && map[cellIdx][1]) {
      addFilter(map[cellIdx][0], String(map[cellIdx][1]), e.shiftKey);
    }
  });
  body.appendChild(tr);
}

// --- classification breakdown ---
const BREAKDOWN_CELLS = [
  { key: 'real_dynamic',      bkey: 'real_dynamic_bytes',      label: 'real doc',    cls: 'bd-real-doc',    view: 'dynamic' },
  { key: 'real_static',       bkey: 'real_static_bytes',       label: 'real static', cls: 'bd-real-static', view: 'static'  },
  { key: 'bot_dynamic',       bkey: 'bot_dynamic_bytes',       label: 'bot doc',     cls: 'bd-bot-doc',     view: 'dynamic' },
  { key: 'bot_static',        bkey: 'bot_static_bytes',        label: 'bot static',  cls: 'bd-bot-static',  view: 'static'  },
  { key: 'local_dynamic',     bkey: 'local_dynamic_bytes',     label: 'local doc',   cls: 'bd-local-doc',   view: 'local'   },
  { key: 'local_static',      bkey: 'local_static_bytes',      label: 'local static',cls: 'bd-local-static',view: 'local'   },
  { key: 'malicious_dynamic', bkey: 'malicious_dynamic_bytes', label: 'mal doc',     cls: 'bd-mal-doc',     view: 'malicious' },
  { key: 'malicious_static',  bkey: 'malicious_static_bytes',  label: 'mal static',  cls: 'bd-mal-static',  view: 'malicious' },
];

function renderBreakdownBar(barEl, totalEl, cells, data, metric, fmtTotal) {
  const accessor = metric === 'bytes' ? 'bkey' : 'key';
  const total = cells.reduce((s, c) => s + (data[c[accessor]] || 0), 0);
  totalEl.textContent = fmtTotal(total);
  if (total === 0) {
    barEl.innerHTML = `<div class="bd-seg" style="flex:1 1 0; background:var(--border); color:var(--muted)">no data</div>`;
    return;
  }
  barEl.innerHTML = cells.map(c => {
    const n = data[c[accessor]] || 0;
    const hits = data[c.key] || 0;
    const bytes = data[c.bkey] || 0;
    const pct = (n / total) * 100;
    if (n === 0) return '';
    const title = `${c.label}\n${fmtInt(hits)} req (${((hits / (cells.reduce((s, x) => s + (data[x.key] || 0), 0) || 1)) * 100).toFixed(1)}% of req)\n${fmtBytes(bytes)} (${((bytes / (cells.reduce((s, x) => s + (data[x.bkey] || 0), 0) || 1)) * 100).toFixed(1)}% of data)`;
    return `<div class="bd-seg ${c.cls}" style="flex:${n} ${n} 0" title="${escapeHTML(title)}" data-view="${c.view}">${pct >= 6 ? c.label : ''}</div>`;
  }).join('');
  barEl.querySelectorAll('.bd-seg').forEach(el => {
    el.addEventListener('click', () => setView(el.dataset.view));
  });
}

async function refreshBreakdown() {
  try {
    const r = await postJSON('/api/classification', { filter: state.filter });
    renderBreakdownBar(
      document.getElementById('bd-requests'),
      document.getElementById('bd-requests-total'),
      BREAKDOWN_CELLS, r, 'hits', n => fmtInt(n) + ' req',
    );
    renderBreakdownBar(
      document.getElementById('bd-bytes'),
      document.getElementById('bd-bytes-total'),
      BREAKDOWN_CELLS, r, 'bytes', n => fmtBytes(n),
    );
    const totalHits = BREAKDOWN_CELLS.reduce((s, c) => s + (r[c.key] || 0), 0) || 1;
    const totalBytes = BREAKDOWN_CELLS.reduce((s, c) => s + (r[c.bkey] || 0), 0) || 1;
    const legend = document.getElementById('breakdown-legend');
    legend.innerHTML = BREAKDOWN_CELLS.map(c => {
      const n = r[c.key] || 0;
      const b = r[c.bkey] || 0;
      return `<span class="lg" title="${escapeHTML(`${c.label}: ${fmtInt(n)} req · ${fmtBytes(b)}`)}"><span class="sw ${c.cls}"></span>${c.label}: ${fmtInt(n)} req · ${fmtBytes(b)}</span>`;
    }).join('') + `<span class="flagged">${fmtInt(r.flagged_ips || 0)} attacker IPs flagged</span>`;
  } catch (e) { console.error('classification:', e); }
}

// viewFilter returns the server-side filter to attach for a given view.
// For "local" we flip the is_local default from exclude→include so the
// local view actually shows local traffic.
function viewFilter(base, view) {
  const f = deepCopyFilter(base || state.filter);
  if (view === 'local') {
    f.include = f.include || {};
    if (!(f.include.is_local || []).includes('true')) {
      f.include.is_local = [...(f.include.is_local || []), 'true'];
    }
  }
  return f;
}
// viewTable picks which SQL table the dashboard should query. Local lives
// inside the dynamic table (with is_local=1), so Local view reuses it.
function viewTable(view) {
  switch (view) {
    case 'static':    return 'static';
    case 'malicious': return 'malicious';
    default:          return 'dynamic';
  }
}

// --- main refresh cycle ---
let inflight = null;
async function refreshAll() {
  renderChips();
  if (inflight) inflight.abort();
  const ac = new AbortController();
  inflight = ac;
  const table = viewTable(state.view);
  const effectiveFilter = viewFilter(state.filter, state.view);
  const body = { filter: effectiveFilter, topn: state.topN, table };
  refreshBreakdown();
  try {
    const url = table === 'static' ? '/api/static' : '/api/dashboard';
    const r = await fetch(url, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body), signal: ac.signal,
    });
    if (!r.ok) throw new Error(r.status);
    const dash = await r.json();
    renderOverview(dash.overview || {});
    renderStatusClass(dash.status_class || {});
    renderTimeline(dash.timeline || []);
    renderPanels(dash.panels || {});
  } catch (e) {
    if (e.name !== 'AbortError') console.error('dashboard:', e);
  }
  // Refresh rows.
  state.rowsOffset = 0;
  try {
    const rowsResp = await postJSON('/api/rows', { filter: effectiveFilter, table });
    renderRows(rowsResp.rows || [], false);
  } catch (e) { console.error('rows:', e); }
}

function setView(v) {
  if (!['dynamic', 'static', 'local', 'malicious'].includes(v)) return;
  state.view = v;
  document.querySelectorAll('.view-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.view === v);
  });
  document.body.dataset.view = v;
  refreshAll();
}

async function loadMoreRows() {
  state.rowsOffset += 50;
  try {
    const r = await fetch('/api/rows?offset=' + state.rowsOffset, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filter: viewFilter(state.filter, state.view), table: viewTable(state.view) }),
    });
    const data = await r.json();
    renderRows(data.rows || [], true);
  } catch (e) { console.error('rows more:', e); }
}

// --- static-asset panel (on demand) ---
async function loadStatic() {
  const btn = document.getElementById('load-static');
  const panelsEl = document.getElementById('static-panels');
  btn.disabled = true;
  panelsEl.innerHTML = `<div class="hint"><span class="spinner"></span>computing static summaries…</div>`;
  try {
    const r = await postJSON('/api/static', { filter: state.filter, topn: state.topN });
    panelsEl.innerHTML = '';
    const spec = [
      { name: 'uri', title: 'Top static files' },
      { name: 'ip', title: 'Top IPs (static)' },
      { name: 'referer', title: 'Top referrers (static)' },
      { name: 'country', title: 'Top countries (static)' },
      { name: 'host', title: 'Top hosts (static)' },
    ];
    spec.forEach(s => {
      const rows = r.panels?.[s.name] || [];
      const sec = document.createElement('section');
      sec.className = 'panel';
      const maxHits = Math.max(...rows.map(x => x.hits || 0)) || 1;
      sec.innerHTML = `
        <div class="panel-title">${escapeHTML(s.title)} <span class="muted">${rows.length}</span></div>
        <table class="panel-table">
          <tbody>${rows.map(row => {
            const pct = ((row.hits || 0) / maxHits) * 100;
            return `<tr><td class="key-cell" title="${escapeHTML(row.key)}">${escapeHTML(truncate(row.key, 80))}</td>
                        <td class="right">${fmtInt(row.hits)}</td>
                        <td class="right">${fmtBytes(row.bytes)}</td>
                        <td class="bar-cell"><div class="bar" style="width:${pct.toFixed(1)}%"></div></td></tr>`;
          }).join('') || '<tr><td class="panel-empty">no data</td></tr>'}</tbody>
        </table>
      `;
      panelsEl.appendChild(sec);
    });
    const ov = r.overview || {};
    const head = document.createElement('section');
    head.className = 'panel';
    head.innerHTML = `
      <div class="panel-title">Static overview</div>
      <div class="hint">${fmtInt(ov.hits)} hits · ${fmtInt(ov.visitors)} visitors · ${fmtBytes(ov.bytes)}</div>
    `;
    panelsEl.insertBefore(head, panelsEl.firstChild);
  } catch (e) {
    panelsEl.innerHTML = `<div class="hint">error: ${escapeHTML(String(e))}</div>`;
  }
  btn.disabled = false;
}

// --- live tail ---
let liveCount = 0;
function flashLive() {
  const el = document.getElementById('live-flash');
  liveCount++;
  el.textContent = `live · ${liveCount}`;
  el.classList.remove('hidden');
  el.classList.add('visible');
  clearTimeout(flashLive.t);
  flashLive.t = setTimeout(() => {
    el.classList.remove('visible');
    el.classList.add('hidden');
  }, 800);
}
function openWS() {
  const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${scheme}://${location.host}/ws`);
  ws.onmessage = (ev) => {
    try {
      const msg = JSON.parse(ev.data);
      if (msg.type === 'event') {
        flashLive();
        // Prepend into rows if it matches current filter (best-effort;
        // exclusions/time-range aren't fully replayed client-side).
        const body = document.getElementById('rows-body');
        const tr = document.createElement('tr');
        tr.className = 'row-clickable';
        const r = msg.row;
        const ua = r.browser && r.os ? `${r.browser} / ${r.os}` : (r.user_agent || '');
        const dur = Math.round((r.duration || 0) / 1e6);
        tr.innerHTML = `
          <td>${escapeHTML(fmtTs(r.ts))}</td>
          <td class="${statusClass(r.status)}">${r.status}</td>
          <td>${escapeHTML(r.method || '')}</td>
          <td>${escapeHTML(truncate(r.host || '', 20))}</td>
          <td title="${escapeHTML(r.uri || '')}">${escapeHTML(truncate(r.uri || '', 60))}</td>
          <td>${escapeHTML(r.ip || '')}</td>
          <td>${escapeHTML(r.country || '')}</td>
          <td title="${escapeHTML(r.user_agent || '')}">${escapeHTML(truncate(ua, 30))}</td>
          <td class="right">${dur}</td>
        `;
        body.insertBefore(tr, body.firstChild);
        while (body.children.length > 300) body.removeChild(body.lastChild);
      }
    } catch (e) { /* ignore */ }
  };
  ws.onclose = () => setTimeout(openWS, 2000);
}

// --- wire up ---
document.getElementById('clear-filters').addEventListener('click', () => {
  state.filter = { include: {}, exclude: {}, time_from: null, time_to: null };
  refreshAll();
});
document.getElementById('load-static').addEventListener('click', loadStatic);
document.getElementById('rows-more').addEventListener('click', loadMoreRows);
document.querySelectorAll('.view-btn').forEach(btn => {
  btn.addEventListener('click', () => setView(btn.dataset.view));
});

async function pollStatus() {
  try {
    const s = await getJSON('/api/status');
    document.getElementById('status').textContent =
      `clients: ${s.clients} · v${s.version}`;
    const ind = document.getElementById('ingest-indicator');
    ind.classList.toggle('hidden', !s.ingest_busy);
  } catch (e) { /* ignore */ }
}
setInterval(pollStatus, 3000);
pollStatus();
refreshAll();
openWS();
