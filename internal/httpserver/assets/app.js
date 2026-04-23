// caddylogs dashboard — single-file vanilla JS.

const state = {
  filter: { include: {}, exclude: {}, contains: {}, time_from: null, time_to: null },
  topN: 10,
  rowsOffset: 0,
  rowsBuffer: [], // live events appended client-side between refreshes
  maxLiveRows: 200,
  view: 'dynamic',   // "dynamic" | "static" | "local" | "bots" | "malicious"
  sortBy: 'hits',    // "hits" | "bytes"
  // 'local' renders timestamps in the browser's timezone, 'utc' in UTC.
  // Persisted in localStorage so the choice survives reloads.
  timeMode: (typeof localStorage !== 'undefined' && localStorage.getItem('caddylogs.timeMode') === 'utc') ? 'utc' : 'local',
  // Most-recent timestamp we've seen for the current view when no time
  // filter is active. Used as the "now" reference for range presets so
  // "last 7 days" means 7 days before the freshest row, not 7 days
  // before wall-clock (which would be empty for historical logs).
  globalLast: null,
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
function inUTC() { return state.timeMode === 'utc'; }
function fmtTs(ts) {
  const d = ts instanceof Date ? ts : new Date(ts);
  if (inUTC()) return d.toISOString().replace('T', ' ').slice(0, 19);
  const pad2 = n => (n < 10 ? '0' : '') + n;
  return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) + ' ' +
    pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
}

// pickTimelineFormat returns a Date -> string formatter whose granularity
// matches the total span so labels stay informative without being redundant.
// Dates outside the current year are suffixed with " YYYY" so a range
// that straddles a year boundary stays unambiguous. Honors state.timeMode:
// UTC labels are suffixed with 'Z'; local labels carry no suffix.
function pickTimelineFormat(spanMs) {
  const pad2 = n => (n < 10 ? '0' : '') + n;
  const MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const utc = inUTC();
  const yr = d => utc ? d.getUTCFullYear() : d.getFullYear();
  const mo = d => utc ? d.getUTCMonth()    : d.getMonth();
  const da = d => utc ? d.getUTCDate()     : d.getDate();
  const hr = d => utc ? d.getUTCHours()    : d.getHours();
  const mi = d => utc ? d.getUTCMinutes()  : d.getMinutes();
  const se = d => utc ? d.getUTCSeconds()  : d.getSeconds();
  const tz = utc ? 'Z' : '';
  const currentYear = yr(new Date());
  const withYear = (d, base) =>
    yr(d) === currentYear ? base : base + ' ' + yr(d);
  if (spanMs < 2 * 60 * 60 * 1000) {
    // < 2h: HH:MM:SS
    return d => pad2(hr(d)) + ':' + pad2(mi(d)) + ':' + pad2(se(d)) + tz;
  }
  if (spanMs < 36 * 60 * 60 * 1000) {
    // < 36h: HH:MM
    return d => pad2(hr(d)) + ':' + pad2(mi(d)) + tz;
  }
  if (spanMs < 10 * 24 * 60 * 60 * 1000) {
    // < 10d: "Apr 22 14:00"
    return d => withYear(d, MONTHS[mo(d)] + ' ' + da(d) + ' ' + pad2(hr(d)) + ':' + pad2(mi(d)));
  }
  if (spanMs < 2 * 365 * 24 * 60 * 60 * 1000) {
    // < 2y: "Apr 22"
    return d => withYear(d, MONTHS[mo(d)] + ' ' + da(d));
  }
  // multi-year
  return d => yr(d) + '-' + pad2(mo(d) + 1) + '-' + pad2(da(d));
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
    contains: Object.fromEntries(Object.entries(f.contains || {}).map(([k, v]) => [k, [...v]])),
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
  const add = (dim, val, kind) => {
    const el = document.createElement('span');
    const excl = kind === 'exclude';
    const contains = kind === 'contains';
    el.className = 'chip' + (excl ? ' excl' : '') + (contains ? ' contains' : '');
    const op = excl ? ' ≠' : contains ? ' ∋' : ' =';
    el.innerHTML = `<span class="dim">${escapeHTML(PRETTY_DIM[dim] || dim)}${op}</span>
                    <span class="val">${escapeHTML(truncate(String(val), 50))}</span>
                    <span class="x" title="Remove filter">×</span>`;
    el.querySelector('.x').addEventListener('click', () => {
      const bucket = state.filter[kind === 'include' ? 'include' : kind];
      bucket[dim] = (bucket[dim] || []).filter(v => v !== val);
      if (bucket[dim].length === 0) delete bucket[dim];
      refreshAll();
    });
    if (dim === 'ip' && kind === 'include') {
      el.addEventListener('contextmenu', (e) => {
        e.preventDefault();
        openTagMenu(String(val), e.clientX, e.clientY);
      });
      el.title = 'right-click to tag';
    }
    c.appendChild(el);
  };
  for (const [dim, vals] of Object.entries(state.filter.include || {})) {
    for (const v of vals) add(dim, v, 'include');
  }
  for (const [dim, vals] of Object.entries(state.filter.exclude || {})) {
    for (const v of vals) add(dim, v, 'exclude');
  }
  for (const [dim, vals] of Object.entries(state.filter.contains || {})) {
    for (const v of vals) add(dim, v, 'contains');
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
  // Include-IP is single-select: a drill-down to one IP almost always
  // means "switch to this one" rather than "union with the previous".
  // Filters on other dimensions (status_class, method, ...) stay
  // additive/OR since those unions are genuinely useful.
  if (dim === 'ip' && !excl) {
    bucket[dim] = [val];
  } else {
    bucket[dim] = bucket[dim] || [];
    if (!bucket[dim].includes(val)) bucket[dim].push(val);
  }
  refreshAll();
}
// addContainsFilter stages a substring (SQL LIKE '%v%') filter for a
// dimension. Used by the free-text URL input; like addFilter it
// refreshes the dashboard on change.
function addContainsFilter(dim, val) {
  val = String(val || '').trim();
  if (!val) return;
  state.filter.contains = state.filter.contains || {};
  const bucket = state.filter.contains;
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
  // When the user has no time filter active, overview.last reflects the
  // full dataset's end; cache it so range presets can compute "last N
  // days" relative to the freshest data rather than wall-clock.
  if (ov.last && !state.filter.time_from && !state.filter.time_to) {
    state.globalLast = ov.last;
  }
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
  const h = 180;           // total svg height
  const chartH = 156;      // bar drawing area (top)
  const axisH = 24;        // axis strip (bottom 24px for ticks + labels)
  svg.setAttribute('viewBox', `0 0 ${w} ${h}`);
  svg.innerHTML = '';
  if (!buckets || buckets.length === 0) return;
  const maxHits = Math.max(...buckets.map(b => b.hits));
  const barW = Math.max(1, w / buckets.length);
  const ns = 'http://www.w3.org/2000/svg';
  buckets.forEach((b, i) => {
    const x = i * barW;
    const bh = (b.hits / maxHits) * (chartH - 4);
    const rect = document.createElementNS(ns, 'rect');
    rect.setAttribute('class', 'tl-bar');
    rect.setAttribute('x', x.toFixed(2));
    rect.setAttribute('y', (chartH - bh).toFixed(2));
    rect.setAttribute('width', Math.max(1, barW - 1).toFixed(2));
    rect.setAttribute('height', bh.toFixed(2));
    const t = document.createElementNS(ns, 'title');
    t.textContent = `${fmtTs(b.start)}: ${fmtInt(b.hits)} hits, ${fmtInt(b.visitors)} visitors`;
    rect.appendChild(t);
    svg.appendChild(rect);
  });

  // Axis baseline + date ticks.
  const axis = document.createElementNS(ns, 'line');
  axis.setAttribute('class', 'tl-axis');
  axis.setAttribute('x1', 0); axis.setAttribute('x2', w);
  axis.setAttribute('y1', chartH); axis.setAttribute('y2', chartH);
  svg.appendChild(axis);

  const spanMs = (new Date(buckets[buckets.length - 1].start) - new Date(buckets[0].start)) || 1;
  const fmt = pickTimelineFormat(spanMs);
  // Aim for roughly one label per ~130 logical px, min 2, max 8.
  const targetTicks = Math.min(8, Math.max(2, Math.floor(w / 130)));
  const tickCount = Math.min(targetTicks, buckets.length);
  const indices = [];
  for (let k = 0; k < tickCount; k++) {
    const idx = tickCount === 1 ? 0 : Math.round(k * (buckets.length - 1) / (tickCount - 1));
    if (indices.length === 0 || indices[indices.length - 1] !== idx) indices.push(idx);
  }
  indices.forEach((i, k) => {
    const bx = i * barW + barW / 2;
    const tick = document.createElementNS(ns, 'line');
    tick.setAttribute('class', 'tl-tick');
    tick.setAttribute('x1', bx); tick.setAttribute('x2', bx);
    tick.setAttribute('y1', chartH); tick.setAttribute('y2', chartH + 4);
    svg.appendChild(tick);
    const label = document.createElementNS(ns, 'text');
    label.setAttribute('class', 'tl-label');
    // Keep first/last labels inside the viewport so they aren't clipped.
    let anchor = 'middle';
    if (k === 0) anchor = 'start';
    else if (k === indices.length - 1) anchor = 'end';
    label.setAttribute('text-anchor', anchor);
    const lx = anchor === 'start' ? 2 : anchor === 'end' ? w - 2 : bx;
    label.setAttribute('x', lx);
    label.setAttribute('y', chartH + 15);
    label.textContent = fmt(new Date(buckets[i].start));
    svg.appendChild(label);
  });
  // Brush overlay for range selection. Once the mousedown fires we install
  // mousemove/mouseup listeners on the document so the drag follows the
  // cursor even when it leaves the SVG (which matters when the user wants
  // to include the last, rightmost bucket). We clamp to SVG bounds so a
  // drag past the right edge still commits "up to the most recent bucket".
  const toBucketIdx = (clientX) => {
    const r = svg.getBoundingClientRect();
    const x = clientX - r.left;
    return Math.max(0, Math.min(buckets.length - 1, Math.floor((x / r.width) * buckets.length)));
  };
  // Use .onmousedown= (not addEventListener) because renderTimeline
  // runs on every refreshAll and the <svg> element is the same static
  // node every time. addEventListener would stack a fresh handler per
  // render; a single mousedown would then fire N handlers, each
  // appending its own semi-transparent brush rect on top of the
  // others — the "blurry blocks" effect. Assignment replaces the
  // prior handler so exactly one brush is ever drawn.
  svg.onmousedown = (e) => {
    e.preventDefault(); // avoid accidental text selection
    const start = toBucketIdx(e.clientX);
    const brushEl = document.createElementNS(ns, 'rect');
    brushEl.setAttribute('class', 'tl-brush');
    brushEl.setAttribute('y', 0);
    brushEl.setAttribute('height', chartH); // stay out of the axis strip
    svg.appendChild(brushEl);

    const onMove = (ev) => {
      const cur = toBucketIdx(ev.clientX);
      const lo = Math.min(start, cur);
      const hi = Math.max(start, cur);
      brushEl.setAttribute('x', (lo * barW).toFixed(2));
      brushEl.setAttribute('width', ((hi - lo + 1) * barW).toFixed(2));
    };
    const onUp = (ev) => {
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
      brushEl.remove();
      const cur = toBucketIdx(ev.clientX);
      const lo = Math.min(start, cur);
      const hi = Math.max(start, cur);
      if (hi <= lo) return; // click, not drag
      const bucketStart = buckets[lo].start;
      // If hi is the last bucket we leave time_to null so the query has
      // no upper bound -- "all the way to now" survives further ingest.
      const bucketEnd = hi >= buckets.length - 1
        ? null
        : (buckets[hi + 1]?.start || null);
      state.filter.time_from = bucketStart;
      state.filter.time_to = bucketEnd;
      refreshAll();
    };
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  };
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

// panelPrimary returns the object describing the primary metric column for
// the current sort mode.
function panelPrimary(def) {
  // Slow panel always displays max_ms regardless of global sort.
  if (def.extraCol === 'max_ms') {
    return { label: 'max ms', get: r => r.max_ms, fmt: fmtDuration, barOf: r => r.max_ms };
  }
  if (state.sortBy === 'bytes') {
    return { label: 'data', get: r => r.bytes, fmt: fmtBytes, barOf: r => r.bytes };
  }
  return { label: 'hits', get: r => r.hits, fmt: fmtInt, barOf: r => r.hits };
}

function renderPanels(panels) {
  const container = document.getElementById('panels');
  container.innerHTML = '';
  const defs = currentPanelDefs();
  defs.forEach(def => {
    const initialRows = panels[def.name] || [];
    const sec = document.createElement('section');
    sec.className = 'panel';
    sec.dataset.panel = def.name;
    const prim = panelPrimary(def);
    const headers =
      `<tr>
         <th data-col="key">${escapeHTML(def.dim)}<span class="col-resize"></span></th>
         <th data-col="primary" class="right">${escapeHTML(prim.label)}<span class="col-resize"></span></th>
         <th data-col="bar"></th>
       </tr>`;
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
    sec._pg = {
      rows: [],
      offset: 0,
      exhausted: false,
      initialLoaded: false,
      def: def,
    };
    appendPanelRows(sec, initialRows);
    sec._pg.offset = initialRows.length;
    sec._pg.initialLoaded = true;
    if (initialRows.length < state.topN) {
      sec._pg.exhausted = true;
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
  const prim = panelPrimary(def);
  const tbody = sec.querySelector('tbody');
  if (sec._pg.rows.length === 0 && rows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="3" class="panel-empty">no data</td></tr>`;
    return;
  }
  if (sec._pg.rows.length === 0) {
    tbody.innerHTML = '';
  }
  sec._pg.rows = sec._pg.rows.concat(rows);
  // Recompute max over ALL rows loaded so bar widths stay comparable.
  const maxPrim = Math.max(...sec._pg.rows.map(r => prim.barOf(r) || 0)) || 1;
  // Rebuild bars on already-rendered rows proportionally.
  tbody.querySelectorAll('.bar').forEach((barEl, i) => {
    const row = sec._pg.rows[i];
    if (!row) return;
    barEl.style.width = (((prim.barOf(row) || 0) / maxPrim) * 100).toFixed(1) + '%';
  });
  rows.forEach(r => {
    const tr = document.createElement('tr');
    tr.dataset.val = r.key || '(none)';
    tr.dataset.dim = def.dim;
    const tip = def.dim === 'ip'
      ? 'click to filter, shift-click to exclude, right-click to tag'
      : 'click to filter, shift-click to exclude';
    tr.setAttribute('title', tip);
    const barWidth = ((prim.barOf(r) || 0) / maxPrim) * 100;
    const val = r.key || '(none)';
    // Tooltip always shows both metrics so the toggle is informational
    // rather than destructive.
    const primVal = prim.fmt(prim.get(r));
    const rowTip = `${fmtInt(r.hits)} hits · ${fmtInt(r.visitors)} visitors · ${fmtBytes(r.bytes)}` +
      (def.extraCol === 'max_ms' ? ` · max ${fmtDuration(r.max_ms)} · avg ${fmtDuration(r.avg_ms)}` : '');
    tr.innerHTML = `
      <td class="key-cell" title="${escapeHTML(val)}">${escapeHTML(val)}</td>
      <td class="right hits-cell" title="${escapeHTML(rowTip)}">${escapeHTML(primVal)}</td>
      <td class="bar-cell"><div class="bar" style="width:${barWidth.toFixed(1)}%"></div></td>`;
    tr.addEventListener('click', (e) => {
      if (e.target.closest('.col-resize')) return;
      const v = tr.dataset.val;
      const d = tr.dataset.dim;
      if (!v || v === '(none)') return;
      addFilter(d, v, e.shiftKey);
    });
    if (def.dim === 'ip') {
      tr.addEventListener('contextmenu', (e) => {
        const ip = tr.dataset.val;
        if (!ip || ip === '(none)') return;
        e.preventDefault();
        openTagMenu(ip, e.clientX, e.clientY);
      });
    }
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
      order_by: state.sortBy,
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
    <td class="ip-cell" title="right-click to tag">${escapeHTML(r.ip || '')}</td>
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
  tr.addEventListener('contextmenu', (e) => {
    if (!e.target.closest('.ip-cell') || !r.ip) return;
    e.preventDefault();
    openTagMenu(r.ip, e.clientX, e.clientY);
  });
  body.appendChild(tr);
}

// --- classification breakdown ---
const BREAKDOWN_CELLS = [
  { key: 'real_dynamic',      bkey: 'real_dynamic_bytes',      label: 'real doc',    cls: 'bd-real-doc',    view: 'dynamic' },
  { key: 'real_static',       bkey: 'real_static_bytes',       label: 'real static', cls: 'bd-real-static', view: 'static'  },
  { key: 'bot_dynamic',       bkey: 'bot_dynamic_bytes',       label: 'bot doc',     cls: 'bd-bot-doc',     view: 'bots'    },
  { key: 'bot_static',        bkey: 'bot_static_bytes',        label: 'bot static',  cls: 'bd-bot-static',  view: 'bots'    },
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
// For "local" and "bots" we flip the matching default from exclude→include
// so those views actually show the traffic they advertise (without the
// server-side applyDefaults re-excluding them).
function viewFilter(base, view) {
  const f = deepCopyFilter(base || state.filter);
  if (view === 'local') {
    f.include = f.include || {};
    if (!(f.include.is_local || []).includes('true')) {
      f.include.is_local = [...(f.include.is_local || []), 'true'];
    }
  }
  if (view === 'bots') {
    f.include = f.include || {};
    if (!(f.include.is_bot || []).includes('true')) {
      f.include.is_bot = [...(f.include.is_bot || []), 'true'];
    }
  }
  return f;
}
// viewTable picks which SQL table the dashboard should query. Local and
// Bots both live inside the dynamic table (with is_local=1 / is_bot=1), so
// they reuse it.
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
  const body = { filter: effectiveFilter, topn: state.topN, table, order_by: state.sortBy };
  refreshBreakdown();
  refreshTagList();
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

function setSort(s) {
  if (!['hits', 'bytes'].includes(s)) return;
  if (state.sortBy === s) return;
  state.sortBy = s;
  document.querySelectorAll('.sort-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.sort === s);
  });
  refreshAll();
}

function setTimeMode(m) {
  if (!['local', 'utc'].includes(m)) return;
  state.timeMode = m;
  try { localStorage.setItem('caddylogs.timeMode', m); } catch {}
  document.querySelectorAll('.time-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.tz === m);
  });
  // Re-fetch + re-render so every timestamp (rows, timeline, chips,
  // tags, span) picks up the new mode in one pass.
  refreshAll();
}

function setView(v) {
  if (!['dynamic', 'static', 'local', 'bots', 'malicious'].includes(v)) return;
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

// --- live-row filter matching ---
// The live tail injects every non-static event into the Recent requests list
// regardless of the view. These helpers reproduce the server-side filter
// evaluation so we can mark (but still show) rows that wouldn't normally
// appear under the current view. That keeps the live feed useful while
// making it obvious when a new event doesn't actually match the current
// filter/view.
function statusClassOf(s) {
  if (s >= 500) return '5xx';
  if (s >= 400) return '4xx';
  if (s >= 300) return '3xx';
  if (s >= 200) return '2xx';
  if (s >= 100) return '1xx';
  return 'other';
}
function rowTable(r) {
  if (r.malicious_reason) return 'malicious';
  if (r.is_static) return 'static';
  return 'dynamic';
}
function dimValOfRow(dim, r) {
  switch (dim) {
    case 'ip':               return r.ip;
    case 'host':             return r.host;
    case 'uri':              return r.uri;
    case 'status':           return String(r.status);
    case 'status_class':     return statusClassOf(r.status);
    case 'method':           return r.method;
    case 'referer':          return r.referer;
    case 'browser':          return r.browser;
    case 'os':               return r.os;
    case 'device':           return r.device;
    case 'country':          return r.country;
    case 'city':             return r.city;
    case 'proto':            return r.proto;
    case 'is_bot':           return r.is_bot ? 'true' : 'false';
    case 'is_local':         return r.is_local ? 'true' : 'false';
    case 'is_static':        return r.is_static ? 'true' : 'false';
    case 'malicious_reason': return r.malicious_reason || '';
  }
  return undefined;
}
function matchesFilter(r, filter) {
  if (filter.time_from && new Date(r.ts) < new Date(filter.time_from)) return false;
  if (filter.time_to && new Date(r.ts) >= new Date(filter.time_to)) return false;
  for (const [dim, vals] of Object.entries(filter.include || {})) {
    if (!vals || !vals.length) continue;
    const rv = dimValOfRow(dim, r);
    if (rv === undefined) continue;
    if (!vals.map(String).includes(String(rv))) return false;
  }
  for (const [dim, vals] of Object.entries(filter.exclude || {})) {
    if (!vals || !vals.length) continue;
    const rv = dimValOfRow(dim, r);
    if (rv === undefined) continue;
    if (vals.map(String).includes(String(rv))) return false;
  }
  for (const [dim, vals] of Object.entries(filter.contains || {})) {
    if (!vals || !vals.length) continue;
    const rv = dimValOfRow(dim, r);
    if (rv === undefined) continue;
    const rvStr = String(rv);
    // OR within a dim: the row matches if any listed substring is found.
    if (!vals.some(v => rvStr.includes(String(v)))) return false;
  }
  return true;
}
// rowMatchesCurrentView returns true when r would be picked up by the
// server-side query that populates the current view's rows panel. We
// approximate the server's applyDefaults (exclude bots/local unless the
// view or the user has opted in) since the client doesn't know the server
// flags; this is correct for the default server config.
function rowMatchesCurrentView(r) {
  if (rowTable(r) !== viewTable(state.view)) return false;
  const f = viewFilter(state.filter, state.view);
  if (state.view !== 'malicious') {
    f.exclude = f.exclude || {};
    const incBot = (f.include && f.include.is_bot) || [];
    const excBot = f.exclude.is_bot || [];
    if (!incBot.includes('true') && !excBot.includes('true')) {
      f.exclude.is_bot = [...excBot, 'true'];
    }
    const incLoc = (f.include && f.include.is_local) || [];
    const excLoc = f.exclude.is_local || [];
    if (!incLoc.includes('true') && !excLoc.includes('true')) {
      f.exclude.is_local = [...excLoc, 'true'];
    }
  }
  return matchesFilter(r, f);
}

// --- manual IP tagging ---
// A manual tag pins an IP to one of {real, local, bot, malicious}. The server
// rewrites existing rows in the store and teaches the classifier so every
// future live-tail event for this IP is classified the same way. Right-click
// on an IP value (in a panel row, the raw-events list, or an IP filter chip)
// to open the menu.
function openTagMenu(ip, x, y) {
  closeTagMenu();
  const menu = document.createElement('div');
  menu.className = 'tag-menu';
  menu.id = 'tag-menu';
  menu.innerHTML = `
    <div class="tag-menu-title">Tag <span class="ip">${escapeHTML(ip)}</span> as:</div>
    <button data-tag="real">Real</button>
    <button data-tag="local">Local</button>
    <button data-tag="bot">Bot</button>
    <button data-tag="malicious">Malicious</button>
    <button class="cancel" type="button">Cancel</button>
  `;
  // Clamp the menu into the viewport so right-clicking near the edge still
  // shows the whole menu.
  const W = 200, H = 220;
  menu.style.left = Math.max(4, Math.min(x, window.innerWidth - W)) + 'px';
  menu.style.top = Math.max(4, Math.min(y, window.innerHeight - H)) + 'px';
  document.body.appendChild(menu);
  menu.querySelectorAll('button[data-tag]').forEach(btn => {
    btn.addEventListener('click', async (ev) => {
      ev.stopPropagation();
      const tag = btn.dataset.tag;
      closeTagMenu();
      await applyTag(ip, tag);
    });
  });
  menu.querySelector('.cancel').addEventListener('click', closeTagMenu);
  // Defer installing the outside-click listener so the click that opened the
  // menu doesn't immediately close it.
  setTimeout(() => {
    document.addEventListener('click', outsideTagClose, true);
    document.addEventListener('keydown', escTagClose);
  }, 0);
}
function outsideTagClose(e) {
  const m = document.getElementById('tag-menu');
  if (m && !m.contains(e.target)) closeTagMenu();
}
function escTagClose(e) {
  if (e.key === 'Escape') closeTagMenu();
}
function closeTagMenu() {
  const m = document.getElementById('tag-menu');
  if (m) m.remove();
  document.removeEventListener('click', outsideTagClose, true);
  document.removeEventListener('keydown', escTagClose);
}
async function applyTag(ip, tag) {
  try {
    const r = await fetch('/api/tag', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, tag }),
    });
    if (!r.ok) {
      const body = await r.json().catch(() => ({}));
      throw new Error(body.error || ('HTTP ' + r.status));
    }
    refreshAll();
  } catch (e) {
    alert('Failed to tag ' + ip + ' as ' + tag + ': ' + e.message);
  }
}

// --- tag inspection + removal ---
// Fetches the persistent tag set and renders a dismissable list so the
// operator can audit or revoke overrides at a glance. Removing a tag
// clears the file + classifier entry but deliberately leaves already-
// classified rows alone; the hint in the HTML explains the trade.
// initCollapsibleSection wires a clickable title to a body element that
// toggles hidden. Remembered state is keyed per-section in localStorage
// so preferences survive reloads; unset keys fall back to collapsed,
// which keeps the initial dashboard view compact.
function initCollapsibleSection({ titleSelector, bodySelector, storageKey }) {
  const title = document.querySelector(titleSelector);
  const body = document.querySelector(bodySelector);
  if (!title || !body) return;
  let expanded = false;
  try {
    if (storageKey && localStorage.getItem(storageKey) === '1') expanded = true;
  } catch {}
  const apply = (want) => {
    title.classList.toggle('expanded', want);
    body.classList.toggle('hidden', !want);
    if (storageKey) {
      try { localStorage.setItem(storageKey, want ? '1' : '0'); } catch {}
    }
  };
  apply(expanded);
  title.addEventListener('click', () => apply(!title.classList.contains('expanded')));
  title.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      apply(!title.classList.contains('expanded'));
    }
  });
}

async function refreshTagList() {
  const sec = document.getElementById('tags-section');
  const body = document.getElementById('tags-body');
  const count = document.getElementById('tags-count');
  const pathEl = document.getElementById('tags-file-path');
  try {
    const data = await getJSON('/api/tags');
    const tags = data.tags || [];
    if (pathEl) pathEl.textContent = data.path || '';
    if (tags.length === 0) {
      sec.classList.add('hidden');
      count.textContent = '0';
      body.innerHTML = '';
      return;
    }
    sec.classList.remove('hidden');
    count.textContent = String(tags.length);
    body.innerHTML = '';
    for (const t of tags) {
      const tr = document.createElement('tr');
      const since = t.at ? fmtTs(new Date(Math.round(t.at / 1e6))) : '';
      const source = t.source || 'manual';
      const reasonTip = t.reason ? ` — ${t.reason}` : '';
      tr.innerHTML = `
        <td class="tag-ip" title="click to filter by this IP">${escapeHTML(t.ip)}</td>
        <td><span class="tag-badge tag-${escapeHTML(t.tag)}">${escapeHTML(t.tag)}</span></td>
        <td class="tag-source" title="${escapeHTML(source + reasonTip)}">${escapeHTML(source)}</td>
        <td class="muted">${escapeHTML(since)}</td>
        <td class="right"><button class="btn btn-ghost tag-remove" type="button">untag</button></td>
      `;
      tr.querySelector('.tag-ip').addEventListener('click', () => addFilter('ip', t.ip, false));
      tr.querySelector('.tag-remove').addEventListener('click', async () => {
        await removeTag(t.ip);
      });
      body.appendChild(tr);
    }
  } catch (e) {
    console.error('tags:', e);
  }
}
// --- heuristic classifiers ---
// Classifiers are registered in Go and ship with the binary. The UI
// lists them with a Run button that triggers a reconciliation and
// shows a short summary of what changed. Listed once at load — the
// registry is static for the process lifetime.
async function loadClassifiers() {
  const sec = document.getElementById('classifiers-section');
  const body = document.getElementById('classifiers-body');
  try {
    const data = await getJSON('/api/classifiers');
    const list = data.classifiers || [];
    if (list.length === 0) {
      sec.classList.add('hidden');
      return;
    }
    sec.classList.remove('hidden');
    body.innerHTML = '';
    for (const c of list) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><code>${escapeHTML(c.name)}</code></td>
        <td class="muted">${escapeHTML(c.description)}</td>
        <td class="right"><button class="btn classifier-run" type="button">Run</button></td>
      `;
      tr.querySelector('.classifier-run').addEventListener('click', (ev) => {
        runClassifier(c.name, ev.target);
      });
      body.appendChild(tr);
    }
  } catch (e) {
    console.error('classifiers:', e);
  }
}
async function runClassifier(name, btn) {
  const original = btn ? btn.textContent : null;
  if (btn) { btn.disabled = true; btn.textContent = 'running…'; }
  try {
    const r = await fetch('/api/classifiers/run?name=' + encodeURIComponent(name), { method: 'POST' });
    if (!r.ok) {
      const body = await r.json().catch(() => ({}));
      throw new Error(body.error || ('HTTP ' + r.status));
    }
    const result = await r.json();
    const added = (result.added || []).length;
    const removed = (result.removed || []).length;
    const skipped = (result.skipped || []).length;
    const elapsed = result.elapsed_ms || 0;
    const msg = `${name}: +${added} tagged, -${removed} untagged, ${skipped} skipped (manual wins) in ${elapsed}ms`;
    console.log(msg);
    if (added || removed) {
      refreshAll();
    } else {
      refreshTagList();
    }
    if (btn) { btn.textContent = `+${added} / -${removed}`; }
    setTimeout(() => { if (btn && original != null) { btn.textContent = original; btn.disabled = false; } }, 2000);
  } catch (e) {
    alert('Failed to run classifier ' + name + ': ' + e.message);
    if (btn && original != null) { btn.textContent = original; btn.disabled = false; }
  }
}

async function removeTag(ip) {
  try {
    const r = await fetch('/api/tag?ip=' + encodeURIComponent(ip), { method: 'DELETE' });
    if (!r.ok) {
      const body = await r.json().catch(() => ({}));
      throw new Error(body.error || ('HTTP ' + r.status));
    }
    refreshAll();
  } catch (e) {
    alert('Failed to untag ' + ip + ': ' + e.message);
  }
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
        // Prepend into rows. Rows that wouldn't match the current view's
        // filtered query get an off-filter class so it's obvious they are
        // not part of what the panels are summarizing.
        const body = document.getElementById('rows-body');
        const tr = document.createElement('tr');
        const r = msg.row;
        const matches = rowMatchesCurrentView(r);
        tr.className = 'row-clickable' + (matches ? '' : ' off-filter');
        if (!matches) {
          tr.setAttribute('title',
            `live event outside the current ${state.view} view (${rowTable(r)})`);
        }
        const ua = r.browser && r.os ? `${r.browser} / ${r.os}` : (r.user_agent || '');
        const dur = Math.round((r.duration || 0) / 1e6);
        tr.innerHTML = `
          <td>${escapeHTML(fmtTs(r.ts))}</td>
          <td class="${statusClass(r.status)}">${r.status}</td>
          <td>${escapeHTML(r.method || '')}</td>
          <td>${escapeHTML(truncate(r.host || '', 20))}</td>
          <td title="${escapeHTML(r.uri || '')}">${escapeHTML(truncate(r.uri || '', 60))}</td>
          <td class="ip-cell" title="right-click to tag">${escapeHTML(r.ip || '')}</td>
          <td>${escapeHTML(r.country || '')}</td>
          <td title="${escapeHTML(r.user_agent || '')}">${escapeHTML(truncate(ua, 30))}</td>
          <td class="right">${dur}</td>
        `;
        tr.addEventListener('contextmenu', (e) => {
          if (!e.target.closest('.ip-cell') || !r.ip) return;
          e.preventDefault();
          openTagMenu(r.ip, e.clientX, e.clientY);
        });
        body.insertBefore(tr, body.firstChild);
        while (body.children.length > 300) body.removeChild(body.lastChild);
      }
    } catch (e) { /* ignore */ }
  };
  ws.onclose = () => setTimeout(openWS, 2000);
}

// --- wire up ---
document.getElementById('clear-filters').addEventListener('click', () => {
  state.filter = { include: {}, exclude: {}, contains: {}, time_from: null, time_to: null };
  const ipInput = document.getElementById('filter-ip');
  const uriInput = document.getElementById('filter-uri');
  if (ipInput) ipInput.value = '';
  if (uriInput) uriInput.value = '';
  refreshAll();
});
// Free-text filter inputs. IP input does exact include, URI does
// substring contains. Enter applies; blank values are ignored.
const ipInputEl = document.getElementById('filter-ip');
if (ipInputEl) {
  ipInputEl.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter') return;
    const v = ipInputEl.value.trim();
    if (!v) return;
    addFilter('ip', v, false);
    ipInputEl.value = '';
  });
}
const uriInputEl = document.getElementById('filter-uri');
if (uriInputEl) {
  uriInputEl.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter') return;
    const v = uriInputEl.value.trim();
    if (!v) return;
    addContainsFilter('uri', v);
    uriInputEl.value = '';
  });
}

// Timeline range presets. "N days back from the freshest known
// timestamp" so historical logs don't end up with an empty window
// when wall-clock has moved past the log's end. time_to stays null
// so live-tail ingestion keeps appending inside the range.
function applyRangePreset(days) {
  if (!days || days <= 0) {
    state.filter.time_from = null;
    state.filter.time_to = null;
  } else {
    const refEnd = state.globalLast ? new Date(state.globalLast) : new Date();
    const start = new Date(refEnd.getTime() - days * 86400000);
    state.filter.time_from = start.toISOString();
    state.filter.time_to = null;
  }
  refreshAll();
}
document.querySelectorAll('.range-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    applyRangePreset(parseInt(btn.dataset.days, 10) || 0);
  });
});
document.getElementById('load-static').addEventListener('click', loadStatic);
document.getElementById('rows-more').addEventListener('click', loadMoreRows);
document.querySelectorAll('.view-btn').forEach(btn => {
  btn.addEventListener('click', () => setView(btn.dataset.view));
});
document.querySelectorAll('.sort-btn').forEach(btn => {
  btn.addEventListener('click', () => setSort(btn.dataset.sort));
});
document.querySelectorAll('.time-btn').forEach(btn => {
  btn.classList.toggle('active', btn.dataset.tz === state.timeMode);
  btn.addEventListener('click', () => setTimeMode(btn.dataset.tz));
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
initCollapsibleSection({
  titleSelector: '#static-section .collapsible-title',
  bodySelector: '#static-collapsible',
  storageKey: 'cl_static_expanded',
});
initCollapsibleSection({
  titleSelector: '#classifiers-section .collapsible-title',
  bodySelector: '#classifiers-collapsible',
  storageKey: 'cl_classifiers_expanded',
});
initCollapsibleSection({
  titleSelector: '#tags-section .collapsible-title',
  bodySelector: '#tags-collapsible',
  storageKey: 'cl_tags_expanded',
});
loadClassifiers();
refreshAll();
openWS();
