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
  // Panel min-column width: 'narrow' fits more panels side-by-side,
  // 'wide' lets long values (URIs, UAs) breathe. Drives the
  // --panel-min-width CSS variable on #panels.
  panelWidth: (typeof localStorage !== 'undefined' && localStorage.getItem('caddylogs.panelWidth')) || 'medium',
  // Most-recent timestamp we've seen for the current view when no time
  // filter is active. Used as the "now" reference for range presets so
  // "last 7 days" means 7 days before the freshest row, not 7 days
  // before wall-clock (which would be empty for historical logs).
  globalLast: null,
  // Oldest timestamp seen with no time filter active — the dataset's left
  // edge. Used to aim the timeline's expand/squish animation when the
  // range is cleared to "all" (there is no explicit time_from to target).
  globalFirst: null,
  // True while the time window is the implicit default ("last
  // DEFAULT_RANGE_DAYS days") rather than something the operator chose. The
  // URL omits the bounds in that case so a reload re-anchors to the freshest
  // data instead of freezing the window at an old time_from.
  defaultRange: false,
  // Pinned filter snapshots overlaid on the timeline for comparison.
  // Each pin captures view + filter (drilldown) but NOT time range,
  // so pins follow the current time window — pins are about *what*,
  // not *when*. Loaded from localStorage on boot; capped at PIN_COLORS
  // length so each pin gets a distinct color. Each pin = one extra
  // /api/timeline call per refresh.
  pins: loadPins(),
};

// --- helpers ---
function fmtInt(n) { return (n || 0).toLocaleString(); }
function fmtBytes(n) {
  if (!n) return '0 B';
  // SI units (powers of 1000) rather than IEC binary (KiB/MiB) — saves
  // a character per label, which matters for the timeline's Y-axis
  // gutter, and the precision difference (~2.4% at MB) is irrelevant
  // for log analytics. Trailing .0 is stripped so exact niceTicks
  // values render as "1 MB" rather than "1.0 MB".
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0; let v = n;
  while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; }
  const s = v < 10 ? v.toFixed(1) : v.toFixed(0);
  return s.replace(/\.0$/, '') + ' ' + u[i];
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
// The shorter formats (HH:MM:SS, HH:MM) prepend "Mon DD" when the bucket
// isn't today and " YYYY" when it isn't this year — without that, a brushed
// range from a week ago would just say "14:32" with no anchor. Honors
// state.timeMode: UTC labels are suffixed with 'Z'; local labels carry no
// suffix.
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
  const today = new Date();
  const todayYr = yr(today), todayMo = mo(today), todayDa = da(today);
  // datePrefix tacks a "Mon DD " (and " YYYY" if needed) onto the time
  // formats so labels stay self-describing when the data isn't from
  // today. Returns "" when the bucket is today so same-day labels stay
  // clean.
  const datePrefix = d => {
    const sameYear = yr(d) === todayYr;
    if (sameYear && mo(d) === todayMo && da(d) === todayDa) return '';
    const base = MONTHS[mo(d)] + ' ' + da(d);
    return (sameYear ? base : base + ' ' + yr(d)) + ' ';
  };
  const withYear = (d, base) =>
    yr(d) === todayYr ? base : base + ' ' + yr(d);
  if (spanMs < 2 * 60 * 60 * 1000) {
    // < 2h: HH:MM:SS, prefixed with date when not today.
    return d => datePrefix(d) + pad2(hr(d)) + ':' + pad2(mi(d)) + ':' + pad2(se(d)) + tz;
  }
  if (spanMs < 36 * 60 * 60 * 1000) {
    // < 36h: HH:MM, prefixed with date when not today.
    return d => datePrefix(d) + pad2(hr(d)) + ':' + pad2(mi(d)) + tz;
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

// --- URL hash <-> state sync ---
// Filters, view, and sort are encoded in the URL hash so the browser
// back/forward buttons walk through prior dashboard states and links can
// share a specific drilldown. localStorage-only prefs (timeMode,
// panelWidth) deliberately stay out of the hash — they're per-browser
// preferences, not per-link state.
//
// Hash format (URLSearchParams-style, repeated keys for list values):
//   view=static&sort=bytes
//   inc.ip=1.2.3.4&inc.ip=5.6.7.8&exc.method=GET&con.uri=admin
//   from=2026-04-01T00:00:00Z&to=2026-04-29T00:00:00Z
const VIEWS = ['dynamic', 'static', 'local', 'bots', 'malicious', 'all'];
const SORTS = ['hits', 'bytes'];
function encodeStateToHash() {
  const p = new URLSearchParams();
  if (state.view && state.view !== 'dynamic') p.set('view', state.view);
  if (state.sortBy && state.sortBy !== 'hits') p.set('sort', state.sortBy);
  const f = state.filter || {};
  for (const [dim, vals] of Object.entries(f.include || {})) {
    for (const v of vals) p.append('inc.' + dim, v);
  }
  for (const [dim, vals] of Object.entries(f.exclude || {})) {
    for (const v of vals) p.append('exc.' + dim, v);
  }
  for (const [dim, vals] of Object.entries(f.contains || {})) {
    for (const v of vals) p.append('con.' + dim, v);
  }
  // Time window: the implicit default is encoded as "nothing", an explicit
  // "all" as range=all (so a reload doesn't re-apply the default), and any
  // chosen window as its bounds.
  if (!state.defaultRange) {
    if (f.time_from) p.set('from', f.time_from);
    if (f.time_to)   p.set('to',   f.time_to);
    if (!f.time_from && !f.time_to) p.set('range', 'all');
  }
  // The log-file stats overlay participates in the URL so it is deep-linkable
  // (#logs=1) and the back button closes it like leaving a page.
  if (state.fileStatsOpen) p.set('logs', '1');
  return p.toString();
}
function applyHashToState() {
  const hash = (window.location.hash || '').replace(/^#/, '');
  const p = new URLSearchParams(hash);
  state.filter = { include: {}, exclude: {}, contains: {}, time_from: null, time_to: null };
  const view = p.get('view') || 'dynamic';
  state.view = VIEWS.includes(view) ? view : 'dynamic';
  const sort = p.get('sort') || 'hits';
  state.sortBy = SORTS.includes(sort) ? sort : 'hits';
  for (const [k, v] of p.entries()) {
    let bucket = null, dim = null;
    if      (k.startsWith('inc.')) { bucket = state.filter.include;  dim = k.slice(4); }
    else if (k.startsWith('exc.')) { bucket = state.filter.exclude;  dim = k.slice(4); }
    else if (k.startsWith('con.')) { bucket = state.filter.contains; dim = k.slice(4); }
    if (bucket && dim) {
      bucket[dim] = bucket[dim] || [];
      bucket[dim].push(v);
    }
  }
  state.filter.time_from = p.get('from') || null;
  state.filter.time_to   = p.get('to')   || null;
  state.defaultRange = !state.filter.time_from && !state.filter.time_to
    && p.get('range') !== 'all';
  // On popstate the span is already known, so the default window can be
  // derived right away; the initial load fetches it first (see boot).
  if (state.defaultRange && state.globalLast) applyDefaultRangeWindow();
  const wantLogs = p.get('logs') === '1';
  if (wantLogs !== !!state.fileStatsOpen) {
    if (wantLogs) openFileStats(); else closeFileStats();
  }
  // Reflect view/sort in the toolbar. (Filter chips re-render via refreshAll.)
  document.querySelectorAll('.view-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.view === state.view);
  });
  document.querySelectorAll('.sort-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.sort === state.sortBy);
  });
  document.body.dataset.view = state.view;
}
// suppressURLSync is set during popstate and initial-load handling so the
// state→URL sync inside refreshAll() doesn't push the URL we just read
// back onto the history stack.
let suppressURLSync = false;
function syncURLFromState() {
  if (suppressURLSync) return;
  const newHash = encodeStateToHash();
  const curHash = (window.location.hash || '').replace(/^#/, '');
  if (newHash === curHash) return;
  const url = newHash ? '#' + newHash : (location.pathname + location.search);
  history.pushState(null, '', url);
}

// --- pinned filters (timeline overlays) ---
// PIN_COLORS is the fixed palette. Pins are capped at this length so
// every active pin gets a distinct color — beyond ~5 the chart turns
// into a tangle of similar lines and the "compare to N other slices"
// story stops being legible.
const PIN_COLORS = ['#f2b95a', '#5ccf7d', '#e07aaa', '#6cd5d5', '#c089e6'];

function loadPins() {
  try {
    const raw = (typeof localStorage !== 'undefined') && localStorage.getItem('caddylogs.pins');
    if (!raw) return [];
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr : [];
  } catch { return []; }
}
function persistPins() {
  try { localStorage.setItem('caddylogs.pins', JSON.stringify(state.pins)); } catch {}
}

// pickPinColor returns the first palette color not already in use, so
// removing a pin frees its color for the next add. With all colors
// taken the cap kicks in elsewhere; this just picks the first as a
// safe fallback.
function pickPinColor() {
  const used = new Set((state.pins || []).map(p => p.color));
  for (const c of PIN_COLORS) {
    if (!used.has(c)) return c;
  }
  return PIN_COLORS[0];
}

// PIN_VIEW_LABELS maps the internal view id to the user-facing name
// shown on the toolbar button so chip text matches the UI vocabulary
// rather than the SQL one (e.g. "dynamic" → "Real").
const PIN_VIEW_LABELS = {
  dynamic: 'Real', static: 'Static', local: 'Local',
  bots: 'Bots', malicious: 'Malicious',
};

// pinShortLabel produces the chip text — kept tight (≤2 active dims +
// "+N" overflow) so a row of chips doesn't push the range presets off
// the panel header. An unfiltered Real view collapses to just
// "baseline" since that's what it functionally is; a non-default view
// with no filter is "baseline (View)" so the operator can tell which
// pool it represents. The full filter spec lives in the chip's title
// attribute via pinDetailedLabel.
function pinShortLabel(filter, view) {
  const parts = [];
  for (const [dim, vals] of Object.entries(filter.include || {})) {
    for (const v of vals) parts.push(`${dim}=${truncate(v, 12)}`);
  }
  for (const [dim, vals] of Object.entries(filter.exclude || {})) {
    for (const v of vals) parts.push(`-${dim}=${truncate(v, 12)}`);
  }
  for (const [dim, vals] of Object.entries(filter.contains || {})) {
    for (const v of vals) parts.push(`${dim}∋${truncate(v, 12)}`);
  }
  const viewLabel = PIN_VIEW_LABELS[view] || view;
  if (parts.length === 0) {
    return view === 'dynamic' ? 'baseline' : `baseline (${viewLabel})`;
  }
  if (view !== 'dynamic') parts.unshift(viewLabel);
  const head = parts.slice(0, 2).join(', ');
  return parts.length > 2 ? `${head}, +${parts.length - 2}` : head;
}
function pinDetailedLabel(filter, view) {
  const parts = [`view=${PIN_VIEW_LABELS[view] || view}`];
  for (const [dim, vals] of Object.entries(filter.include || {})) {
    for (const v of vals) parts.push(`${dim}=${v}`);
  }
  for (const [dim, vals] of Object.entries(filter.exclude || {})) {
    for (const v of vals) parts.push(`${dim}≠${v}`);
  }
  for (const [dim, vals] of Object.entries(filter.contains || {})) {
    for (const v of vals) parts.push(`${dim}∋${v}`);
  }
  return parts.join(', ');
}

function pinCurrent() {
  if (state.pins.length >= PIN_COLORS.length) return; // cap reached
  const filter = deepCopyFilter(state.filter);
  // Strip time bounds — pins follow the current time window.
  filter.time_from = null;
  filter.time_to = null;
  state.pins.push({
    id: Date.now() + '_' + Math.random().toString(36).slice(2, 8),
    view: state.view,
    filter,
    color: pickPinColor(),
  });
  persistPins();
  renderPinChips();
  refreshAll();
}
function unpin(id) {
  state.pins = state.pins.filter(p => p.id !== id);
  persistPins();
  renderPinChips();
  refreshAll();
}

function renderPinChips() {
  const el = document.getElementById('pin-chips');
  if (!el) return;
  el.innerHTML = '';
  for (const pin of state.pins) {
    const chip = document.createElement('span');
    chip.className = 'pin-chip';
    chip.title = pinDetailedLabel(pin.filter, pin.view);
    const sw = document.createElement('span');
    sw.className = 'pin-sw';
    sw.style.background = pin.color;
    chip.appendChild(sw);
    const txt = document.createElement('span');
    txt.className = 'pin-lbl';
    txt.textContent = pinShortLabel(pin.filter, pin.view);
    chip.appendChild(txt);
    const x = document.createElement('span');
    x.className = 'pin-x';
    x.textContent = '×';
    x.title = 'remove pin';
    x.addEventListener('click', (e) => {
      e.stopPropagation();
      unpin(pin.id);
    });
    chip.appendChild(x);
    el.appendChild(chip);
  }
  const btn = document.getElementById('pin-current');
  if (btn) btn.disabled = state.pins.length >= PIN_COLORS.length;
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
      setTimeWindow(null, null);
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
  if (ov.first && !state.filter.time_from && !state.filter.time_to) {
    state.globalFirst = ov.first;
  }
  // globalLast is the presets' reference "now"; re-evaluate which preset
  // the current window matches once it's known.
  updateRangePresetHighlight();
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

// monotoneCubicCurves returns the SVG cubic Bézier "C" segments tracing
// pts in order. Tangents come from Fritsch-Carlson monotone Hermite
// interpolation, which guarantees the curve doesn't overshoot — plain
// Catmull-Rom would dip below the baseline before/after a sharp spike,
// looking like negative traffic. Returns just the C-segments (no
// leading M) so callers compose with their own move/anchor commands
// for line vs. area paths.
function monotoneCubicCurves(pts) {
  const n = pts.length;
  if (n < 2) return '';
  const d = new Array(n - 1);
  for (let i = 0; i < n - 1; i++) {
    d[i] = (pts[i + 1].y - pts[i].y) / (pts[i + 1].x - pts[i].x);
  }
  const m = new Array(n);
  m[0] = d[0];
  m[n - 1] = d[n - 2];
  for (let i = 1; i < n - 1; i++) {
    if (d[i - 1] * d[i] <= 0) {
      m[i] = 0;
    } else {
      m[i] = (d[i - 1] + d[i]) / 2;
      const lim = 3 * Math.min(Math.abs(d[i - 1]), Math.abs(d[i]));
      if (Math.abs(m[i]) > lim) m[i] = m[i] > 0 ? lim : -lim;
    }
  }
  let s = '';
  for (let i = 0; i < n - 1; i++) {
    const dx = pts[i + 1].x - pts[i].x;
    const c1x = pts[i].x + dx / 3;
    const c1y = pts[i].y + (m[i] * dx) / 3;
    const c2x = pts[i + 1].x - dx / 3;
    const c2y = pts[i + 1].y - (m[i + 1] * dx) / 3;
    s += ` C ${c1x.toFixed(2)} ${c1y.toFixed(2)},`
       + ` ${c2x.toFixed(2)} ${c2y.toFixed(2)},`
       + ` ${pts[i + 1].x.toFixed(2)} ${pts[i + 1].y.toFixed(2)}`;
  }
  return s;
}

// niceTicks returns ~targetCount round-number tick values from 0 up to
// max, using the standard 1/2/5 × 10^k scheme so steps read as nice
// (1, 2, 5, 10, 20, 50, …) rather than e.g. "1.27, 2.54, …". Used to
// drive the timeline's Y-axis gridlines and labels.
function niceTicks(max, targetCount) {
  if (max <= 0 || targetCount <= 0) return [0];
  const rough = max / targetCount;
  const exp = Math.pow(10, Math.floor(Math.log10(rough)));
  const norm = rough / exp;
  let step;
  if (norm < 1.5) step = 1 * exp;
  else if (norm < 3) step = 2 * exp;
  else if (norm < 7) step = 5 * exp;
  else step = 10 * exp;
  const out = [];
  for (let v = 0; v <= max + step / 2; v += step) out.push(v);
  return out;
}

// bucketSizeLabel names the bucket interval for the timeline title.
// Computed from the gap between two consecutive bucket starts so it
// reflects whatever the backend's autoBucket actually picked, with no
// duplication of its sizing rules. The names match the autoBucket
// candidates (1s/5s/15s/30s/1m/5m/15m/30m/1h/2h/6h/12h/1d/7d/30d);
// "second"/"minute"/"hour"/"day"/"week" are spelled out for the
// common single-unit cases since "Timeline (hits per 1h)" reads
// awkwardly compared to "per hour".
function bucketSizeLabel(buckets) {
  if (!buckets || buckets.length < 2) return 'bucket';
  const ms = new Date(buckets[1].start).getTime() - new Date(buckets[0].start).getTime();
  if (ms <= 0) return 'bucket';
  const s = ms / 1000;
  if (s % (7 * 24 * 3600) === 0) {
    const w = s / (7 * 24 * 3600);
    return w === 1 ? 'week' : `${w}w`;
  }
  if (s % (24 * 3600) === 0) {
    const d = s / (24 * 3600);
    return d === 1 ? 'day' : `${d}d`;
  }
  if (s % 3600 === 0) {
    const h = s / 3600;
    return h === 1 ? 'hour' : `${h}h`;
  }
  if (s % 60 === 0) {
    const m = s / 60;
    return m === 1 ? 'minute' : `${m}m`;
  }
  return s === 1 ? 'second' : `${s}s`;
}

// --- timeline range-change animation ---------------------------------------
// A range change reads as one continuous zoom rather than a hard cut, INCLUDING
// across the moment the new (differently-bucketed) data replaces the old. A pure
// viewport transform can't do that: the two series are different discrete curves,
// so swapping one SVG path for another is a visible jerk no matter how smooth the
// coordinate frame is. Instead we morph the curve *geometry* every frame:
//
//   - the viewport (an animated time window) drives the x mapping;
//   - both the old and new series are resampled — via a monotone-cubic sampler,
//     matching the static render's smoothing — onto a shared dense grid across
//     the current viewport, in a bucket-size-independent unit (per-ms intensity);
//   - the two resampled curves are blended, and normalised by an animated
//     reference intensity, so height transitions smoothly too.
//
// Before the response lands only the old series exists (blend = 0), so the curve
// is exactly the old data zooming. When the new series is drawn we start the
// blend from 0: at that instant the curve is still the old data at the on-screen
// scale (no jump), and over the settle it morphs into the new data. Rapid changes
// snapshot whatever is on screen so the next morph starts from the live curve.
const TL_AXIS_W = 44;       // must match renderTimeline's left Y-axis gutter
const TL_CHART_H = 156;     // bar drawing area height (baseline at y = TL_CHART_H)
const TL_RESCALE_MS = 900;  // horizontal window morph duration
const TL_SETTLE_MS = 700;   // data blend + vertical settle duration
// The currently drawn series as an animatable model (see tlModelFrom): its
// window, per-ms max intensity, a monotone-cubic sampler, and the native path
// strings to restore when the animation ends.
let tlMeta = null;
// Truthy while a range-change render is pending; set by setTimeWindow, consumed
// by renderTimeline to hand the fresh render off to completeTimelineSwap.
let tlTransition = false;
// The live animation, or null when settled. Holds the old + (once known) new
// models, the interpolating viewport window, and the blend clock.
let tlAnim = null;
let tlRAF = 0;              // requestAnimationFrame handle (0 = idle)

function tlEase(t) { return t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2; }

// tlMakeSampler builds a Fritsch–Carlson monotone-cubic interpolant over the
// (t, v) points and returns { at(t) } evaluating it — matching the smoothing the
// static render uses, so resampling a series reproduces its curve. Beyond the
// outermost points it holds the endpoint value flat (the plotted points are
// bucket centres, so this fills the half-bucket to the window edge the way the
// static line reads); emptiness outside the data window is handled by
// tlSampleModel gating on the window, not here.
function tlMakeSampler(pts) {
  const n = pts.length;
  const xs = pts.map(p => p.t), ys = pts.map(p => p.v);
  const m = new Array(n).fill(0);
  if (n >= 2) {
    const d = [];
    for (let i = 0; i < n - 1; i++) d.push((ys[i + 1] - ys[i]) / ((xs[i + 1] - xs[i]) || 1));
    m[0] = d[0]; m[n - 1] = d[n - 2];
    for (let i = 1; i < n - 1; i++) m[i] = d[i - 1] * d[i] <= 0 ? 0 : (d[i - 1] + d[i]) / 2;
    for (let i = 0; i < n - 1; i++) {
      if (d[i] === 0) { m[i] = 0; m[i + 1] = 0; continue; }
      const a = m[i] / d[i], b = m[i + 1] / d[i], s = a * a + b * b;
      if (s > 9) { const tt = 3 / Math.sqrt(s); m[i] = tt * a * d[i]; m[i + 1] = tt * b * d[i]; }
    }
  }
  return {
    at(t) {
      if (n === 0) return 0;
      if (t <= xs[0]) return ys[0];
      if (t >= xs[n - 1]) return ys[n - 1];
      let lo = 0, hi = n - 1;
      while (hi - lo > 1) { const mid = (lo + hi) >> 1; if (xs[mid] <= t) lo = mid; else hi = mid; }
      const h = (xs[hi] - xs[lo]) || 1, u = (t - xs[lo]) / h;
      const u2 = u * u, u3 = u2 * u;
      return (2 * u3 - 3 * u2 + 1) * ys[lo] + (u3 - 2 * u2 + u) * h * m[lo]
           + (-2 * u3 + 3 * u2) * ys[hi] + (u3 - u2) * h * m[hi];
    },
  };
}

// tlSampleModel reads a model's intensity at time t, returning 0 outside its data
// window so an expanding viewport shows empty regions there (rather than the
// sampler's flat-held endpoint value).
function tlSampleModel(mdl, t) {
  return (!mdl || t < mdl.fromMs || t > mdl.toMs) ? 0 : mdl.sampler.at(t);
}

// tlModelFrom captures a drawn series as an animatable model. Values are stored
// as per-ms intensity (value / bucketMs) so old and new series — bucketed at
// different sizes — are directly comparable when blended. maxIntensity is the
// reference the curve normalises against (maxVal / bucketMs).
function tlModelFrom(fromMs, toMs, maxVal, bucketMs, centerPts, lineD, areaD) {
  return {
    fromMs, toMs, bucketMs,
    maxIntensity: bucketMs > 0 ? maxVal / bucketMs : 0,
    sampler: tlMakeSampler(centerPts.map(p => ({ t: p.t, v: bucketMs > 0 ? p.v / bucketMs : 0 }))),
    lineD, areaD,
  };
}

// tlIntensityAt blends the old and new series' intensity at time t by the current
// blend amount (new absent → just old).
function tlIntensityAt(a, t) {
  const oi = tlSampleModel(a.old, t);
  const ni = a.new ? tlSampleModel(a.new, t) : oi;
  return oi + (ni - oi) * a.blendE;
}

// tlDrawCurve rebuilds the line + area paths for the current viewport and blend:
// it resamples the blended intensity across the viewport, normalises by the
// blended reference intensity, and writes fresh path data. Native dots are hidden
// (.tl-morphing) while this runs since they belong to the un-morphed series.
function tlDrawCurve() {
  const a = tlAnim;
  if (!a) return;
  const svg = document.getElementById('timeline-chart');
  const dataG = svg && svg.querySelector('.tl-data');
  const line = dataG && dataG.querySelector('.tl-line');
  const area = dataG && dataG.querySelector('.tl-area');
  if (!line || !area) return;
  dataG.classList.add('tl-morphing');
  const chartW = Math.max(1, (svg.clientWidth || 800) - TL_AXIS_W);
  const chartH = TL_CHART_H, top = chartH - 4;
  const M = Math.max(60, Math.min(220, Math.round(chartW / 6)));
  const refI = a.old.maxIntensity + ((a.new ? a.new.maxIntensity : a.old.maxIntensity) - a.old.maxIntensity) * a.blendE;
  const vf = a.viewFrom, span = (a.viewTo - a.viewFrom) || 1;
  let lineD = '', areaD = '';
  for (let j = 0; j < M; j++) {
    const f = j / (M - 1);
    const x = TL_AXIS_W + f * chartW;
    let frac = refI > 0 ? tlIntensityAt(a, vf + f * span) / refI : 0;
    frac = frac < 0 ? 0 : frac > 1.02 ? 1.02 : frac;
    const xs = x.toFixed(2), ys = (chartH - frac * top).toFixed(2);
    if (j === 0) { lineD = `M ${xs} ${ys}`; areaD = `M ${xs} ${chartH} L ${xs} ${ys}`; }
    else { lineD += ` L ${xs} ${ys}`; areaD += ` L ${xs} ${ys}`; }
  }
  areaD += ` L ${(TL_AXIS_W + chartW).toFixed(2)} ${chartH} Z`;
  line.setAttribute('d', lineD);
  area.setAttribute('d', areaD);
}

// tlSnapshotModel freezes the currently displayed (possibly mid-morph) curve as a
// model, so a new range change begun before the last one settled morphs from
// what's actually on screen rather than snapping back to a prior series.
function tlSnapshotModel(a) {
  const M = 200, vf = a.viewFrom, span = (a.viewTo - a.viewFrom) || 1;
  const refI = a.old.maxIntensity + ((a.new ? a.new.maxIntensity : a.old.maxIntensity) - a.old.maxIntensity) * a.blendE;
  const pts = [];
  for (let j = 0; j < M; j++) { const t = vf + (j / (M - 1)) * span; pts.push({ t, v: tlIntensityAt(a, t) }); }
  return { fromMs: a.viewFrom, toMs: a.viewTo, bucketMs: 1, maxIntensity: refI,
           sampler: tlMakeSampler(pts), lineD: '', areaD: '' };
}

// tlFrame advances the viewport window and the blend clock, redraws the morphing
// curve, and finishes once both are done (restoring the crisp native new paths).
function tlFrame(now) {
  const a = tlAnim;
  if (!a) { tlRAF = 0; return; }
  const hp = a.hDur > 0 ? Math.min(1, (now - a.hT0) / a.hDur) : 1;
  const he = tlEase(hp);
  a.viewFrom = a.hFrom0 + (a.hFromT - a.hFrom0) * he;
  a.viewTo = a.hTo0 + (a.hToT - a.hTo0) * he;
  const bp = a.new ? (a.bDur > 0 ? Math.min(1, (now - a.bT0) / a.bDur) : 1) : 0;
  a.blendE = tlEase(bp);
  tlDrawCurve();
  if (hp >= 1 && a.new && bp >= 1) finishTlAnim();
  else if (hp >= 1 && !a.new) tlRAF = 0;     // fully zoomed, paused until data lands
  else tlRAF = requestAnimationFrame(tlFrame);
}

// finishTlAnim restores the new series' crisp native paths (the morph draws a
// resampled approximation) and re-shows its dots.
function finishTlAnim() {
  const a = tlAnim;
  const svg = document.getElementById('timeline-chart');
  const dataG = svg && svg.querySelector('.tl-data');
  if (dataG && a && a.new) {
    const line = dataG.querySelector('.tl-line'), area = dataG.querySelector('.tl-area');
    if (line) line.setAttribute('d', a.new.lineD);
    if (area) area.setAttribute('d', a.new.areaD);
    dataG.classList.remove('tl-morphing');
  }
  tlAnim = null;
  tlRAF = 0;
}

// cancelTlAnim drops any in-flight morph without touching the DOM — used when a
// plain (non-range) render is about to wipe and redraw the chart authoritatively.
function cancelTlAnim() {
  if (tlRAF) { cancelAnimationFrame(tlRAF); tlRAF = 0; }
  tlAnim = null;
}

// setTimeWindow changes the timeline's [from,to] (RFC3339 strings or null; null
// from = dataset start, null to = now) and starts the zoom, then refreshes.
function setTimeWindow(fromISO, toISO) {
  const newFromMs = fromISO ? Date.parse(fromISO)
    : (state.globalFirst ? Date.parse(state.globalFirst)
       : (tlMeta ? tlMeta.fromMs : Date.now() - 7 * 86400000));
  const newToMs = toISO ? Date.parse(toISO) : Date.now();
  tlTransition = true;
  beginTimelineTransition(newFromMs, newToMs);
  state.filter.time_from = fromISO;
  state.filter.time_to = toISO;
  state.defaultRange = false;
  refreshAll();
}

// beginTimelineTransition starts (or, mid-morph, retargets) the viewport zoom
// toward the new window, keeping the old series as the blend source. If a morph
// is already running the on-screen curve is snapshotted first, so the new zoom
// continues seamlessly from it.
function beginTimelineTransition(newFromMs, newToMs) {
  if (!tlMeta || newToMs - newFromMs <= 0) return;
  const now = performance.now();
  if (tlAnim) {
    tlAnim.old = tlSnapshotModel(tlAnim);
    tlAnim.new = null;
    tlAnim.hFrom0 = tlAnim.viewFrom; tlAnim.hTo0 = tlAnim.viewTo;
    tlAnim.hFromT = newFromMs; tlAnim.hToT = newToMs;
    tlAnim.hT0 = now; tlAnim.hDur = TL_RESCALE_MS;
    tlAnim.bT0 = now; tlAnim.bDur = 0; tlAnim.blendE = 0;
  } else {
    tlAnim = {
      old: tlMeta, new: null,
      hFrom0: tlMeta.fromMs, hTo0: tlMeta.toMs, hFromT: newFromMs, hToT: newToMs,
      hT0: now, hDur: TL_RESCALE_MS,
      bT0: now, bDur: 0, blendE: 0,
      viewFrom: tlMeta.fromMs, viewTo: tlMeta.toMs,
    };
  }
  if (!tlRAF) tlRAF = requestAnimationFrame(tlFrame);
  tlDrawCurve();
}

// completeTimelineSwap runs once the new series is drawn (as tlMeta): it adds it
// as the blend target and starts the blend from 0 — so the curve stays exactly
// as it is this frame (still the old data at the on-screen scale) and morphs into
// the new data — while the viewport finishes converging on the real data window.
function completeTimelineSwap() {
  if (!tlAnim) return; // first-ever data: nothing to morph from, static stands
  const now = performance.now();
  const nat = tlMeta;
  const remaining = Math.max(TL_SETTLE_MS, tlAnim.hDur - (now - tlAnim.hT0));
  tlAnim.hFrom0 = tlAnim.viewFrom; tlAnim.hTo0 = tlAnim.viewTo;
  tlAnim.hFromT = nat.fromMs; tlAnim.hToT = nat.toMs;
  tlAnim.hT0 = now; tlAnim.hDur = remaining;
  tlAnim.new = nat;
  tlAnim.bT0 = now; tlAnim.bDur = TL_SETTLE_MS; tlAnim.blendE = 0;
  if (!tlRAF) tlRAF = requestAnimationFrame(tlFrame);
  tlDrawCurve();
}

function renderTimeline(buckets, overlays) {
  const svg = document.getElementById('timeline-chart');
  // A range change routes through setTimeWindow, which sets tlTransition and
  // starts the viewport zoom; this render then hands off to completeTimelineSwap
  // below to keep it continuous. Any other render (sort/view toggle, pin
  // overlay fold-in, empty result) is authoritative and static, so it cancels
  // whatever zoom may be running and draws at rest.
  const transition = tlTransition;
  tlTransition = null;
  if (!transition) cancelTlAnim();
  const w = svg.clientWidth || 800;
  const h = 180;           // total svg height
  const chartH = TL_CHART_H; // bar drawing area (top); baseline at y = chartH
  const axisH = 24;        // axis strip (bottom 24px for ticks + labels)
  svg.setAttribute('viewBox', `0 0 ${w} ${h}`);
  svg.innerHTML = '';
  if (!buckets || buckets.length === 0) {
    tlMeta = null;
    cancelTlAnim(); // nothing to animate onto
    return;
  }
  // Bar height tracks whichever metric the global hits/data toggle is
  // sorting on, so the timeline visualization stays in sync with the
  // panels' primary column. Tooltip carries both regardless.
  const useBytes = state.sortBy === 'bytes';
  const valueOf = b => useBytes ? b.bytes : b.hits;
  const fmtVal = useBytes ? fmtBytes : fmtInt;
  const valueLabel = useBytes ? 'bytes' : 'hits';

  // Overlay alignment is keyed by bucket start time, not array index,
  // so a small off-by-one between any overlay's bucket boundaries and
  // the filtered series can't shift it relative to the main curve.
  // Buckets missing from an overlay's map (e.g. the overlay's range
  // doesn't extend that far) render as zero. Each entry carries its
  // own indexed lookup so every overlay's value can be read at any
  // filtered bucket position cheaply.
  const overlayMaps = (overlays || []).map(o => ({
    color: o.color,
    label: o.label,
    byStart: Object.fromEntries((o.buckets || []).map(b => [b.start, b])),
  }));
  const overlayValueAt = (om, i) => {
    const b = om.byStart[buckets[i].start];
    return b ? valueOf(b) : 0;
  };
  const filteredMax = Math.max(0, ...buckets.map(valueOf));
  const overlayMaxes = overlayMaps.map(
    om => Math.max(0, ...buckets.map((_, i) => overlayValueAt(om, i)))
  );
  // Scale to max across filtered + every overlay so proportions stay
  // honest — a small-slice filter overlaid on a large pin SHOULD
  // render small, since the comparison we want to convey is "this
  // slice vs that slice", not "both fill the chart".
  const maxVal = Math.max(filteredMax, ...overlayMaxes);
  const titleEl = document.getElementById('timeline-title-text');
  if (titleEl) {
    const unit = bucketSizeLabel(buckets);
    titleEl.textContent = useBytes
      ? `Timeline (data per ${unit})`
      : `Timeline (hits per ${unit})`;
  }
  // AXIS_W reserves a left margin for Y-axis labels. Everything that
  // positions in the chart area offsets by it; the brush handler at
  // the bottom maps client-x back to bucket index using the same
  // offset so a click in the label gutter clamps to bucket 0 instead
  // of selecting nothing. 44px fits worst-case SI labels like "999 KB"
  // and "1.5 MB" with a couple px of breathing room.
  const AXIS_W = TL_AXIS_W;
  const chartW = Math.max(1, w - AXIS_W);
  const barW = chartW / buckets.length;
  const ns = 'http://www.w3.org/2000/svg';
  const xc = i => AXIS_W + i * barW + barW / 2;
  const yFor = b => chartH - (maxVal > 0 ? (valueOf(b) / maxVal) * (chartH - 4) : 0);

  // The data-bearing shapes (overlays + area/line/dots) live inside a
  // <g class="tl-data"> nested in a clip-wrapper. Transition transforms are
  // applied to tl-data; the wrapper carries the clip so an expanding curve is
  // cropped to the chart (never spilling over the Y-axis gutter or the edges)
  // while its own transform is free to move it. Everything else (gridlines,
  // boundaries, axis, ticks, hit-rects) is drawn straight onto the svg and
  // snaps to the new geometry.
  const clip = document.createElementNS(ns, 'clipPath');
  clip.setAttribute('id', 'tl-clip');
  const clipRect = document.createElementNS(ns, 'rect');
  clipRect.setAttribute('x', AXIS_W); clipRect.setAttribute('y', 0);
  clipRect.setAttribute('width', chartW.toFixed(2)); clipRect.setAttribute('height', chartH);
  clip.appendChild(clipRect);
  const clipWrap = document.createElementNS(ns, 'g');
  clipWrap.setAttribute('class', 'tl-clipwrap');
  clipWrap.setAttribute('clip-path', 'url(#tl-clip)');
  const dataG = document.createElementNS(ns, 'g');
  dataG.setAttribute('class', 'tl-data');
  clipWrap.appendChild(dataG);

  // Y-axis: nice round-number gridlines + labels. Drawn first so data
  // overlays them. The 0 line is omitted here because the X-axis
  // baseline drawn later already serves that role; without skipping
  // we'd paint two lines on top of each other. maxVal=0 (empty filter
  // range) skips ticks entirely — a single "0" label adds nothing.
  if (maxVal > 0) {
    const yToPx = v => chartH - (v / maxVal) * (chartH - 4);
    for (const t of niceTicks(maxVal, 4)) {
      const ty = yToPx(t);
      if (t > 0) {
        const grid = document.createElementNS(ns, 'line');
        grid.setAttribute('class', 'tl-grid');
        grid.setAttribute('x1', AXIS_W); grid.setAttribute('x2', w);
        grid.setAttribute('y1', ty.toFixed(2)); grid.setAttribute('y2', ty.toFixed(2));
        svg.appendChild(grid);
      }
      const lbl = document.createElementNS(ns, 'text');
      lbl.setAttribute('class', 'tl-yaxis-label');
      lbl.setAttribute('x', AXIS_W - 4);
      lbl.setAttribute('y', (ty + 3).toFixed(2));
      lbl.setAttribute('text-anchor', 'end');
      lbl.textContent = fmtVal(t);
      svg.appendChild(lbl);
    }
  }

  // Insert the clip + data layer above the gridlines but below the boundary
  // dividers / axis / hit-rects that follow, preserving the original z-order.
  svg.appendChild(clip);
  svg.appendChild(clipWrap);

  // Visualization is a smoothed filled area + line + dot markers
  // tracing the chosen metric. Smoothing uses Fritsch-Carlson monotone
  // cubic interpolation so spikes don't overshoot the baseline, and
  // the area shape makes empty intervals legible — a flat baseline
  // section is visibly "no data here", whereas a bars row was just
  // absent.

  // Pin overlays — drawn first so the filtered series sits on top.
  // Same x positions as filtered so shapes line up; each overlay's
  // color comes from the pin and is set inline (CSS handles only
  // opacity + pointer-events).
  for (const om of overlayMaps) {
    const yForOverlay = i => chartH - (maxVal > 0 ? (overlayValueAt(om, i) / maxVal) * (chartH - 4) : 0);
    const opts = buckets.map((b, i) => ({ x: xc(i), y: yForOverlay(i) }));
    const ocurves = monotoneCubicCurves(opts);
    const oAreaD = `M ${opts[0].x.toFixed(2)} ${chartH}`
                 + ` L ${opts[0].x.toFixed(2)} ${opts[0].y.toFixed(2)}`
                 + ocurves
                 + ` L ${opts[opts.length - 1].x.toFixed(2)} ${chartH} Z`;
    const oArea = document.createElementNS(ns, 'path');
    oArea.setAttribute('class', 'tl-area-overlay');
    oArea.setAttribute('style', `fill: ${om.color}`);
    oArea.setAttribute('d', oAreaD);
    dataG.appendChild(oArea);
    const oLineD = `M ${opts[0].x.toFixed(2)} ${opts[0].y.toFixed(2)}` + ocurves;
    const oLine = document.createElementNS(ns, 'path');
    oLine.setAttribute('class', 'tl-line-overlay');
    oLine.setAttribute('style', `stroke: ${om.color}`);
    oLine.setAttribute('d', oLineD);
    dataG.appendChild(oLine);
  }

  const pts = buckets.map((b, i) => ({ x: xc(i), y: yFor(b) }));
  const curves = monotoneCubicCurves(pts);

  // Area path: anchor at first point's x on the baseline, line up to
  // the first data point, follow the curves, drop to baseline at the
  // last point. Anchoring to first/last data x (not chart edges)
  // avoids artificial ramps from edge to first bucket center.
  const areaD = `M ${pts[0].x.toFixed(2)} ${chartH}`
              + ` L ${pts[0].x.toFixed(2)} ${pts[0].y.toFixed(2)}`
              + curves
              + ` L ${pts[pts.length - 1].x.toFixed(2)} ${chartH} Z`;
  const area = document.createElementNS(ns, 'path');
  area.setAttribute('class', 'tl-area');
  area.setAttribute('d', areaD);
  dataG.appendChild(area);

  // Line path: just the smoothed trace, no fill.
  const lineD = `M ${pts[0].x.toFixed(2)} ${pts[0].y.toFixed(2)}` + curves;
  const line = document.createElementNS(ns, 'path');
  line.setAttribute('class', 'tl-line');
  line.setAttribute('d', lineD);
  dataG.appendChild(line);

  // Dot markers — only when buckets are spaced widely enough that the
  // dots read as distinct points (with r=2, anything below ~5px barW
  // makes them visually merge). Bucket count alone is the wrong gate:
  // alignment overhead can push e.g. a 30d view from 60 to 61 buckets
  // and silently drop the dots. Empty buckets get no dot so the
  // baseline isn't littered with markers that aren't real data.
  if (barW >= 5) {
    buckets.forEach((b, i) => {
      if (valueOf(b) === 0) return;
      const c = document.createElementNS(ns, 'circle');
      c.setAttribute('class', 'tl-dot');
      c.setAttribute('cx', pts[i].x.toFixed(2));
      c.setAttribute('cy', pts[i].y.toFixed(2));
      c.setAttribute('r', 2);
      dataG.appendChild(c);
    });
  }

  const spanMs = (new Date(buckets[buckets.length - 1].start) - new Date(buckets[0].start)) || 1;

  // Boundary markers — three nested layers of decreasing prominence so
  // the eye can find the calendar structure inside the data:
  //   Year:  full-height solid divider, always shown (rare even on
  //          decade-scale views)
  //   Month: full-height dashed divider, faint; gated at < 3y so a
  //          long view doesn't get 100+ dashed lines
  //   Day:   small axis tick, gated at < 30d (else 365 ticks spam)
  // Each boundary contributes at most one marker — Jan 1 is a year
  // boundary, not also a month one. Drawn between bars and axis so
  // dividers overlay data but the baseline still anchors the bottom.
  // Boundaries respect state.timeMode so a year/month/day flip lines up
  // with what the labels are showing.
  const utcMode = inUTC();
  const yrOf = d => utcMode ? d.getUTCFullYear() : d.getFullYear();
  const moOf = d => utcMode ? d.getUTCMonth()    : d.getMonth();
  const daOf = d => utcMode ? d.getUTCDate()     : d.getDate();
  const showMonthDiv = spanMs < 3 * 365 * 24 * 60 * 60 * 1000;
  const showDayTick  = spanMs < 30 * 24 * 60 * 60 * 1000;
  const MONTH_NAMES = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  for (let i = 1; i < buckets.length; i++) {
    const prev = new Date(buckets[i - 1].start);
    const cur  = new Date(buckets[i].start);
    const yearChange  = yrOf(prev) !== yrOf(cur);
    const monthChange = !yearChange  && moOf(prev) !== moOf(cur);
    const dayChange   = !yearChange  && !monthChange && daOf(prev) !== daOf(cur);
    const dx = AXIS_W + i * barW;
    if (yearChange) {
      const line = document.createElementNS(ns, 'line');
      line.setAttribute('class', 'tl-yr-div');
      line.setAttribute('x1', dx.toFixed(2)); line.setAttribute('x2', dx.toFixed(2));
      line.setAttribute('y1', 0);             line.setAttribute('y2', chartH);
      const lt = document.createElementNS(ns, 'title');
      lt.textContent = `${yrOf(cur)} starts`;
      line.appendChild(lt);
      svg.appendChild(line);
    } else if (monthChange && showMonthDiv) {
      const line = document.createElementNS(ns, 'line');
      line.setAttribute('class', 'tl-mo-div');
      line.setAttribute('x1', dx.toFixed(2)); line.setAttribute('x2', dx.toFixed(2));
      line.setAttribute('y1', 0);             line.setAttribute('y2', chartH);
      const lt = document.createElementNS(ns, 'title');
      lt.textContent = `${MONTH_NAMES[moOf(cur)]} ${yrOf(cur)} starts`;
      line.appendChild(lt);
      svg.appendChild(line);
    } else if (dayChange && showDayTick) {
      const dt = document.createElementNS(ns, 'line');
      dt.setAttribute('class', 'tl-day-tick');
      dt.setAttribute('x1', dx.toFixed(2)); dt.setAttribute('x2', dx.toFixed(2));
      dt.setAttribute('y1', chartH);        dt.setAttribute('y2', chartH + 6);
      svg.appendChild(dt);
    }
  }

  // Axis baseline + date ticks. Baseline starts at AXIS_W so it doesn't
  // run under the Y-axis label gutter.
  const axis = document.createElementNS(ns, 'line');
  axis.setAttribute('class', 'tl-axis');
  axis.setAttribute('x1', AXIS_W); axis.setAttribute('x2', w);
  axis.setAttribute('y1', chartH); axis.setAttribute('y2', chartH);
  svg.appendChild(axis);

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
    const bx = xc(i);
    const tick = document.createElementNS(ns, 'line');
    tick.setAttribute('class', 'tl-tick');
    tick.setAttribute('x1', bx); tick.setAttribute('x2', bx);
    tick.setAttribute('y1', chartH); tick.setAttribute('y2', chartH + 4);
    svg.appendChild(tick);
    const label = document.createElementNS(ns, 'text');
    label.setAttribute('class', 'tl-label');
    // Keep first/last labels inside the chart area so they aren't clipped
    // and don't run into the Y-axis gutter on the left.
    let anchor = 'middle';
    if (k === 0) anchor = 'start';
    else if (k === indices.length - 1) anchor = 'end';
    label.setAttribute('text-anchor', anchor);
    const lx = anchor === 'start' ? AXIS_W + 2 : anchor === 'end' ? w - 2 : bx;
    label.setAttribute('x', lx);
    label.setAttribute('y', chartH + 15);
    label.textContent = fmt(new Date(buckets[i].start));
    svg.appendChild(label);
  });

  // Per-bucket transparent hit rects for tooltips + column highlight on
  // hover. Drawn last so they sit on top of every visual layer; the
  // area/line/dots have pointer-events: none in CSS so the cursor
  // reaches the rect underneath. The rects are full chart-height so the
  // bucket "owns" its column, not just the area below the line.
  buckets.forEach((b, i) => {
    const x = AXIS_W + i * barW;
    const rect = document.createElementNS(ns, 'rect');
    rect.setAttribute('class', 'tl-hit');
    rect.setAttribute('x', x.toFixed(2));
    rect.setAttribute('y', 0);
    rect.setAttribute('width', barW.toFixed(2));
    rect.setAttribute('height', chartH);
    const t = document.createElementNS(ns, 'title');
    let tip = `${fmtTs(b.start)}\n  ● ${fmtVal(valueOf(b))} ${valueLabel} (current)`;
    for (const om of overlayMaps) {
      tip += `\n  ● ${fmtVal(overlayValueAt(om, i))} ${valueLabel} — ${om.label}`;
    }
    tip += `\n  (current: ${fmtInt(b.hits)} hits, ${fmtBytes(b.bytes)}, ${fmtInt(b.visitors)} visitors)`;
    t.textContent = tip;
    rect.appendChild(t);
    svg.appendChild(rect);
  });

  // Brush overlay for range selection. Once the mousedown fires we install
  // mousemove/mouseup listeners on the document so the drag follows the
  // cursor even when it leaves the SVG (which matters when the user wants
  // to include the last, rightmost bucket). We clamp to SVG bounds so a
  // drag past the right edge still commits "up to the most recent bucket".
  const toBucketIdx = (clientX) => {
    const r = svg.getBoundingClientRect();
    // Strip the Y-axis label gutter (left AXIS_W px) before mapping to a
    // bucket. r.width already matches viewBox w 1:1 since we set
    // viewBox from clientWidth on render. A click in the gutter clamps
    // to bucket 0 via the Math.max below.
    const chartPx = Math.max(1, r.width - AXIS_W);
    const x = clientX - r.left - AXIS_W;
    return Math.max(0, Math.min(buckets.length - 1, Math.floor((x / chartPx) * buckets.length)));
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
      brushEl.setAttribute('x', (AXIS_W + lo * barW).toFixed(2));
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
      setTimeWindow(bucketStart, bucketEnd);
    };
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  };

  // Capture this render as an animatable model so a range change can morph
  // from/into it. Points are the bucket centres (matching where the curve is
  // plotted); the right window edge is one bucket past the last start (buckets
  // are dense and edge-to-edge across [from, to)).
  const bucketMs = buckets.length > 1
    ? (new Date(buckets[1].start) - new Date(buckets[0].start))
    : Math.max(1, spanMs);
  const firstMs = new Date(buckets[0].start).getTime();
  const centerPts = buckets.map((b, i) => ({ t: firstMs + i * bucketMs + bucketMs / 2, v: valueOf(b) }));
  tlMeta = tlModelFrom(firstMs, firstMs + buckets.length * bucketMs, maxVal, bucketMs, centerPts, lineD, areaD);

  // Range-change render: the new series is in the DOM at its native scale. Hand
  // off to the morph, which starts blending it in from the on-screen curve so
  // there is no jerk when the old data is replaced by the new.
  if (transition) completeTimelineSwap();
}

// HTTP status reason phrases for the status-code panel tooltip. Covers
// every code the store currently surfaces in the real-traffic sets;
// unknown codes fall through to just the numeric value.
const HTTP_STATUS_NAMES = {
  '100': 'Continue', '101': 'Switching Protocols', '102': 'Processing', '103': 'Early Hints',
  '200': 'OK', '201': 'Created', '202': 'Accepted', '203': 'Non-Authoritative Information',
  '204': 'No Content', '205': 'Reset Content', '206': 'Partial Content', '207': 'Multi-Status',
  '208': 'Already Reported', '226': 'IM Used',
  '300': 'Multiple Choices', '301': 'Moved Permanently', '302': 'Found', '303': 'See Other',
  '304': 'Not Modified', '305': 'Use Proxy', '307': 'Temporary Redirect', '308': 'Permanent Redirect',
  '400': 'Bad Request', '401': 'Unauthorized', '402': 'Payment Required', '403': 'Forbidden',
  '404': 'Not Found', '405': 'Method Not Allowed', '406': 'Not Acceptable',
  '407': 'Proxy Authentication Required', '408': 'Request Timeout', '409': 'Conflict',
  '410': 'Gone', '411': 'Length Required', '412': 'Precondition Failed', '413': 'Payload Too Large',
  '414': 'URI Too Long', '415': 'Unsupported Media Type', '416': 'Range Not Satisfiable',
  '417': 'Expectation Failed', '418': "I'm a teapot", '421': 'Misdirected Request',
  '422': 'Unprocessable Entity', '423': 'Locked', '424': 'Failed Dependency', '425': 'Too Early',
  '426': 'Upgrade Required', '428': 'Precondition Required', '429': 'Too Many Requests',
  '431': 'Request Header Fields Too Large', '451': 'Unavailable For Legal Reasons',
  '500': 'Internal Server Error', '501': 'Not Implemented', '502': 'Bad Gateway',
  '503': 'Service Unavailable', '504': 'Gateway Timeout', '505': 'HTTP Version Not Supported',
  '506': 'Variant Also Negotiates', '507': 'Insufficient Storage', '508': 'Loop Detected',
  '510': 'Not Extended', '511': 'Network Authentication Required',
};

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
  { name: 'status', title: 'Status codes', dim: 'status' },
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
// The classifier panels are client-rendered from the /api/tags data
// (source/reason/score live in the tag set, not the request rows), so
// they carry a `client` flag and `tagType` selecting which tags belong
// on this view. The "classifiers" panel is a source/score-bucket
// breakdown that scopes the "reasons" panel when a row is clicked.
const CLASSIFIERS_PANEL_BOTS = { name: 'classifiers', title: 'Classifiers', client: true, tagType: 'bot' };
const CLASSIFIERS_PANEL_MALICIOUS = { name: 'classifiers', title: 'Classifiers', client: true, tagType: 'malicious' };
const REASONS_PANEL_BOTS = { name: 'reasons', title: 'Classifier flags', client: true, tagType: 'bot' };
const REASONS_PANEL_MALICIOUS = { name: 'reasons', title: 'Classifier flags', client: true, tagType: 'malicious' };

function currentPanelDefs() {
  if (state.view === 'malicious') return [CLASSIFIERS_PANEL_MALICIOUS, REASONS_PANEL_MALICIOUS, ...MALICIOUS_PANELS];
  if (state.view === 'bots') return [CLASSIFIERS_PANEL_BOTS, REASONS_PANEL_BOTS, ...DYNAMIC_PANELS];
  // 'all' and the real/local/static views share the generic breakdown set;
  // the top class-composition bar supplies the cross-class split for 'all'.
  return DYNAMIC_PANELS;
}

// renderAllNeedsFilter replaces the panels with a prompt when the All view is
// selected without a filter, and clears the stale overview/timeline/rows so no
// leftover numbers from the previous view look like "all" results.
function renderAllNeedsFilter() {
  renderOverview({});
  renderStatusClass({});
  renderTimeline([], null);
  renderRows([], false);
  const container = document.getElementById('panels');
  container.innerHTML =
    `<div class="all-needs-filter">
       <strong>The All view spans every class</strong> — real, static, bots, local, and malicious.
       <p>Add at least one filter (an IP, host, URL, status, …) to use it. Click a value in any
       panel or the raw-requests list, or use a panel's filter box. The current filters then apply
       across every class instead of just one.</p>
       <p class="muted">A filter is required so the view stays fast: without one it would scan
       every request in every pool.</p>
     </div>`;
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
    if (def.client) {
      container.appendChild(def.name === 'classifiers'
        ? renderClassifiersPanel(def)
        : renderReasonsPanel(def));
      return;
    }
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
    // Panel-filter input does exact-include for IP (drill-down) and
    // substring-contains for every other dimension, mirroring the old
    // top-bar inputs but per-panel. Chips still render in the filter bar.
    const pfPlaceholder = `filter ${def.dim}…`;
    const pfTitle = def.dim === 'ip'
      ? 'Type an IP and hit Enter to filter'
      : `Type a substring and hit Enter to filter by ${def.dim}`;
    sec.innerHTML = `
      <div class="panel-title">
        <span><span>${escapeHTML(def.title)}</span> <span class="muted panel-count">${initialRows.length}</span></span>
        <input type="text" class="panel-filter" placeholder="${escapeHTML(pfPlaceholder)}" autocomplete="off" spellcheck="false" title="${escapeHTML(pfTitle)}">
      </div>
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
    const pfInput = sec.querySelector('.panel-filter');
    pfInput.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter') return;
      const v = pfInput.value.trim();
      if (!v) return;
      if (def.dim === 'ip') addFilter(def.dim, v, false);
      else addContainsFilter(def.dim, v);
      pfInput.value = '';
    });
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
    const keyTitle = def.dim === 'status' && HTTP_STATUS_NAMES[val]
      ? `${val} ${HTTP_STATUS_NAMES[val]}`
      : val;
    tr.innerHTML = `
      <td class="key-cell" title="${escapeHTML(keyTitle)}">${escapeHTML(val)}</td>
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

// --- Classifier-flags ("reasons") panel ---------------------------------
// Client-rendered from latestTags because the score/reason lives in the
// tag set, not the request rows. Lists the IPs the classifiers flagged
// for the current pool, the numeric score parsed out of the reason, and
// the full reason text, sorted by score descending.

// flagsScope, when set, narrows the "Classifier flags" panel to one
// classifier source or score threshold. Set by clicking a row in the
// "Classifiers" breakdown panel; toggled off by clicking it again. Kept
// as a module var (not URL state) — it's an ephemeral drill-down. tagType
// records the pool it was set under so it doesn't leak across views.
let flagsScope = null;

// flagsSortDir controls the score sort on the "Classifier flags" panel.
// Toggled by clicking the score column header. Ascending + a score
// bucket (e.g. "score >100") surfaces the lowest-scoring flags.
let flagsSortDir = 'desc';

// Cumulative score thresholds for the "Classifiers" breakdown buckets.
// Each row counts score-flagged IPs whose score exceeds the threshold;
// clicking one scopes the flags panel to that "score > X" set.
const SCORE_THRESHOLDS = [
  { min: 1000000, label: 'score >1M' },
  { min: 100000, label: 'score >100k' },
  { min: 10000, label: 'score >10k' },
  { min: 1000, label: 'score >1k' },
  { min: 100, label: 'score >100' },
];

// parseScore pulls the leading integer out of a "score 1306: ..." reason.
// Returns null when the reason isn't score-shaped (e.g. another rule).
function parseScore(reason) {
  const m = /score\s+(-?\d+)/i.exec(reason || '');
  return m ? parseInt(m[1], 10) : null;
}

// matchScope reports whether a flags row satisfies the active scope.
function matchScope(r, scope) {
  if (!scope) return true;
  if (scope.type === 'source') return r.source === scope.value;
  if (scope.type === 'minscore') return r.score != null && r.score > scope.min;
  return true;
}

// reasonRowsForView selects the tags belonging to this panel's pool
// (bot vs malicious), annotates each with a parsed score, applies the
// active scope, and sorts highest-score first (scoreless tags sink to
// the bottom by recency).
function reasonRowsForView(tagType) {
  const scope = (flagsScope && flagsScope.tagType === tagType) ? flagsScope : null;
  const rows = latestTags
    .filter(t => t.tag === tagType && (t.reason || t.source))
    .map(t => ({ ip: t.ip, source: t.source || 'manual', reason: t.reason || '', score: parseScore(t.reason), at: t.at || 0 }))
    .filter(r => matchScope(r, scope));
  const dir = flagsSortDir === 'asc' ? 1 : -1;
  rows.sort((a, b) => {
    // Scoreless rows always sink to the bottom regardless of direction.
    const an = a.score == null, bn = b.score == null;
    if (an !== bn) return an ? 1 : -1;
    if (an && bn) return b.at - a.at;
    if (a.score !== b.score) return dir * (a.score - b.score);
    return b.at - a.at;
  });
  return rows;
}

function renderReasonsPanel(def) {
  const sec = document.createElement('section');
  sec.className = 'panel';
  sec.dataset.panel = def.name;
  sec.innerHTML = `
    <div class="panel-title">
      <span><span>${escapeHTML(def.title)}</span> <span class="muted panel-count">0</span></span>
      <input type="text" class="panel-filter" placeholder="filter ip…" autocomplete="off" spellcheck="false" title="Type an IP and hit Enter to filter">
    </div>
    <table class="panel-table" data-panel="${def.name}">
      <thead><tr>
        <th data-col="key">ip<span class="col-resize"></span></th>
        <th data-col="score" class="right sortable" title="click to reverse sort"><span class="sort-label">score</span><span class="col-resize"></span></th>
        <th data-col="reason">reason</th>
      </tr></thead>
      <tbody></tbody>
    </table>
    <div class="panel-footer">
      <span class="panel-status">showing 0</span>
      <button class="btn panel-more" type="button">show more</button>
    </div>
  `;
  const pfInput = sec.querySelector('.panel-filter');
  pfInput.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter') return;
    const v = pfInput.value.trim();
    if (v) addFilter('ip', v, false);
    pfInput.value = '';
  });
  sec._pg = { def, limit: state.topN };
  sec.querySelector('.panel-more').addEventListener('click', () => {
    sec._pg.limit += PANEL_PAGE_SIZE;
    fillReasonsPanel(sec);
  });
  sec.querySelector('th[data-col="score"]').addEventListener('click', (e) => {
    if (e.target.closest('.col-resize')) return;
    flagsSortDir = flagsSortDir === 'asc' ? 'desc' : 'asc';
    refreshTagPanels();
  });
  fillReasonsPanel(sec);
  installColumnResize(sec.querySelector('table.panel-table'));
  restoreColumnWidths(sec.querySelector('table.panel-table'), def.name);
  return sec;
}

function fillReasonsPanel(sec) {
  const def = sec._pg.def;
  const tbody = sec.querySelector('tbody');
  const lbl = sec.querySelector('.sort-label');
  if (lbl) lbl.textContent = 'score ' + (flagsSortDir === 'asc' ? '▲' : '▼');
  const all = reasonRowsForView(def.tagType);
  const shown = all.slice(0, sec._pg.limit);
  tbody.innerHTML = '';
  if (all.length === 0) {
    tbody.innerHTML = `<tr><td colspan="3" class="panel-empty">no flagged IPs</td></tr>`;
  } else {
    shown.forEach(r => {
      const tr = document.createElement('tr');
      tr.dataset.val = r.ip;
      tr.setAttribute('title', 'click to filter, right-click to tag');
      const scoreTxt = r.score == null ? '—' : fmtInt(r.score);
      tr.innerHTML = `
        <td class="key-cell" title="${escapeHTML(r.ip)}">${escapeHTML(r.ip)}</td>
        <td class="right score-cell" title="${escapeHTML(r.reason)}">${escapeHTML(scoreTxt)}</td>
        <td class="reason-cell" title="${escapeHTML('source: ' + r.source)}">${escapeHTML(r.reason || r.source)}</td>`;
      tr.addEventListener('click', (e) => {
        if (e.target.closest('.col-resize')) return;
        addFilter('ip', r.ip, e.shiftKey);
      });
      tr.addEventListener('contextmenu', (e) => {
        e.preventDefault();
        openTagMenu(r.ip, e.clientX, e.clientY);
      });
      tbody.appendChild(tr);
    });
  }
  sec.querySelector('.panel-count').textContent = all.length;
  const exhausted = shown.length >= all.length;
  const scope = (flagsScope && flagsScope.tagType === def.tagType) ? flagsScope : null;
  const scopeNote = scope ? ` · ${scope.label} (click again to clear)` : '';
  sec.querySelector('.panel-status').textContent =
    `showing ${shown.length}` + (exhausted ? ' (all)' : ` of ${all.length}`) + scopeNote;
  const btn = sec.querySelector('.panel-more');
  btn.disabled = exhausted;
  btn.textContent = exhausted ? 'no more' : `show ${PANEL_PAGE_SIZE} more`;
}

// --- Classifiers breakdown panel ----------------------------------------
// A source/score-bucket count for the current pool, built from latestTags.
// Clicking a row scopes the "Classifier flags" panel; clicking the active
// row clears the scope.

// classifierBreakdown returns the per-source counts and cumulative
// score-bucket counts for one pool (bot vs malicious).
function classifierBreakdown(tagType) {
  const tags = latestTags.filter(t => t.tag === tagType);
  const bySource = {};
  for (const t of tags) {
    const s = t.source || 'manual';
    bySource[s] = (bySource[s] || 0) + 1;
  }
  const sources = Object.entries(bySource)
    .map(([source, count]) => ({ source, count }))
    .sort((a, b) => b.count - a.count);
  const scores = tags.map(t => parseScore(t.reason)).filter(s => s != null);
  const buckets = SCORE_THRESHOLDS
    .map(t => ({ min: t.min, label: t.label, count: scores.filter(s => s > t.min).length }))
    .filter(b => b.count > 0);
  return { sources, buckets };
}

function renderClassifiersPanel(def) {
  const sec = document.createElement('section');
  sec.className = 'panel';
  sec.dataset.panel = def.name;
  sec.innerHTML = `
    <div class="panel-title">
      <span><span>${escapeHTML(def.title)}</span> <span class="muted panel-count">0</span></span>
    </div>
    <table class="panel-table" data-panel="${def.name}">
      <thead><tr>
        <th data-col="key">classifier<span class="col-resize"></span></th>
        <th data-col="primary" class="right">flagged<span class="col-resize"></span></th>
        <th data-col="bar"></th>
      </tr></thead>
      <tbody></tbody>
    </table>
  `;
  sec._pg = { def };
  fillClassifiersPanel(sec);
  installColumnResize(sec.querySelector('table.panel-table'));
  restoreColumnWidths(sec.querySelector('table.panel-table'), def.name);
  return sec;
}

function fillClassifiersPanel(sec) {
  const def = sec._pg.def;
  const tbody = sec.querySelector('tbody');
  const { sources, buckets } = classifierBreakdown(def.tagType);
  const scope = (flagsScope && flagsScope.tagType === def.tagType) ? flagsScope : null;
  const maxCount = Math.max(1, ...sources.map(s => s.count), ...buckets.map(b => b.count));
  tbody.innerHTML = '';
  const total = sources.reduce((a, s) => a + s.count, 0);
  sec.querySelector('.panel-count').textContent = total;
  if (total === 0) {
    tbody.innerHTML = `<tr><td colspan="3" class="panel-empty">no flagged IPs</td></tr>`;
    return;
  }

  const addRow = (label, count, active, onClick, isHeader) => {
    const tr = document.createElement('tr');
    if (isHeader) {
      tr.innerHTML = `<td colspan="3" class="classifier-subhead">${escapeHTML(label)}</td>`;
      tbody.appendChild(tr);
      return;
    }
    if (active) tr.classList.add('scope-active');
    tr.setAttribute('title', active ? 'click to clear filter' : 'click to filter the flags panel');
    const w = (count / maxCount) * 100;
    tr.innerHTML = `
      <td class="key-cell" title="${escapeHTML(label)}">${escapeHTML(label)}</td>
      <td class="right hits-cell">${fmtInt(count)}</td>
      <td class="bar-cell"><div class="bar" style="width:${w.toFixed(1)}%"></div></td>`;
    tr.addEventListener('click', (e) => {
      if (e.target.closest('.col-resize')) return;
      onClick();
    });
    tbody.appendChild(tr);
  };

  sources.forEach(s => {
    const active = !!scope && scope.type === 'source' && scope.value === s.source;
    addRow(s.source, s.count, active,
      () => setFlagsScope(active ? null : { type: 'source', value: s.source, label: s.source, tagType: def.tagType }));
  });
  if (buckets.length > 0) {
    addRow('by score', 0, false, null, true);
    buckets.forEach(b => {
      const active = !!scope && scope.type === 'minscore' && scope.min === b.min;
      addRow(b.label, b.count, active,
        () => setFlagsScope(active ? null : { type: 'minscore', min: b.min, label: b.label, tagType: def.tagType }));
    });
  }
}

// setFlagsScope updates the drill-down and refreshes both client panels
// (the breakdown for the active highlight, the flags list for the rows).
function setFlagsScope(scope) {
  flagsScope = scope;
  refreshTagPanels();
}

// refreshTagPanels refills the client-rendered classifier panels after
// the tag list updates (the tag fetch and the dashboard fanout race) or
// after the scope changes.
function refreshTagPanels() {
  document.querySelectorAll('section.panel[data-panel="reasons"]').forEach(sec => {
    if (sec._pg) fillReasonsPanel(sec);
  });
  document.querySelectorAll('section.panel[data-panel="classifiers"]').forEach(sec => {
    if (sec._pg) fillClassifiersPanel(sec);
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
// The trailing bar column compensates every drag: as the dragged column
// grows by Δ the bar shrinks by Δ, so the table never overflows the
// panel. Bar is purely a rescaling sparkline so it tolerates a wide
// range of widths. Growth is capped at the point bar would shrink past
// MIN_BAR_W; if you need more room, switch panel-width up a notch.
const MIN_BAR_W = 20;
function installColumnResize(table) {
  const ths = [...table.querySelectorAll('thead th')];
  const barTh = ths.find(t => t.dataset.col === 'bar') || null;
  ths.forEach((th) => {
    const handle = th.querySelector('.col-resize');
    if (!handle) return;
    handle.addEventListener('mousedown', (e) => {
      e.preventDefault();
      e.stopPropagation();
      const startX = e.clientX;
      const startW = th.getBoundingClientRect().width;
      const compensate = barTh && barTh !== th;
      const startBarW = compensate ? barTh.getBoundingClientRect().width : 0;
      const maxGrow = compensate ? Math.max(0, startBarW - MIN_BAR_W) : Infinity;
      handle.classList.add('resizing');
      th.classList.add('resizing');
      const onMove = (ev) => {
        const delta = ev.clientX - startX;
        const newW = Math.max(30, Math.min(startW + delta, startW + maxGrow));
        th.style.width = newW + 'px';
        if (compensate) {
          barTh.style.width = (startBarW - (newW - startW)) + 'px';
        }
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
// Column widths are scoped by current panel-width setting because what
// looks balanced at "narrow" overflows at "wide" and vice versa. Key is
// cl_cols_<panelWidth>_<panelName>.
function colsKey(panelName) {
  return 'cl_cols_' + state.panelWidth + '_' + panelName;
}
function saveColumnWidths(table) {
  const panel = table.dataset.panel;
  if (!panel) return;
  const widths = [...table.querySelectorAll('thead th')].map(th => th.style.width || '');
  try { localStorage.setItem(colsKey(panel), JSON.stringify(widths)); } catch {}
}
function restoreColumnWidths(table, panelName) {
  try {
    const raw = localStorage.getItem(colsKey(panelName));
    if (!raw) return;
    const widths = JSON.parse(raw);
    const ths = table.querySelectorAll('thead th');
    widths.forEach((w, i) => { if (w && ths[i]) ths[i].style.width = w; });
  } catch {}
}
// One-time migration: legacy keys (cl_cols_<panel>) were unscoped and
// produced overflow when switching layouts. Drop them so the new scoped
// scheme starts from defaults.
function purgeLegacyColumnWidths() {
  const layouts = ['narrow_', 'medium_', 'wide_'];
  const stale = [];
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i);
    if (!k || !k.startsWith('cl_cols_')) continue;
    const rest = k.slice('cl_cols_'.length);
    if (!layouts.some(p => rest.startsWith(p))) stale.push(k);
  }
  stale.forEach(k => { try { localStorage.removeItem(k); } catch {} });
}
// Clear inline widths on existing tables and reapply from the layout
// scope. Called both after the user resets and after a panel-width
// toggle so already-mounted tables pick up the right per-layout widths.
function reapplyColumnWidthsForCurrentLayout() {
  document.querySelectorAll('table.panel-table').forEach(table => {
    const panel = table.dataset.panel;
    if (!panel) return;
    table.querySelectorAll('thead th').forEach(th => { th.style.width = ''; });
    restoreColumnWidths(table, panel);
  });
}
function resetColumnWidthsForCurrentLayout() {
  const prefix = 'cl_cols_' + state.panelWidth + '_';
  const toDrop = [];
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i);
    if (k && k.startsWith(prefix)) toDrop.push(k);
  }
  toDrop.forEach(k => { try { localStorage.removeItem(k); } catch {} });
  document.querySelectorAll('table.panel-table thead th').forEach(th => {
    th.style.width = '';
  });
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
    <td class="ua-cell" title="${escapeHTML(r.user_agent || '')}">${escapeHTML(truncate(ua, 30))}</td>
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
  tr.addEventListener('contextmenu', (e) => rowContextMenu(e, r));
  body.appendChild(tr);
}

// rowContextMenu routes a right-click on a recent-requests row: the UA cell
// opens the allowlist menu (keyed on the raw User-Agent), the IP cell opens
// the tag menu. Shared by the initial render and the live-tail rows.
function rowContextMenu(e, r) {
  if (e.target.closest('.ua-cell') && r.user_agent) {
    e.preventDefault();
    openAllowMenu(r.user_agent, e.clientX, e.clientY);
    return;
  }
  if (e.target.closest('.ip-cell') && r.ip) {
    e.preventDefault();
    openTagMenu(r.ip, e.clientX, e.clientY);
  }
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
    case 'all':       return 'all';
    default:          return 'dynamic';
  }
}

// hasNonTimeFilter mirrors the server's filterHasPredicate: true when the
// filter constrains by something other than a time bound. The All view needs
// one to stay fast (it spans every class), so the UI uses this both to decide
// whether to fire the query and to show the "add a filter" prompt instead.
function hasNonTimeFilter(f) {
  f = f || state.filter || {};
  const any = o => o && Object.values(o).some(a => (a || []).length > 0);
  return any(f.include) || any(f.exclude) || any(f.contains);
}

// --- main refresh cycle ---
let inflight = null;
async function refreshAll() {
  syncURLFromState();
  renderChips();
  updateRangePresetHighlight();
  if (inflight) inflight.abort();
  const ac = new AbortController();
  inflight = ac;
  const table = viewTable(state.view);
  const effectiveFilter = viewFilter(state.filter, state.view);
  const body = { filter: effectiveFilter, topn: state.topN, table, order_by: state.sortBy };
  refreshBreakdown();
  refreshTagList();
  refreshAllowlist();

  // The All view spans every class and the server requires a non-time
  // filter before serving it (filterHasPredicate). With none set, show a
  // prompt rather than firing a request the server will reject. The
  // breakdown bar above still renders the global class composition.
  if (state.view === 'all' && !hasNonTimeFilter()) {
    renderAllNeedsFilter();
    inflight = null;
    return;
  }

  // Pin overlays fire in parallel so their latency overlaps the main
  // dashboard's. Each pin keeps its captured view + filter (the "what")
  // but inherits the current time window (the "when") so pinned slices
  // track as the operator brushes / changes presets. Each pin → one
  // /api/timeline call.
  const pinPromises = state.pins.map(pin => {
    const f = deepCopyFilter(pin.filter);
    f.time_from = state.filter.time_from;
    f.time_to = state.filter.time_to;
    const pinFilter = viewFilter(f, pin.view);
    const pinBody = { filter: pinFilter, table: viewTable(pin.view) };
    return fetch('/api/timeline', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(pinBody), signal: ac.signal,
    })
      .then(r => r.ok ? r.json() : null)
      .then(j => (j && j.timeline) ? { pin, buckets: j.timeline } : null)
      .catch(e => {
        if (e.name !== 'AbortError') console.error('pin:', pin.id, e);
        return null;
      });
  });

  let mainDash = null;
  try {
    const url = table === 'static' ? '/api/static' : '/api/dashboard';
    const r = await fetch(url, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body), signal: ac.signal,
    });
    if (!r.ok) throw new Error(r.status);
    mainDash = await r.json();
    renderOverview(mainDash.overview || {});
    renderStatusClass(mainDash.status_class || {});
    // Initial timeline render without overlays so the user sees the
    // main chart immediately; pin overlays fold in once their requests
    // return.
    renderTimeline(mainDash.timeline || [], null);
    renderPanels(mainDash.panels || {});
  } catch (e) {
    if (e.name !== 'AbortError') console.error('dashboard:', e);
  }
  if (pinPromises.length > 0 && mainDash) {
    const settled = await Promise.all(pinPromises);
    const overlays = settled.filter(Boolean).map(({ pin, buckets }) => ({
      buckets, color: pin.color, label: pinShortLabel(pin.filter, pin.view),
    }));
    if (overlays.length > 0) {
      renderTimeline(mainDash.timeline || [], overlays);
    }
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

// PANEL_MIN_WIDTHS maps the operator-facing label to the actual CSS
// minmax() floor that #panels uses. Wider floors mean fewer-but-wider
// columns, which is what you want when long URIs or UAs are getting
// truncated; narrower floors let more panels sit side-by-side on a
// big monitor.
const PANEL_MIN_WIDTHS = { narrow: '280px', medium: '380px', wide: '560px' };

function setPanelWidth(w) {
  if (!PANEL_MIN_WIDTHS[w]) return;
  state.panelWidth = w;
  try { localStorage.setItem('caddylogs.panelWidth', w); } catch {}
  document.documentElement.style.setProperty('--panel-min-width', PANEL_MIN_WIDTHS[w]);
  document.querySelectorAll('.pw-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.pw === w);
  });
  reapplyColumnWidthsForCurrentLayout();
}

function setView(v) {
  if (!['dynamic', 'static', 'local', 'bots', 'malicious', 'all'].includes(v)) return;
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
  // The All view spans every pool, so any row's table qualifies; other views
  // pin to their single table.
  if (state.view !== 'all' && rowTable(r) !== viewTable(state.view)) return false;
  const f = viewFilter(state.filter, state.view);
  // malicious and all bypass the server-side bot/local exclusion defaults.
  if (state.view !== 'malicious' && state.view !== 'all') {
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

// --- UA allowlist ---
// Right-clicking a user-agent in the recent-requests list opens this menu.
// The operator trims the full UA down to a distinctive substring (e.g.
// "ScoreBox/") and confirms; the server persists it, teaches the classifier,
// and reclassifies matching rows to real. Beats the bot heuristic + attack
// detection, but a per-IP tag still wins.
function openAllowMenu(ua, x, y) {
  closeAllowMenu();
  const menu = document.createElement('div');
  menu.className = 'tag-menu allow-menu';
  menu.id = 'allow-menu';
  menu.innerHTML = `
    <div class="tag-menu-title">Allowlist user-agent as <span class="tag-badge tag-real">real</span></div>
    <div class="allow-ua" title="${escapeHTML(ua)}">${escapeHTML(ua)}</div>
    <label class="allow-label">Match any UA containing:</label>
    <input class="allow-pattern" type="text" spellcheck="false" />
    <input class="allow-note" type="text" spellcheck="false" placeholder="note (optional, e.g. scoring boxes)" />
    <div class="allow-actions">
      <button class="allow-confirm" type="button">Allowlist</button>
      <button class="cancel" type="button">Cancel</button>
    </div>
  `;
  const W = 340, H = 240;
  menu.style.left = Math.max(4, Math.min(x, window.innerWidth - W)) + 'px';
  menu.style.top = Math.max(4, Math.min(y, window.innerHeight - H)) + 'px';
  document.body.appendChild(menu);
  const patternEl = menu.querySelector('.allow-pattern');
  const noteEl = menu.querySelector('.allow-note');
  patternEl.value = ua;
  const submit = async () => {
    const pattern = patternEl.value.trim();
    if (!pattern) { patternEl.focus(); return; }
    closeAllowMenu();
    await addAllow(pattern, noteEl.value.trim());
  };
  menu.querySelector('.allow-confirm').addEventListener('click', submit);
  patternEl.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); submit(); } });
  noteEl.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); submit(); } });
  menu.querySelector('.cancel').addEventListener('click', closeAllowMenu);
  // Focus the pattern input and select it so the operator can immediately
  // trim the full UA down to a distinctive token.
  setTimeout(() => {
    patternEl.focus();
    patternEl.select();
    document.addEventListener('click', outsideAllowClose, true);
    document.addEventListener('keydown', escAllowClose);
  }, 0);
}
function outsideAllowClose(e) {
  const m = document.getElementById('allow-menu');
  if (m && !m.contains(e.target)) closeAllowMenu();
}
function escAllowClose(e) {
  if (e.key === 'Escape') closeAllowMenu();
}
function closeAllowMenu() {
  const m = document.getElementById('allow-menu');
  if (m) m.remove();
  document.removeEventListener('click', outsideAllowClose, true);
  document.removeEventListener('keydown', escAllowClose);
}
async function addAllow(pattern, note) {
  try {
    const r = await fetch('/api/allowlist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pattern, note }),
    });
    if (!r.ok) {
      const body = await r.json().catch(() => ({}));
      throw new Error(body.error || ('HTTP ' + r.status));
    }
    refreshAll();
  } catch (e) {
    alert('Failed to allowlist "' + pattern + '": ' + e.message);
  }
}
async function removeAllow(pattern) {
  try {
    const r = await fetch('/api/allowlist?pattern=' + encodeURIComponent(pattern), { method: 'DELETE' });
    if (!r.ok) {
      const body = await r.json().catch(() => ({}));
      throw new Error(body.error || ('HTTP ' + r.status));
    }
    refreshAll();
  } catch (e) {
    alert('Failed to remove "' + pattern + '": ' + e.message);
  }
}
// refreshAllowlist repaints the allowlist management panel from /api/allowlist.
async function refreshAllowlist() {
  const sec = document.getElementById('allow-section');
  const body = document.getElementById('allow-body');
  const count = document.getElementById('allow-count');
  const pathEl = document.getElementById('allow-file-path');
  try {
    const data = await getJSON('/api/allowlist');
    const patterns = data.patterns || [];
    if (pathEl) pathEl.textContent = data.path || '';
    count.textContent = String(patterns.length);
    if (patterns.length === 0) {
      sec.classList.add('hidden');
      body.innerHTML = '';
      return;
    }
    sec.classList.remove('hidden');
    body.innerHTML = '';
    for (const p of patterns) {
      const tr = document.createElement('tr');
      const since = p.at ? fmtTs(new Date(Math.round(p.at / 1e6))) : '';
      tr.innerHTML = `
        <td><code>${escapeHTML(p.pattern)}</code></td>
        <td class="muted">${escapeHTML(p.note || '')}</td>
        <td class="muted">${escapeHTML(since)}</td>
        <td class="right"><button class="btn btn-ghost allow-remove" type="button">remove</button></td>
      `;
      tr.querySelector('.allow-remove').addEventListener('click', () => removeAllow(p.pattern));
      body.appendChild(tr);
    }
  } catch (e) {
    console.error('allowlist:', e);
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
function initCollapsibleSection({ titleSelector, bodySelector, storageKey, onExpand }) {
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
    if (want && onExpand) onExpand();
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

// latestTags caches the most recent /api/tags payload so the
// client-rendered "Classifier flags" panel can read reasons/scores
// without its own fetch. Updated by refreshTagList.
let latestTags = [];
// The tag table is deliberately decoupled from the tag fetch. With tens of
// thousands of persistent tags a naive rebuild is ~130k DOM nodes; besides
// the app's own ~300ms of innerHTML parsing, every rebuild (and every later
// DOM mutation anywhere on the page, while those nodes exist) makes
// password-manager extensions re-walk the whole tree looking for form
// fields — seconds of main-thread time that froze the timeline zoom on
// each range change. So: nothing is rendered while the section is
// collapsed, an unchanged payload never re-renders, rows are paged, and
// clicks are delegated from the tbody instead of two listeners per row.
const TAGS_PAGE_INITIAL = 200;
const TAGS_PAGE_MORE = 1000;
// tagsText is the raw body of the last /api/tags response. Comparing raw
// bodies is a memcmp, so an unchanged payload (the common case on a range
// change) costs nothing beyond the fetch: no JSON parse, no panel refill,
// no DOM work. tagsRenderedText / tagsRenderedRows describe what the table
// currently shows.
let tagsText = '';
let tagsRenderedText = null;
let tagsRenderedRows = 0;
let tagsShown = 0;              // rows currently in the DOM

async function refreshTagList() {
  const sec = document.getElementById('tags-section');
  const count = document.getElementById('tags-count');
  const pathEl = document.getElementById('tags-file-path');
  try {
    const r = await fetch('/api/tags');
    if (!r.ok) throw new Error(`/api/tags: ${r.status}`);
    const text = await r.text();
    if (text === tagsText) return;
    const data = JSON.parse(text);
    const tags = data.tags || [];
    latestTags = tags;
    tagsText = text;
    // The dashboard fanout and this tag fetch race; refill the
    // client-rendered classifier panels now that the data has landed.
    refreshTagPanels();
    if (pathEl) pathEl.textContent = data.path || '';
    sec.classList.toggle('hidden', tags.length === 0);
    count.textContent = String(tags.length);
    renderTagList();
  } catch (e) {
    console.error('tags:', e);
  }
}

// renderTagList syncs the table with latestTags. It is a no-op while the
// section is collapsed (initCollapsibleSection calls it again on expand) and
// when the DOM already shows this exact payload at this page size.
function renderTagList() {
  const body = document.getElementById('tags-body');
  const collapsible = document.getElementById('tags-collapsible');
  const more = document.getElementById('tags-more');
  if (!body) return;
  if (collapsible && collapsible.classList.contains('hidden')) return;
  const tags = latestTags;
  const want = Math.min(tags.length, Math.max(tagsShown, TAGS_PAGE_INITIAL));
  if (tagsText === tagsRenderedText && want === tagsRenderedRows) return;
  const parts = [];
  for (let i = 0; i < want; i++) {
    const t = tags[i];
    const since = t.at ? fmtTs(new Date(Math.round(t.at / 1e6))) : '';
    const source = t.source || 'manual';
    const reasonTip = t.reason ? ` — ${t.reason}` : '';
    parts.push(`<tr data-ip="${escapeHTML(t.ip)}">
        <td class="tag-ip" title="click to filter by this IP">${escapeHTML(t.ip)}</td>
        <td><span class="tag-badge tag-${escapeHTML(t.tag)}">${escapeHTML(t.tag)}</span></td>
        <td class="tag-source" title="${escapeHTML(source + reasonTip)}">${escapeHTML(source)}</td>
        <td class="muted">${escapeHTML(since)}</td>
        <td class="right"><button class="btn btn-ghost tag-remove" type="button">untag</button></td>
      </tr>`);
  }
  body.innerHTML = parts.join('');
  tagsShown = want;
  tagsRenderedText = tagsText;
  tagsRenderedRows = want;
  if (more) {
    const left = tags.length - want;
    more.classList.toggle('hidden', left <= 0);
    more.textContent = `show ${Math.min(left, TAGS_PAGE_MORE)} more (${left} hidden)`;
  }
}
// One delegated handler for the whole table: the per-row IP filter and
// untag actions read the IP off the row instead of closing over it.
document.getElementById('tags-body').addEventListener('click', (e) => {
  const tr = e.target.closest('tr[data-ip]');
  if (!tr) return;
  const ip = tr.dataset.ip;
  if (e.target.closest('.tag-remove')) removeTag(ip);
  else if (e.target.closest('.tag-ip')) addFilter('ip', ip, false);
});
document.getElementById('tags-more').addEventListener('click', () => {
  tagsShown = Math.min(latestTags.length, tagsShown + TAGS_PAGE_MORE);
  renderTagList();
});
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
        <td class="right">
          <button class="btn classifier-run" type="button">Run</button>
          <button class="btn classifier-clear" type="button" title="Remove every IP this classifier tagged">Clear</button>
        </td>
      `;
      tr.querySelector('.classifier-run').addEventListener('click', (ev) => {
        runClassifier(c.name, ev.target);
      });
      tr.querySelector('.classifier-clear').addEventListener('click', (ev) => {
        clearClassifier(c.name, ev.target);
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

async function clearClassifier(name, btn) {
  if (!confirm(`Remove every IP tagged by ${name}?\n\nThis reverts those rows back to the real pool. Manual tags and other classifiers' tags are not affected.`)) {
    return;
  }
  const original = btn ? btn.textContent : null;
  if (btn) { btn.disabled = true; btn.textContent = 'clearing…'; }
  try {
    const r = await fetch('/api/classifiers/clear?name=' + encodeURIComponent(name), { method: 'POST' });
    if (!r.ok) {
      const body = await r.json().catch(() => ({}));
      throw new Error(body.error || ('HTTP ' + r.status));
    }
    const result = await r.json();
    const removed = (result.removed || []).length;
    const elapsed = result.elapsed_ms || 0;
    console.log(`${name}: -${removed} untagged in ${elapsed}ms`);
    if (removed) {
      refreshAll();
    } else {
      refreshTagList();
    }
    if (btn) { btn.textContent = `-${removed}`; }
    setTimeout(() => { if (btn && original != null) { btn.textContent = original; btn.disabled = false; } }, 2000);
  } catch (e) {
    alert('Failed to clear classifier ' + name + ': ' + e.message);
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
        // Live rows are the freshest data; keep the presets' reference
        // "now" tracking them so "last 7d" stays relative to real data on
        // a long-lived page.
        const ts = msg.row && msg.row.ts;
        if (ts && (!state.globalLast || Date.parse(ts) > Date.parse(state.globalLast))) {
          state.globalLast = ts;
        }
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
          <td class="ua-cell" title="${escapeHTML(r.user_agent || '')}">${escapeHTML(truncate(ua, 30))}</td>
          <td class="right">${dur}</td>
        `;
        tr.addEventListener('contextmenu', (e) => rowContextMenu(e, r));
        body.insertBefore(tr, body.firstChild);
        while (body.children.length > 300) body.removeChild(body.lastChild);
      }
    } catch (e) { /* ignore */ }
  };
  ws.onclose = () => setTimeout(openWS, 2000);
}

// --- log-file statistics overlay ---
// Opened from the header's "log files" button; fetches /api/filestats on each
// open and renders the ingest-time snapshot per input file plus a totals row.
// Deliberately an overlay rather than a dashboard panel: inspecting input
// files (e.g. to tune log rotation) is occasional, not part of the core flow.

// fmtSpan renders a duration in the largest readable unit (log files span
// hours to months, so ms/seconds precision is noise here).
function fmtSpan(ms) {
  if (!ms || ms <= 0) return '—';
  const h = ms / 3600000;
  if (h < 1) return Math.round(ms / 60000) + ' min';
  if (h < 48) return h.toFixed(1) + ' h';
  return (h / 24).toFixed(1) + ' d';
}

function openFileStats() {
  state.fileStatsOpen = true;
  syncURLFromState();
  document.getElementById('filestats-overlay').classList.remove('hidden');
  document.addEventListener('keydown', escFileStatsClose);
  const el = document.getElementById('filestats-content');
  el.innerHTML = '<div class="hint">loading…</div>';
  getJSON('/api/filestats')
    .then(data => renderFileStats(data.files || []))
    .catch(e => { el.innerHTML = `<div class="hint">failed to load: ${escapeHTML(e.message)}</div>`; });
}
function closeFileStats() {
  state.fileStatsOpen = false;
  syncURLFromState();
  document.getElementById('filestats-overlay').classList.add('hidden');
  document.removeEventListener('keydown', escFileStatsClose);
}
function escFileStatsClose(e) { if (e.key === 'Escape') closeFileStats(); }

function renderFileStats(files) {
  const el = document.getElementById('filestats-content');
  if (files.length === 0) {
    el.innerHTML = `<div class="hint">No ingest statistics recorded. This cached database predates
      per-file stats — run <code>caddylogs clear-cache</code> (or serve with <code>--no-cache</code>)
      and re-ingest to record them.</div>`;
    return;
  }
  // Per-file derived values. Timestamps are meaningful only when the file
  // had parseable entries (zero-time otherwise). Per-day rates are shown
  // only for spans over an hour so short files don't extrapolate nonsense.
  const row = f => {
    const hasTs = f.entries > 0 && new Date(f.first).getTime() > 0;
    const spanMs = hasTs ? new Date(f.last) - new Date(f.first) : 0;
    const days = spanMs / 86400000;
    const perDay = spanMs >= 3600000
      ? `${fmtInt(Math.round(f.entries / days))} / ${fmtBytes(f.raw_bytes / days)}`
      : '—';
    const name = f.path.split('/').pop();
    const bad = f.bad_lines ? ` <span class="muted">+${fmtInt(f.bad_lines)} bad</span>` : '';
    return `<tr>
      <td title="${escapeHTML(f.path)}">${escapeHTML(name)}${f.compressed ? ' <span class="muted">gz</span>' : ''}</td>
      <td>${fmtInt(f.entries)}${bad}</td>
      <td>${fmtBytes(f.disk_bytes)}</td>
      <td>${fmtBytes(f.raw_bytes)}</td>
      <td>${f.compressed && f.disk_bytes > 0 ? (f.raw_bytes / f.disk_bytes).toFixed(1) + '×' : '—'}</td>
      <td>${f.entries > 0 ? fmtBytes(f.raw_bytes / f.entries) : '—'}</td>
      <td class="muted">${hasTs ? fmtTs(f.first) : '—'}</td>
      <td class="muted">${hasTs ? fmtTs(f.last) : '—'}</td>
      <td>${fmtSpan(spanMs)}</td>
      <td>${perDay}</td>
    </tr>`;
  };
  const sum = k => files.reduce((a, f) => a + (f[k] || 0), 0);
  const entries = sum('entries'), disk = sum('disk_bytes'), raw = sum('raw_bytes');
  const withTs = files.filter(f => f.entries > 0 && new Date(f.first).getTime() > 0);
  const first = withTs.length ? withTs.reduce((a, f) => Math.min(a, new Date(f.first)), Infinity) : 0;
  const last = withTs.length ? withTs.reduce((a, f) => Math.max(a, new Date(f.last)), 0) : 0;
  const totalSpan = last > first ? last - first : 0;
  const totalDays = totalSpan / 86400000;
  const totalPerDay = totalSpan >= 3600000
    ? `${fmtInt(Math.round(entries / totalDays))} / ${fmtBytes(raw / totalDays)}`
    : '—';
  el.innerHTML = `
    <table id="filestats-table">
      <thead><tr>
        <th>file</th><th>entries</th><th>on disk</th><th>uncompressed</th><th>ratio</th>
        <th>bytes/entry</th><th>first entry</th><th>last entry</th><th>span</th><th>per day</th>
      </tr></thead>
      <tbody>
        ${files.map(row).join('')}
        <tr class="totals">
          <td>${files.length} files</td>
          <td>${fmtInt(entries)}</td>
          <td>${fmtBytes(disk)}</td>
          <td>${fmtBytes(raw)}</td>
          <td>${disk > 0 ? (raw / disk).toFixed(1) + '×' : '—'}</td>
          <td>${entries > 0 ? fmtBytes(raw / entries) : '—'}</td>
          <td class="muted">${first ? fmtTs(first) : '—'}</td>
          <td class="muted">${last ? fmtTs(last) : '—'}</td>
          <td>${fmtSpan(totalSpan)}</td>
          <td>${totalPerDay}</td>
        </tr>
      </tbody>
    </table>
    <div class="hint">Sizes and timespans are per input file as of ingest; "per day" is
    entries / uncompressed data per day over the file's span — compare against your
    rotation settings (e.g. roll_size / roll_keep) to see how much history they retain.</div>`;
}

document.getElementById('filestats-open').addEventListener('click', openFileStats);
document.getElementById('filestats-close').addEventListener('click', closeFileStats);
document.getElementById('filestats-overlay').addEventListener('click', (e) => {
  if (e.target === e.currentTarget) closeFileStats(); // backdrop click closes
});

// --- wire up ---
document.getElementById('clear-filters').addEventListener('click', () => {
  // Clear the non-time filters in place, then let setTimeWindow drop the time
  // bounds so the timeline animates the range back to "all" like the presets.
  state.filter.include = {};
  state.filter.exclude = {};
  state.filter.contains = {};
  setTimeWindow(null, null);
});

// Timeline range presets. "N days back from the freshest known
// timestamp" so historical logs don't end up with an empty window
// when wall-clock has moved past the log's end. time_to stays null
// so live-tail ingestion keeps appending inside the range.
function applyRangePreset(days) {
  if (!days || days <= 0) {
    setTimeWindow(null, null);
  } else {
    const refEnd = state.globalLast ? new Date(state.globalLast) : new Date();
    const start = new Date(refEnd.getTime() - days * 86400000);
    setTimeWindow(start.toISOString(), null);
  }
}
document.querySelectorAll('.range-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    applyRangePreset(parseInt(btn.dataset.days, 10) || 0);
  });
});

// Default time window when the URL names none: the last DEFAULT_RANGE_DAYS
// days before the freshest data. applyDefaultRangeWindow sets the filter
// bounds from state.globalLast (no refresh, no history push); fetchDataSpan
// learns globalLast/globalFirst cheaply at boot, before the first dashboard
// load, so the default is anchored to the data rather than wall-clock.
const DEFAULT_RANGE_DAYS = 30;
function applyDefaultRangeWindow() {
  const refEnd = state.globalLast ? Date.parse(state.globalLast) : Date.now();
  state.filter.time_from = new Date(refEnd - DEFAULT_RANGE_DAYS * 86400000).toISOString();
  state.filter.time_to = null;
}
async function fetchDataSpan() {
  // The All view refuses unfiltered queries (and its union can't use the
  // ts index anyway); fall back to wall-clock there.
  if (state.view === 'all' && !hasNonTimeFilter()) return;
  try {
    const f = viewFilter(state.filter, state.view);
    f.time_from = null; f.time_to = null;
    const r = await postJSON('/api/query', { table: viewTable(state.view), kind: 'span', filter: f });
    const ov = r.overview || {};
    // Go's zero time serializes as year 0001; treat that as "no data".
    if (ov.last && Date.parse(ov.last) > 0) {
      state.globalLast = ov.last;
      state.globalFirst = ov.first;
    }
  } catch (e) {
    console.error('span:', e);
  }
}
// Highlight the preset button whose window the current time filter
// "closely" matches — whether it was set by the button itself, a
// timeline brush, or a URL. "Closely" is a tolerance of 5% of the preset
// span (~1.2h for 24h, ~8h for 7d), so a brush that lands near a preset
// still lights it up, while a window a day off from 7d doesn't.
function updateRangePresetHighlight() {
  const from = state.filter.time_from, to = state.filter.time_to;
  const refEnd = to ? Date.parse(to)
    : (state.globalLast ? Date.parse(state.globalLast) : Date.now());
  document.querySelectorAll('.range-btn').forEach(btn => {
    const days = parseInt(btn.dataset.days, 10) || 0;
    let match;
    if (!days) {
      match = !from && !to;
    } else if (!from) {
      match = false;
    } else {
      const span = days * 86400000;
      const tol = span * 0.05;
      const fromOK = Math.abs(refEnd - span - Date.parse(from)) <= tol;
      // An explicit time_to must also sit near the reference end the
      // presets use (the freshest data), or the window is merely the
      // right *length*, not the "last N days".
      const endRef = state.globalLast ? Date.parse(state.globalLast) : Date.now();
      const toOK = !to || Math.abs(Date.parse(to) - endRef) <= tol;
      match = fromOK && toOK;
    }
    btn.classList.toggle('active', match);
  });
}
updateRangePresetHighlight();
const pinBtn = document.getElementById('pin-current');
if (pinBtn) pinBtn.addEventListener('click', pinCurrent);
renderPinChips();
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
document.querySelectorAll('.pw-btn').forEach(btn => {
  btn.addEventListener('click', () => setPanelWidth(btn.dataset.pw));
});
document.querySelectorAll('.cols-reset').forEach(btn => {
  btn.addEventListener('click', resetColumnWidthsForCurrentLayout);
});
purgeLegacyColumnWidths();
// Apply the persisted panel-width on load so the grid starts at the
// operator's preferred density rather than flashing the default first.
setPanelWidth(state.panelWidth);

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
  onExpand: renderTagList,
});
initCollapsibleSection({
  titleSelector: '#allow-section .collapsible-title',
  bodySelector: '#allow-collapsible',
  storageKey: 'cl_allow_expanded',
});
loadClassifiers();

// Browser back/forward navigates through the filter/view/sort history.
// suppressURLSync stops the syncURLFromState() at the top of refreshAll
// from re-pushing the URL we just read. It only needs to cover that
// synchronous prefix — clearing it before the await window means a
// concurrent user click that triggers another refreshAll still pushes.
window.addEventListener('popstate', () => {
  suppressURLSync = true;
  applyHashToState();
  refreshAll();
  suppressURLSync = false;
});

// Initial load: pick up filters from the hash (deep links, reload) and
// normalize the URL to our canonical encoding via replaceState so the
// first history entry already matches what refreshAll would emit.
// One cheap span query first so the dataset's freshest timestamp is known
// before the first load: the default "last N days" window is anchored to it,
// and with a deep-linked window the presets / their highlight are relative
// to the data rather than wall-clock. suppressURLSync is only raised around
// the synchronous part so a click during the await still pushes history.
applyHashToState();
(async () => {
  await fetchDataSpan();
  if (state.defaultRange) applyDefaultRangeWindow();
  suppressURLSync = true;
  refreshAll();
  const initHash = encodeStateToHash();
  const curHash = (window.location.hash || '').replace(/^#/, '');
  if (initHash !== curHash) {
    const url = initHash ? '#' + initHash : (location.pathname + location.search);
    history.replaceState(null, '', url);
  }
  suppressURLSync = false;
  openWS();
})();
