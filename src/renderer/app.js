/* Rae Proxy — main renderer */

const S = {
  config: null,
  proxy: {},
  ca: {},
  systemProxy: false,
  scriptTemplate: '',
  flows: new Map(),
  view: [],
  selected: new Set(),
  focusId: null,
  anchorId: null,
  detail: null,
  filter: { text: '', kind: 'All', status: 'All', side: { type: 'all' } },
  sort: { col: 'id', asc: true },
  tabs: { req: 'Header', res: 'Body' },
  modes: { req: null, res: null },
  sideSearch: '',
};

const ROW_H = 24;
const KIND_CHIPS = ['All', 'HTTP', 'HTTPS', 'WebSocket', 'JSON', 'GraphQL', 'Form', 'XML', 'HTML', 'JS', 'CSS', 'Image', 'Media', 'Font'];
const STATUS_CHIPS = ['1xx', '2xx', '3xx', '4xx', '5xx', 'Errors'];

const COLS = [
  { key: 'id', label: '#', get: (f) => f.id },
  { key: 'url', label: 'URL', get: (f) => f.url },
  { key: 'method', label: 'Method', get: (f) => f.method },
  { key: 'status', label: 'Status', get: (f) => f.status || 0 },
  { key: 'kind', label: 'Type', get: (f) => contentKind(f) },
  { key: 'start', label: 'Time', get: (f) => f.start },
  { key: 'duration', label: 'Duration', get: (f) => f.duration ?? -1 },
  { key: 'size', label: 'Size', get: (f) => f.resSize },
  { key: 'tags', label: 'Tags', get: (f) => f.tags.join(',') },
];

// ---------------- state ----------------
async function refreshState() {
  const st = await rae.invoke('state:get');
  S.config = st.config;
  S.proxy = st.proxy;
  S.ca = st.ca;
  S.systemProxy = st.systemProxy;
  S.scriptTemplate = st.scriptTemplate;
  return st;
}

async function saveConfig(patch) {
  S.config = await rae.invoke('config:set', patch);
  if (patch.port !== undefined || patch.listenAll !== undefined) await refreshState();
  updateChrome();
  return S.config;
}

// ---------------- filtering / sorting ----------------
function matchesFilter(f) {
  const { text, kind, status, side } = S.filter;
  if (side.type === 'host' && f.host !== side.value) return false;
  if (side.type === 'client' && f.clientAddr !== side.value) return false;
  if (side.type === 'pinned' && !S.config.pinned.includes(f.host)) return false;
  if (kind !== 'All') {
    if (kind === 'HTTP' && (f.scheme !== 'http' || f.ws)) return false;
    if (kind === 'HTTPS' && f.scheme !== 'https') return false;
    if (kind !== 'HTTP' && kind !== 'HTTPS' && contentKind(f) !== kind) return false;
  }
  if (status !== 'All') {
    if (status === 'Errors') { if (f.state !== 'error') return false; }
    else if (!f.status || String(f.status)[0] !== status[0]) return false;
  }
  if (text) {
    const hay = `${f.method} ${f.url} ${f.status || ''} ${f.tags.join(' ')} ${f.clientAddr}`.toLowerCase();
    for (const term of text.toLowerCase().split(/\s+/).filter(Boolean)) {
      const neg = term.startsWith('-') && term.length > 1;
      const t = neg ? term.slice(1) : term;
      const m = t.match(/^(method|status|host|tag):(.+)$/);
      let hit;
      if (m) {
        const v = m[2];
        hit = m[1] === 'method' ? f.method.toLowerCase() === v
          : m[1] === 'status' ? String(f.status || '').startsWith(v.replace(/x+$/, ''))
          : m[1] === 'host' ? f.host.toLowerCase().includes(v)
          : f.tags.some((x) => x.includes(v));
      } else hit = hay.includes(t);
      if (hit === neg) return false;
    }
  }
  return true;
}

function recompute() {
  const col = COLS.find((c) => c.key === S.sort.col) || COLS[0];
  const list = [];
  for (const f of S.flows.values()) if (matchesFilter(f)) list.push(f);
  if (col.key !== 'id') {
    list.sort((a, b) => {
      const x = col.get(a), y = col.get(b);
      return (x < y ? -1 : x > y ? 1 : a.id - b.id) * (S.sort.asc ? 1 : -1);
    });
  } else if (!S.sort.asc) list.reverse();
  S.view = list;
}

// ---------------- table ----------------
const tbody = $('#tbody');
const rowsEl = $('#rows');
const spacer = $('#spacer');
let renderQueued = false;
let stickToBottom = true;

function scheduleRender(full = true) {
  if (renderQueued) return;
  renderQueued = true;
  requestAnimationFrame(() => {
    renderQueued = false;
    if (full) recompute();
    renderTable();
    renderStatus();
  });
}

function renderHead() {
  $('#thead').replaceChildren(...COLS.map((c) => h('div', {
    class: S.sort.col === c.key ? 'sorted' + (S.sort.asc ? ' asc' : '') : '',
    onclick: () => {
      if (S.sort.col === c.key) S.sort.asc = !S.sort.asc;
      else S.sort = { col: c.key, asc: true };
      renderHead();
      scheduleRender();
    },
  }, c.label)));
}

function statusCell(f) {
  if (f.state === 'paused') return '<span class="st s4">Paused</span>';
  if (f.state === 'error' && !f.status) return '<span class="st serr">Failed</span>';
  if (!f.status) return '<span class="dim">…</span>';
  return `<span class="st ${statusClass(f.status)}">${f.status}</span>`;
}

function rowHTML(f) {
  const sel = S.selected.has(f.id);
  let pathPart = f.path;
  if (f.tunnel) pathPart = f.port ? `:${f.port}` : '';
  const tags = f.tags.filter((t) => t !== 'tunnel').map((t) => `<span class="tag">${esc(t)}</span>`).join('');
  return `<div class="row${sel ? ' sel' : ''}${f.state === 'error' ? ' err' : ''}${f.state === 'paused' ? ' paused' : ''}" data-id="${f.id}">`
    + `<div class="dim">${f.id}</div>`
    + `<div class="url" title="${esc(f.url)}"><span class="host">${esc(f.scheme === 'https' && f.tunnel ? '🔒 ' : '')}${esc(f.ws ? (f.scheme === 'https' ? 'wss' : 'ws') : f.scheme)}://${esc(f.host)}</span>${esc(pathPart)}</div>`
    + `<div class="method">${esc(f.method)}</div>`
    + `<div>${statusCell(f)}</div>`
    + `<div class="dim">${esc(f.tunnel ? 'SSL tunnel' : contentKind(f))}</div>`
    + `<div class="dim">${fmtTime(f.start)}</div>`
    + `<div class="dim">${f.duration === null ? '' : fmtDuration(f.duration)}</div>`
    + `<div class="dim">${f.ws ? `${f.wsCount} msg` : fmtBytes(f.resSize)}</div>`
    + `<div>${tags}</div></div>`;
}

function renderTable() {
  const n = S.view.length;
  spacer.style.height = n * ROW_H + 'px';
  $('#empty').classList.toggle('hidden', S.flows.size > 0);
  if (stickToBottom && S.sort.col === 'id' && S.sort.asc) tbody.scrollTop = tbody.scrollHeight;
  const top = tbody.scrollTop;
  const height = tbody.clientHeight;
  const start = Math.max(0, Math.floor(top / ROW_H) - 10);
  const end = Math.min(n, Math.ceil((top + height) / ROW_H) + 10);
  let html = '';
  for (let i = start; i < end; i++) html += rowHTML(S.view[i]);
  rowsEl.innerHTML = html;
  rowsEl.style.transform = `translateY(${start * ROW_H}px)`;
  [...rowsEl.children].forEach((r, i) => { r.style.top = i * ROW_H + 'px'; });
}

tbody.addEventListener('scroll', () => {
  stickToBottom = tbody.scrollTop + tbody.clientHeight >= tbody.scrollHeight - ROW_H * 2;
  renderTable();
});
new ResizeObserver(() => renderTable()).observe(tbody);

rowsEl.addEventListener('mousedown', (e) => {
  const row = e.target.closest('.row');
  if (!row) return;
  const id = Number(row.dataset.id);
  if (e.button === 2 && S.selected.has(id)) return;
  if (e.metaKey) {
    S.selected.has(id) ? S.selected.delete(id) : S.selected.add(id);
    S.anchorId = id;
  } else if (e.shiftKey && S.anchorId !== null) {
    const a = S.view.findIndex((f) => f.id === S.anchorId);
    const b = S.view.findIndex((f) => f.id === id);
    S.selected = new Set(S.view.slice(Math.min(a, b), Math.max(a, b) + 1).map((f) => f.id));
  } else {
    S.selected = new Set([id]);
    S.anchorId = id;
  }
  setFocus(id);
  tbody.focus();
});
rowsEl.addEventListener('dblclick', (e) => {
  const row = e.target.closest('.row');
  if (row) openComposeFrom(Number(row.dataset.id));
});
rowsEl.addEventListener('contextmenu', (e) => {
  e.preventDefault();
  const row = e.target.closest('.row');
  if (row) rowMenu(Number(row.dataset.id));
});
tbody.tabIndex = 0;
tbody.addEventListener('keydown', (e) => {
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    e.preventDefault();
    const idx = S.view.findIndex((f) => f.id === S.focusId);
    const next = S.view[Math.max(0, Math.min(S.view.length - 1, idx + (e.key === 'ArrowDown' ? 1 : -1)))];
    if (!next) return;
    if (!e.shiftKey) S.selected = new Set([next.id]);
    else S.selected.add(next.id);
    S.anchorId = e.shiftKey ? S.anchorId : next.id;
    setFocus(next.id);
    const y = S.view.indexOf(next) * ROW_H;
    if (y < tbody.scrollTop) tbody.scrollTop = y;
    else if (y + ROW_H > tbody.scrollTop + tbody.clientHeight) tbody.scrollTop = y + ROW_H - tbody.clientHeight;
  } else if (e.key === 'a' && e.metaKey) {
    e.preventDefault();
    S.selected = new Set(S.view.map((f) => f.id));
    renderTable();
  } else if ((e.key === 'Backspace' || e.key === 'Delete') && S.selected.size) {
    deleteFlows([...S.selected]);
  } else if (e.key === 'c' && e.metaKey && S.focusId) {
    e.preventDefault();
    rae.invoke('clipboard:write', [...S.selected].map((id) => S.flows.get(id)?.url).filter(Boolean).join('\n'));
    toast('URL copied');
  }
});

function setFocus(id) {
  S.focusId = id;
  renderTable();
  loadDetail();
}

function selectFlow(id, scroll) {
  if (!S.flows.has(id)) return;
  S.selected = new Set([id]);
  S.anchorId = id;
  setFocus(id);
  if (scroll) {
    const i = S.view.findIndex((f) => f.id === id);
    if (i >= 0) tbody.scrollTop = i * ROW_H - tbody.clientHeight / 2;
  }
}

async function deleteFlows(ids) {
  await rae.invoke('flows:delete', ids);
  for (const id of ids) S.flows.delete(id);
  S.selected.clear();
  if (ids.includes(S.focusId)) { S.focusId = null; S.detail = null; renderDetail(); }
  scheduleRender();
  scheduleSidebar();
}

// ---------------- filter bar ----------------
function renderChips() {
  const chip = (label, group) => h('span', {
    class: 'chip' + (S.filter[group] === label ? ' on' : ''),
    onclick: () => { S.filter[group] = S.filter[group] === label && label !== 'All' ? 'All' : label; renderChips(); scheduleRender(); },
  }, label);
  $('#chips').replaceChildren(...KIND_CHIPS.map((k) => chip(k, 'kind')), h('span', { class: 'chip-sep' }), ...STATUS_CHIPS.map((k) => chip(k, 'status')));
}
$('#filter').addEventListener('input', debounce((e) => { S.filter.text = e.target.value.trim(); scheduleRender(); }, 120));

// ---------------- sidebar ----------------
let sidebarTimer = null;
function scheduleSidebar() {
  if (sidebarTimer) return;
  sidebarTimer = setTimeout(() => { sidebarTimer = null; renderSidebar(); }, 400);
}

function renderSidebar() {
  const hosts = new Map();
  const clients = new Map();
  for (const f of S.flows.values()) {
    const e = hosts.get(f.host) || { count: 0, https: false, tunnel: false };
    e.count++;
    if (f.scheme === 'https' && !f.tunnel) e.https = true;
    if (f.tunnel) e.tunnel = true;
    hosts.set(f.host, e);
    if (f.clientAddr) clients.set(f.clientAddr, (clients.get(f.clientAddr) || 0) + 1);
  }
  const q = S.sideSearch.toLowerCase();
  const side = S.filter.side;
  const item = (type, value, label, count, icon, extra) => h('div', {
    class: 'sb-item' + (side.type === type && side.value === value ? ' sel' : ''),
    title: label,
    onclick: () => { S.filter.side = { type, value }; renderSidebar(); scheduleRender(); },
    oncontextmenu: (e) => { e.preventDefault(); if (type === 'host' || type === 'pinnedHost') hostMenu(value); },
  }, h('span', { class: 'ic' }, icon), h('span', { class: 'name' }, label), extra || null, count !== null ? h('span', { class: 'count' }, count) : null);

  const out = [item('all', undefined, 'All Requests', S.flows.size, '◎')];
  const pinned = S.config.pinned.filter((p) => !q || p.includes(q));
  if (pinned.length) {
    out.push(h('div', { class: 'sb-section' }, 'Pinned'));
    for (const p of pinned) out.push(item('host', p, p, hosts.get(p)?.count || 0, '📌'));
  }
  if (clients.size > 1) {
    out.push(h('div', { class: 'sb-section' }, 'Clients'));
    for (const [c, n] of [...clients].sort()) if (!q || c.includes(q)) out.push(item('client', c, c === '127.0.0.1' ? 'This Mac' : c, n, '💻'));
  }
  out.push(h('div', { class: 'sb-section' }, `Domains (${hosts.size})`));
  for (const [host, e] of [...hosts].sort((a, b) => a[0].localeCompare(b[0]))) {
    if (q && !host.toLowerCase().includes(q)) continue;
    const icon = e.https ? '🔓' : e.tunnel ? '🔒' : '🌐';
    out.push(item('host', host, host, e.count, icon));
  }
  $('#sidebar-list').replaceChildren(...out);
}
$('#sidebar-search').addEventListener('input', (e) => { S.sideSearch = e.target.value; renderSidebar(); });

// ---------------- detail panes ----------------
let detailSeq = 0;
async function loadDetail() {
  const id = S.focusId;
  if (!id) { S.detail = null; return renderDetail(); }
  const seq = ++detailSeq;
  const d = await rae.invoke('flow:get', id);
  if (seq !== detailSeq) return;
  S.detail = d;
  renderDetail();
}
const reloadDetail = debounce(loadDetail, 150);

function paneHead(title, side, tabs, modes) {
  const head = h('div', { class: 'pane-head' }, h('span', { class: 'pane-title' }, title));
  for (const t of tabs) {
    const [name, badge] = Array.isArray(t) ? t : [t];
    head.append(h('span', { class: 'tab' + (S.tabs[side] === name ? ' on' : ''), onclick: () => { S.tabs[side] = name; renderDetail(); } }, name, badge ? h('span', { class: 'badge' }, badge) : null));
  }
  if (modes && modes.length) {
    const cur = modes.includes(S.modes[side]) ? S.modes[side] : modes[0];
    head.append(h('div', { class: 'viewmodes' }, modes.map((m) => h('span', { class: 'tab' + (m === cur ? ' on' : ''), onclick: () => { S.modes[side] = m; renderDetail(); } }, m))));
  }
  return head;
}

function renderDetail() {
  const d = S.detail;
  const req = $('#pane-req');
  const res = $('#pane-res');
  if (!d) {
    req.replaceChildren(h('div', { class: 'pane-empty' }, 'Select a request'));
    res.replaceChildren();
    return;
  }
  const u = (() => { try { return new URL(d.url); } catch { return null; } })();
  const query = u ? [...u.searchParams] : [];
  const reqBytes = b64ToBytes(d.reqBody);
  const resBytes = d.resBody ? b64ToBytes(d.resBody) : null;
  const cookies = parseCookies(header(d.reqHeaders, 'cookie'));

  // Request
  const reqTabs = ['Header', ['Query', query.length || ''], ['Body', reqBytes.length ? fmtBytes(reqBytes.length) : ''], ['Cookies', cookies.length || ''], 'Raw', 'Summary'];
  if (!reqTabs.some((t) => (Array.isArray(t) ? t[0] : t) === S.tabs.req)) S.tabs.req = 'Header';
  const reqModes = S.tabs.req === 'Body' ? availableModes(reqBytes, d.reqContentType) : null;
  let reqBody;
  switch (S.tabs.req) {
    case 'Header':
      reqBody = h('div', null, h('div', { class: 'kv-section' }, `${d.method} ${u ? (d.tunnel ? u.host : u.pathname + u.search) : d.url} HTTP/${d.httpVersion}`), kvTable(d.reqHeaders, 'No headers'));
      break;
    case 'Query': reqBody = kvTable(query, 'No query parameters'); break;
    case 'Body': reqBody = renderBody(reqBytes, d.reqContentType, reqModes.includes(S.modes.req) ? S.modes.req : reqModes[0]); break;
    case 'Cookies': reqBody = kvTable(cookies, 'No cookies'); break;
    case 'Raw': reqBody = rawRequest(d); break;
    case 'Summary': reqBody = summaryView(d); break;
  }
  req.replaceChildren(paneHead('Request', 'req', reqTabs, reqModes), h('div', { class: 'pane-body' }, reqBody));

  // Response
  const setCookies = (d.resHeaders || []).filter(([k]) => k.toLowerCase() === 'set-cookie').length;
  const resTabs = [...(d.ws ? [['Messages', d.wsCount || '']] : []), 'Header', ['Body', resBytes && resBytes.length ? fmtBytes(resBytes.length) : ''], ['Set-Cookie', setCookies || ''], 'Raw', 'Timing'];
  if (!resTabs.some((t) => (Array.isArray(t) ? t[0] : t) === S.tabs.res)) S.tabs.res = d.ws ? 'Messages' : 'Body';
  const resModes = S.tabs.res === 'Body' && resBytes ? availableModes(resBytes, d.contentType) : null;
  let resBody;
  if (!d.status && S.tabs.res !== 'Timing') {
    resBody = h('div', { class: 'note' }, d.error ? h('div', { style: { color: 'var(--err)', lineHeight: 1.5 } }, h('b', null, 'Error: '), d.error) : d.state === 'paused' ? 'Paused at breakpoint…' : 'Waiting for response…');
  } else {
    switch (S.tabs.res) {
      case 'Messages': resBody = wsView(d); break;
      case 'Header':
        resBody = h('div', null, h('div', { class: 'kv-section' }, `HTTP/${d.httpVersion} ${d.status} ${d.statusMessage || ''}`), kvTable(d.resHeaders, 'No headers'));
        break;
      case 'Body':
        resBody = d.tunnel ? h('div', { class: 'note' }, `Encrypted tunnel — enable SSL Proxying for ${d.host} to see the content.`, h('div', { style: { marginTop: '10px' } }, h('button', { class: 'btn primary', onclick: () => enableSSLFor(d.host) }, `Enable SSL Proxying for ${d.host}`)))
          : renderBody(resBytes, d.contentType, resModes && resModes.length ? (resModes.includes(S.modes.res) ? S.modes.res : resModes[0]) : 'Text');
        break;
      case 'Set-Cookie': resBody = setCookieTable(d.resHeaders); break;
      case 'Raw': resBody = rawResponse(d); break;
      case 'Timing': resBody = timingView(d); break;
    }
  }
  res.replaceChildren(paneHead('Response', 'res', resTabs, resModes), h('div', { class: 'pane-body' }, resBody));
}

function summaryView(d) {
  const rows = [
    ['URL', d.url],
    d.originalUrl ? ['Original URL', d.originalUrl] : null,
    ['Method', d.method],
    ['Status', d.status ? `${d.status} ${d.statusMessage || ''}` : d.state],
    ['Protocol', `${d.scheme.toUpperCase()} · HTTP/${d.httpVersion}${d.ws ? ' · WebSocket' : ''}`],
    ['Client', d.clientAddr || '—'],
    ['Request size', fmtBytes(b64ToBytes(d.reqBody).length)],
    ['Response size', fmtBytes(d.resSize)],
    ['Started', new Date(d.start).toLocaleString()],
    ['Duration', fmtDuration(d.duration) || '—'],
    d.tags.length ? ['Tags', d.tags.join(', ')] : null,
    d.error ? ['Error', d.error] : null,
  ].filter(Boolean);
  return kvTable(rows);
}

// ---------------- context menus ----------------
async function rowMenu(id) {
  if (!S.selected.has(id)) { S.selected = new Set([id]); setFocus(id); }
  const f = S.flows.get(id);
  const ids = [...S.selected];
  const multi = ids.length > 1;
  const pinned = S.config.pinned.includes(f.host);
  const action = await rae.invoke('contextMenu', [
    { id: 'copy-url', label: multi ? `Copy ${ids.length} URLs` : 'Copy URL' },
    { id: 'copy-curl', label: 'Copy as cURL', enabled: !multi && !f.tunnel },
    { id: 'copy-body', label: 'Copy Response Body', enabled: !multi && !f.tunnel },
    { type: 'separator' },
    { id: 'repeat', label: multi ? `Repeat ${ids.length} Requests` : 'Repeat', enabled: !f.tunnel },
    { id: 'edit', label: 'Edit and Repeat…', enabled: !multi && !f.tunnel },
    { type: 'separator' },
    {
      label: 'Tools', submenu: [
        { id: 'tool-bp', label: 'Breakpoint…' },
        { id: 'tool-ml', label: 'Map Local (use this response)…', enabled: !f.tunnel },
        { id: 'tool-mr', label: 'Map Remote…' },
        { id: 'tool-sc', label: 'Scripting…' },
        { id: 'tool-block', label: 'Block List…' },
        { id: 'tool-allow', label: 'Allow List…' },
      ],
    },
    f.tunnel || !(S.config.ssl.interceptAll || S.config.ssl.include.length) || f.scheme === 'http'
      ? { id: 'ssl-on', label: `Enable SSL Proxying for ${f.host}`, enabled: f.scheme === 'https' }
      : { id: 'ssl-off', label: `Disable SSL Proxying for ${f.host}` },
    { id: 'pin', label: pinned ? `Unpin ${f.host}` : `Pin ${f.host}` },
    { type: 'separator' },
    { id: 'save-body', label: 'Save Response Body…', enabled: !multi && !f.tunnel },
    { id: 'har', label: multi ? `Export ${ids.length} as HAR…` : 'Export as HAR…' },
    { type: 'separator' },
    { id: 'delete', label: multi ? `Delete ${ids.length}` : 'Delete' },
  ]);
  if (!action) return;
  const d = !multi ? await rae.invoke('flow:get', id) : null;
  const pathPattern = f.url.split('?')[0] + (f.url.includes('?') ? '*' : '');
  switch (action) {
    case 'copy-url': rae.invoke('clipboard:write', ids.map((i) => S.flows.get(i)?.url).join('\n')); toast('Copied'); break;
    case 'copy-curl': rae.invoke('clipboard:write', toCurl(d)); toast('cURL copied'); break;
    case 'copy-body': rae.invoke('clipboard:write', d.resBody ? bytesToText(b64ToBytes(d.resBody)) : ''); toast('Body copied'); break;
    case 'repeat': for (const i of ids) rae.invoke('flow:repeat', i); break;
    case 'edit': openComposeFrom(id); break;
    case 'tool-bp': openTools('breakpoints', { name: f.host + f.path.split('?')[0], pattern: pathPattern, method: f.method }); break;
    case 'tool-ml': {
      const ct = header(d.resHeaders, 'content-type');
      const bytes = d.resBody ? b64ToBytes(d.resBody) : new Uint8Array();
      const textual = !looksBinary(bytes);
      const filePath = textual ? '' : await rae.invoke('mapLocal:saveBody', { id });
      openTools('mapLocal', {
        name: f.host + f.path.split('?')[0], pattern: pathPattern, method: f.method, status: d.status || 200,
        headers: (d.resHeaders || []).filter(([k]) => !/^(content-length|content-encoding|transfer-encoding|connection|date)$/i.test(k)).map(([k, v]) => `${k}: ${v}`).join('\n') || (ct ? `Content-Type: ${ct}` : ''),
        body: textual ? prettyMaybe(bytesToText(bytes)) : '', filePath: filePath || '',
      });
      break;
    }
    case 'tool-mr': openTools('mapRemote', { name: f.host, pattern: `${f.scheme}://${f.host}${f.port ? ':' + f.port : ''}/*` }); break;
    case 'tool-sc': openTools('scripting', { name: f.host + f.path.split('?')[0], pattern: pathPattern }); break;
    case 'tool-block': openTools('blockList', { name: f.host, pattern: `*://${f.host}/*` }); break;
    case 'tool-allow': openTools('allowList', { name: f.host, pattern: `*://${f.host}/*` }); break;
    case 'ssl-on': enableSSLFor(f.host); break;
    case 'ssl-off': disableSSLFor(f.host); break;
    case 'pin': togglePin(f.host); break;
    case 'save-body': rae.invoke('body:save', { id, which: 'response' }); break;
    case 'har': rae.invoke('har:export', ids); break;
    case 'delete': deleteFlows(ids); break;
  }
}

async function hostMenu(host) {
  const pinned = S.config.pinned.includes(host);
  const action = await rae.invoke('contextMenu', [
    { id: 'pin', label: pinned ? 'Unpin' : 'Pin' },
    { id: 'ssl-on', label: 'Enable SSL Proxying' },
    { id: 'ssl-off', label: 'Disable SSL Proxying' },
    { type: 'separator' },
    { id: 'block', label: 'Block this domain…' },
    { id: 'map-remote', label: 'Map Remote…' },
    { type: 'separator' },
    { id: 'copy', label: 'Copy Domain' },
    { id: 'delete', label: 'Remove all requests from this domain' },
  ]);
  switch (action) {
    case 'pin': togglePin(host); break;
    case 'ssl-on': enableSSLFor(host); break;
    case 'ssl-off': disableSSLFor(host); break;
    case 'block': openTools('blockList', { name: host, pattern: `*://${host}/*` }); break;
    case 'map-remote': openTools('mapRemote', { name: host, pattern: `*://${host}/*` }); break;
    case 'copy': rae.invoke('clipboard:write', host); break;
    case 'delete': deleteFlows([...S.flows.values()].filter((f) => f.host === host).map((f) => f.id)); break;
  }
}

function togglePin(host) {
  const pinned = S.config.pinned.includes(host) ? S.config.pinned.filter((p) => p !== host) : [...S.config.pinned, host];
  saveConfig({ pinned }).then(renderSidebar);
}

function enableSSLFor(host) {
  const ssl = structuredClone(S.config.ssl);
  ssl.exclude = ssl.exclude.filter((p) => p !== host);
  if (!ssl.interceptAll && !ssl.include.includes(host)) ssl.include.push(host);
  saveConfig({ ssl });
  toast(`SSL Proxying enabled for ${host} — retry the request`);
}

function disableSSLFor(host) {
  const ssl = structuredClone(S.config.ssl);
  ssl.include = ssl.include.filter((p) => p !== host);
  if (!ssl.exclude.includes(host)) ssl.exclude.push(host);
  saveConfig({ ssl });
  toast(`SSL Proxying disabled for ${host}`);
}

async function openComposeFrom(id) {
  const d = await rae.invoke('flow:get', id);
  if (!d || d.tunnel) return;
  const bytes = b64ToBytes(d.reqBody);
  openCompose({ method: d.method, url: d.url, headers: d.reqHeaders.filter(([k]) => !/^(content-length|proxy-connection)$/i.test(k)), body: looksBinary(bytes) ? '' : bytesToText(bytes) });
}

// ---------------- chrome: toolbar / banner / status ----------------
function activeRules(key) {
  const t = S.config[key];
  return t && t.enabled ? t.rules.filter((r) => r.enabled !== false).length : 0;
}

function updateChrome() {
  const c = S.config;
  $('#btn-record').classList.toggle('on', c.recording);
  $('#btn-sysproxy').classList.toggle('on', S.systemProxy);
  $('#btn-throttle').classList.toggle('on', c.throttle.enabled);
  $('#btn-throttle').textContent = c.throttle.enabled ? `Throttle: ${c.throttle.preset || 'Custom'}` : 'Throttle';
  $('#btn-breakpoints').classList.toggle('on', activeRules('breakpoints') > 0);
  $('#btn-scripting').classList.toggle('on', activeRules('scripting') > 0);

  const p = S.proxy;
  const addrs = (p.addresses || []).map((a) => a.address);
  $('#proxy-addr').textContent = p.running
    ? `Listening on 127.0.0.1:${p.port}${c.listenAll && addrs.length ? ' · ' + addrs.map((a) => `${a}:${p.port}`).join(' · ') : ''}`
    : `Not running${p.error ? ' — ' + p.error : ''}`;
  $('#empty-addr').textContent = `127.0.0.1:${p.port || c.port}`;

  const banner = $('#banner');
  if (!p.running) {
    banner.className = 'banner err';
    banner.replaceChildren(h('span', null, `⚠︎ Proxy is not running: ${p.error || 'unknown error'}`), h('button', { class: 'btn small', onclick: () => openTools('general') }, 'Change Port'), h('button', { class: 'btn small', onclick: async () => { S.proxy = { ...(await rae.invoke('proxy:restart')), addresses: S.proxy.addresses }; updateChrome(); } }, 'Retry'));
  } else if (!S.ca.trusted && !c.dismissCABanner) {
    banner.className = 'banner';
    banner.replaceChildren(
      h('span', null, '🔐 The Rae Proxy root certificate is not trusted on this Mac yet — HTTPS requests from this Mac can’t be decrypted.'),
      h('button', { class: 'btn small primary', onclick: () => openTools('certificate') }, 'Install Certificate…'),
      h('span', { class: 'grow' }),
      h('button', { class: 'btn small', onclick: () => saveConfig({ dismissCABanner: true }) }, 'Dismiss'));
  } else banner.className = 'banner hidden';

  const flags = [];
  if (c.throttle.enabled) flags.push(`Throttle ${c.throttle.latency}ms`);
  if (c.noCache) flags.push('No Caching');
  for (const [k, label] of [['breakpoints', 'Breakpoints'], ['mapLocal', 'Map Local'], ['mapRemote', 'Map Remote'], ['scripting', 'Scripts'], ['blockList', 'Block'], ['allowList', 'Allow']]) {
    const n = activeRules(k);
    if (n) flags.push(`${label} ${n}`);
  }
  $('#sb-flags').replaceChildren(...flags.map((f) => h('span', { class: 'flag' }, f)));
  $('#sb-cert').textContent = S.ca.trusted ? '🔐 Certificate trusted' : '⚠︎ Certificate not trusted';
  $('#sb-cert').style.color = S.ca.trusted ? 'var(--ok)' : 'var(--warn)';
}

function renderStatus() {
  $('#sb-count').textContent = `${S.flows.size.toLocaleString()} requests`;
  $('#sb-filter').textContent = S.view.length !== S.flows.size ? `${S.view.length.toLocaleString()} shown` : '';
}

async function toggleSystemProxy() {
  try {
    S.systemProxy = await rae.invoke('systemProxy:set', !S.systemProxy);
    toast(S.systemProxy ? 'This Mac now routes HTTP/HTTPS through Rae Proxy' : 'System proxy disabled');
  } catch (e) {
    toast('Could not change system proxy: ' + e.message.replace(/^Error invoking remote method '[^']+': (Error: )?/, ''));
  }
  updateChrome();
}

async function clearSession() {
  await rae.invoke('flows:clear');
  S.flows.clear();
  S.selected.clear();
  S.focusId = null;
  S.detail = null;
  renderDetail();
  renderSidebar();
  scheduleRender();
}

$('#btn-record').onclick = () => saveConfig({ recording: !S.config.recording });
$('#btn-clear').onclick = clearSession;
$('#btn-sysproxy').onclick = toggleSystemProxy;
$('#btn-throttle').onclick = () => saveConfig({ throttle: { enabled: !S.config.throttle.enabled } });
$('#btn-throttle').oncontextmenu = () => openTools('throttle');
$('#btn-breakpoints').onclick = () => openTools('breakpoints');
$('#btn-scripting').onclick = () => openTools('scripting');
$('#btn-compose').onclick = () => openCompose();
$('#btn-tools').onclick = () => openTools('ssl');
$('#sb-cert').onclick = () => openTools('certificate');

// ---------------- console ----------------
function logLine(entry) {
  const body = $('#console-body');
  body.append(h('div', { class: entry.level }, h('span', { class: 'src' }, `${fmtTime(entry.time || Date.now())} [${entry.source || 'proxy'}]`), entry.message));
  while (body.childElementCount > 2000) body.firstChild.remove();
  body.scrollTop = body.scrollHeight;
}
const toggleConsole = () => $('#console').classList.toggle('hidden');
$('#sb-console').onclick = toggleConsole;
$('#console-close').onclick = toggleConsole;
$('#console-clear').onclick = () => $('#console-body').replaceChildren();

// ---------------- splitters ----------------
function dragSplit(handle, onMove) {
  handle.addEventListener('mousedown', (e) => {
    e.preventDefault();
    const move = (ev) => onMove(ev);
    const up = () => { document.removeEventListener('mousemove', move); document.removeEventListener('mouseup', up); };
    document.addEventListener('mousemove', move);
    document.addEventListener('mouseup', up);
  });
}
dragSplit($('.vsplit'), (e) => { $('#sidebar').style.width = Math.max(150, Math.min(500, e.clientX)) + 'px'; });
dragSplit($('#hsplit'), (e) => {
  const rect = $('#center').getBoundingClientRect();
  $('#detail').style.height = Math.max(120, Math.min(rect.height - 140, rect.bottom - e.clientY)) + 'px';
});
dragSplit($('.psplit'), (e) => {
  const d = $('#detail');
  const rect = d.getBoundingClientRect();
  const ratio = d.classList.contains('vertical') ? (e.clientY - rect.top) / rect.height : (e.clientX - rect.left) / rect.width;
  const r = Math.max(0.15, Math.min(0.85, ratio));
  $('#pane-req').style.flex = `${r}`;
  $('#pane-res').style.flex = `${1 - r}`;
});

// ---------------- menu + IPC events ----------------
const MENU = {
  settings: () => openTools('general'),
  compose: () => openCompose(),
  clear: clearSession,
  'session:open': () => rae.invoke('har:import'),
  'session:save': () => rae.invoke('session:save'),
  'har:import': () => rae.invoke('har:import'),
  'har:export': () => rae.invoke('har:export', null),
  'focus-filter': () => $('#filter').focus(),
  'toggle-sidebar': () => $('#sidebar').classList.toggle('collapsed'),
  'toggle-layout': () => $('#detail').classList.toggle('vertical'),
  'toggle-recording': () => saveConfig({ recording: !S.config.recording }),
  'toggle-system-proxy': toggleSystemProxy,
  'toggle-throttle': () => saveConfig({ throttle: { enabled: !S.config.throttle.enabled } }),
  'toggle-nocache': () => saveConfig({ noCache: !S.config.noCache }),
  console: toggleConsole,
  'cert:install': () => openTools('certificate'),
  'cert:device': () => openTools('certificate'),
  'cert:export': () => rae.invoke('ca:export'),
  'cert:regenerate': async () => { S.ca = await rae.invoke('ca:regenerate'); updateChrome(); },
};

rae.on('menu', (action) => {
  if (action.startsWith('tool:')) return openTools(action.slice(5));
  MENU[action] && MENU[action]();
});

rae.on('flows:update', (list) => {
  let hostsChanged = false;
  for (const f of list) {
    if (!S.flows.has(f.id)) hostsChanged = true;
    S.flows.set(f.id, f);
    if (f.id === S.focusId) reloadDetail();
  }
  if (hostsChanged) scheduleSidebar();
  scheduleRender();
});
rae.on('flows:reset', (list) => {
  S.flows = new Map(list.map((f) => [f.id, f]));
  renderSidebar();
  scheduleRender();
});
rae.on('breakpoint:hit', enqueueBreakpoint);
rae.on('script:log', (entry) => {
  logLine(entry);
  if (entry.level === 'error') $('#console').classList.remove('hidden');
});
rae.on('proxy:status', (p) => { S.proxy = p; updateChrome(); });
rae.on('systemProxy:status', (on) => { S.systemProxy = on; updateChrome(); });

// ---------------- boot ----------------
(async () => {
  const st = await refreshState();
  for (const f of st.flows) S.flows.set(f.id, f);
  renderHead();
  renderChips();
  renderSidebar();
  renderDetail();
  updateChrome();
  scheduleRender();
  // Re-check certificate trust when the window regains focus (user may have trusted it in Keychain Access).
  window.addEventListener('focus', debounce(async () => {
    const ca = await rae.invoke('ca:info');
    if (ca.trusted !== S.ca.trusted) { S.ca = ca; updateChrome(); }
  }, 300));
})();
