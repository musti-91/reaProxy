/* Shared renderer helpers (exposed as globals). */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

function h(tag, attrs, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k === 'style' && typeof v === 'object') Object.assign(e.style, v);
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'html') e.innerHTML = v;
    else if (k === 'value') e.value = v;
    else if (k in e && typeof v !== 'string') e[k] = v;
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return e;
}

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

function fmtBytes(n) {
  if (n === null || n === undefined) return '';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

function fmtDuration(ms) {
  if (ms === null || ms === undefined) return '';
  if (ms < 1000) return `${ms} ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(2)} s`;
  return `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`;
}

function fmtTime(ts) {
  const d = new Date(ts);
  return d.toTimeString().slice(0, 8) + '.' + String(d.getMilliseconds()).padStart(3, '0');
}

function b64ToBytes(b64) {
  if (!b64) return new Uint8Array(0);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const decoder = new TextDecoder('utf-8', { fatal: false });
const bytesToText = (bytes) => decoder.decode(bytes);

function looksBinary(bytes) {
  const n = Math.min(bytes.length, 2000);
  let bad = 0;
  for (let i = 0; i < n; i++) {
    const c = bytes[i];
    if (c === 0) return true;
    if (c < 9 || (c > 13 && c < 32)) bad++;
  }
  return n > 0 && bad / n > 0.1;
}

function isTextType(ct) {
  return /^text\/|json|xml|javascript|ecmascript|x-www-form-urlencoded|graphql|yaml|csv|html|svg/i.test(ct || '');
}

function header(pairs, name) {
  name = name.toLowerCase();
  const f = (pairs || []).find(([k]) => k.toLowerCase() === name);
  return f ? f[1] : undefined;
}

const headersToText = (pairs) => (pairs || []).map(([k, v]) => `${k}: ${v}`).join('\n');
function textToHeaders(text) {
  return String(text || '')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const i = l.indexOf(':', l.startsWith(':') ? 1 : 0);
      return i === -1 ? [l, ''] : [l.slice(0, i).trim(), l.slice(i + 1).trim()];
    });
}

function shellQuote(s) {
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
}

function toCurl(d) {
  const parts = ['curl'];
  if (d.method !== 'GET') parts.push('-X', d.method);
  parts.push(shellQuote(d.url));
  for (const [k, v] of d.reqHeaders || []) {
    if (/^(content-length|host|proxy-connection|connection)$/i.test(k)) continue;
    parts.push('-H', shellQuote(`${k}: ${v}`));
  }
  const body = b64ToBytes(d.reqBody);
  if (body.length) {
    if (looksBinary(body)) parts.push('--data-binary', '@-');
    else parts.push('--data-raw', shellQuote(bytesToText(body)));
  }
  if (/gzip|br|deflate/.test(header(d.reqHeaders, 'accept-encoding') || '')) parts.push('--compressed');
  return parts.join(' \\\n  ');
}

function debounce(fn, ms) {
  let t;
  return (...a) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...a), ms);
  };
}

const uid = () => Math.random().toString(36).slice(2, 10) + Date.now().toString(36).slice(-4);

function statusClass(s) {
  if (!s) return '';
  return 's' + String(s)[0];
}

function contentKind(f) {
  const ct = (f.contentType || '').toLowerCase();
  if (f.ws) return 'WebSocket';
  if (f.tunnel) return 'Tunnel';
  if (f.graphql) return 'GraphQL';
  if (/json/.test(ct)) return 'JSON';
  if (/html/.test(ct)) return 'HTML';
  if (/xml/.test(ct)) return 'XML';
  if (/javascript|ecmascript/.test(ct)) return 'JS';
  if (/css/.test(ct)) return 'CSS';
  if (/^image\//.test(ct)) return 'Image';
  if (/^(video|audio)\//.test(ct)) return 'Media';
  if (/font/.test(ct)) return 'Font';
  if (/form/.test(f.reqContentType || '')) return 'Form';
  if (/^text\//.test(ct)) return 'Text';
  return ct ? ct.split(';')[0].split('/').pop() : '';
}

// Simple modal manager
function openModal({ title, sub, body, foot, cls = '', onClose, closeOnOverlay = true }) {
  const overlay = h('div', { class: 'overlay' });
  const modal = h('div', { class: `modal ${cls}` },
    h('div', { class: 'modal-head' }, h('h2', null, title), sub ? h('span', { class: 'sub' }, sub) : null),
    h('div', { class: 'modal-body' }, body),
    foot ? h('div', { class: 'modal-foot' }, foot) : null);
  overlay.append(modal);
  const close = () => {
    overlay.remove();
    document.removeEventListener('keydown', onKey, true);
    onClose && onClose();
  };
  const onKey = (e) => {
    if (e.key === 'Escape' && overlay === $('#modal-root').lastElementChild) {
      e.stopPropagation();
      close();
    }
  };
  document.addEventListener('keydown', onKey, true);
  if (closeOnOverlay) overlay.addEventListener('mousedown', (e) => { if (e.target === overlay) close(); });
  $('#modal-root').append(overlay);
  return { overlay, modal, close };
}

function toast(msg) {
  const t = h('div', { style: { position: 'fixed', bottom: '40px', left: '50%', transform: 'translateX(-50%)', background: 'var(--fg)', color: 'var(--bg)', padding: '8px 16px', borderRadius: '8px', zIndex: 100, fontSize: '12px', boxShadow: '0 6px 20px rgba(0,0,0,.25)' } }, msg);
  document.body.append(t);
  setTimeout(() => t.remove(), 1800);
}

// textarea: Tab inserts two spaces
function codeArea(attrs) {
  const ta = h('textarea', { spellcheck: false, ...attrs });
  ta.addEventListener('keydown', (e) => {
    if (e.key === 'Tab') {
      e.preventDefault();
      const s = ta.selectionStart;
      ta.setRangeText('  ', s, ta.selectionEnd, 'end');
      ta.dispatchEvent(new Event('input'));
    }
  });
  return ta;
}

// Line-based diff (LCS). Returns [{type: 'same'|'add'|'del', text}]. Capped for huge inputs.
function diffLines(aText, bText) {
  const a = String(aText ?? '').split('\n');
  const b = String(bText ?? '').split('\n');
  const n = a.length, m = b.length;
  if (n * m > 2_000_000) {
    // Too big to diff cheaply — fall back to a single replace block.
    return [...a.map((text) => ({ type: 'del', text })), ...b.map((text) => ({ type: 'add', text }))];
  }
  const dp = new Array(n + 1);
  for (let i = 0; i <= n; i++) dp[i] = new Uint32Array(m + 1);
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const out = [];
  let i = 0, j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) { out.push({ type: 'same', text: a[i] }); i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) { out.push({ type: 'del', text: a[i] }); i++; }
    else { out.push({ type: 'add', text: b[j] }); j++; }
  }
  while (i < n) out.push({ type: 'del', text: a[i++] });
  while (j < m) out.push({ type: 'add', text: b[j++] });
  return out;
}

function switchEl(checked, onchange) {
  const input = h('input', { type: 'checkbox', checked: !!checked, onchange: (e) => onchange(e.target.checked) });
  return h('label', { class: 'switch' }, input, h('span'));
}
