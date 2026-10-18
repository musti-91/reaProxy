/* Body / header / timing viewers used by the detail panes. */

function highlightJSON(text) {
  return esc(text).replace(
    /(&quot;(?:\\.|[^&\\]|&(?!quot;))*?&quot;)(\s*:)?|\b(true|false)\b|\bnull\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g,
    (m, str, colon, bool) => {
      if (str) return colon ? `<span class="j-key">${str}</span>${colon}` : `<span class="j-str">${str}</span>`;
      if (bool) return `<span class="j-bool">${m}</span>`;
      if (m === 'null') return `<span class="j-null">null</span>`;
      return `<span class="j-num">${m}</span>`;
    }
  );
}

function jsonTree(value, key, depth = 0, inArray = false) {
  const label = key !== undefined ? h('span', { class: inArray ? 'meta' : 'j-key' }, inArray ? String(key) : JSON.stringify(String(key)), ': ') : null;
  if (value === null || typeof value !== 'object') {
    let cls = 'j-str', txt = JSON.stringify(value);
    if (typeof value === 'number') cls = 'j-num';
    else if (typeof value === 'boolean') cls = 'j-bool';
    else if (value === null) cls = 'j-null';
    return h('div', { class: 'leaf' }, label, h('span', { class: cls }, txt));
  }
  const isArr = Array.isArray(value);
  const entries = isArr ? value.map((v, i) => [i, v]) : Object.entries(value);
  const d = h('details', { open: depth < 2 });
  d.append(h('summary', null, label, isArr ? '[' : '{', h('span', { class: 'meta' }, ` ${entries.length} ${isArr ? 'items' : 'keys'} `), isArr ? ']' : '}'));
  let rendered = false;
  const fill = () => {
    if (rendered) return;
    rendered = true;
    for (const [k, v] of entries.slice(0, 5000)) d.append(jsonTree(v, k, depth + 1, isArr));
    if (entries.length > 5000) d.append(h('div', { class: 'leaf meta' }, `… ${entries.length - 5000} more`));
  };
  if (d.open) fill();
  d.addEventListener('toggle', fill);
  return d;
}

function hexDump(bytes, max = 64 * 1024) {
  const n = Math.min(bytes.length, max);
  let out = '';
  for (let i = 0; i < n; i += 16) {
    const slice = bytes.subarray(i, Math.min(i + 16, n));
    const hex = [...slice].map((b) => b.toString(16).padStart(2, '0')).join(' ').padEnd(47, ' ');
    const asc = [...slice].map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');
    out += `<span class="off">${i.toString(16).padStart(8, '0')}</span>  ${hex}  <span class="asc">${esc(asc)}</span>\n`;
  }
  if (bytes.length > max) out += `\n… ${fmtBytes(bytes.length - max)} more`;
  return h('div', { class: 'hex', html: out });
}

function formatXML(xml) {
  let pad = 0;
  return xml
    .replace(/>\s*</g, '>\n<')
    .split('\n')
    .map((line) => {
      if (/^<\/\w/.test(line)) pad = Math.max(0, pad - 1);
      const out = '  '.repeat(pad) + line;
      if (/^<\w[^>]*[^/]>.*$/.test(line) && !/<\/\w/.test(line) && !/^<(br|img|meta|link|input|hr)\b/i.test(line)) pad++;
      return out;
    })
    .join('\n');
}

function availableModes(bytes, ct) {
  if (!bytes || !bytes.length) return [];
  const modes = [];
  const text = !looksBinary(bytes) || isTextType(ct);
  if (/^image\//i.test(ct) && !/svg/i.test(ct)) return ['Preview', 'Hex'];
  if (text) {
    const s = bytesToText(bytes.subarray(0, 1)).trim();
    const isJson = /json|graphql/i.test(ct) || s === '{' || s === '[';
    if (isJson) modes.push('Tree', 'Pretty');
    else if (/x-www-form-urlencoded/i.test(ct)) modes.push('Form');
    else if (/xml|html|svg/i.test(ct)) modes.push('Pretty');
    if (/svg/i.test(ct)) modes.push('Preview');
    modes.push('Text');
  }
  modes.push('Hex');
  return [...new Set(modes)];
}

function renderBody(bytes, ct, mode) {
  if (!bytes || !bytes.length) return h('div', { class: 'pane-empty' }, 'No body');
  if (mode === 'Hex') return hexDump(bytes);
  if (mode === 'Preview') {
    const url = URL.createObjectURL(new Blob([bytes], { type: (ct || '').split(';')[0] || 'image/png' }));
    return h('div', { class: 'preview-img' }, h('img', { src: url, onload: () => setTimeout(() => URL.revokeObjectURL(url), 1000) }));
  }
  const text = bytesToText(bytes.length > 5e6 ? bytes.subarray(0, 5e6) : bytes);
  if (mode === 'Tree' || mode === 'Pretty') {
    if (/xml|html|svg/i.test(ct) && mode === 'Pretty') return h('pre', { class: 'code' }, formatXML(text));
    try {
      const v = JSON.parse(text);
      if (mode === 'Tree') return h('div', { class: 'jtree' }, jsonTree(v));
      return h('pre', { class: 'code', html: highlightJSON(JSON.stringify(v, null, 2)) });
    } catch {
      return h('pre', { class: 'code' }, text);
    }
  }
  if (mode === 'Form') {
    const params = [...new URLSearchParams(text)];
    return kvTable(params);
  }
  return h('pre', { class: 'code' }, text + (bytes.length > 5e6 ? `\n\n… truncated (${fmtBytes(bytes.length)})` : ''));
}

function kvTable(pairs, emptyText = 'None') {
  if (!pairs || !pairs.length) return h('div', { class: 'pane-empty' }, emptyText);
  return h('table', { class: 'kv' }, h('tbody', null, pairs.map(([k, v]) => h('tr', null, h('td', null, k), h('td', { class: 'mono' }, v)))));
}

function parseCookies(str) {
  return String(str || '')
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => {
      const i = s.indexOf('=');
      return i === -1 ? [s, ''] : [s.slice(0, i), decodeURIComponentSafe(s.slice(i + 1))];
    });
}

function decodeURIComponentSafe(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

function setCookieTable(pairs) {
  const cookies = (pairs || []).filter(([k]) => k.toLowerCase() === 'set-cookie').map(([, v]) => v);
  if (!cookies.length) return h('div', { class: 'pane-empty' }, 'No cookies set');
  return h('table', { class: 'kv' }, h('tbody', null, cookies.map((c) => {
    const [first, ...attrs] = c.split(';');
    const i = first.indexOf('=');
    return h('tr', null, h('td', null, first.slice(0, i)), h('td', { class: 'mono' }, decodeURIComponentSafe(first.slice(i + 1)), h('div', { class: 'dim', style: { color: 'var(--fg-faint)' } }, attrs.join(';').trim())));
  })));
}

function timingView(d) {
  const t = d.timing || {};
  const total = (t.end || Date.now()) - t.start;
  const phases = [
    ['Request sent', t.start, t.sent],
    ['Waiting (TTFB)', t.sent, t.firstByte],
    ['Content download', t.firstByte, t.end],
  ].filter(([, a, b]) => a && b);
  const rows = phases.map(([name, a, b]) => {
    const left = ((a - t.start) / Math.max(total, 1)) * 100;
    const width = ((b - a) / Math.max(total, 1)) * 100;
    return h('tr', null, h('td', null, name), h('td', null,
      h('div', { style: { position: 'relative', height: '10px', marginTop: '4px' } }, h('div', { class: 'timing-bar', style: { position: 'absolute', left: left + '%', width: Math.max(width, 0.5) + '%' } })),
    ), h('td', { style: { width: '80px', textAlign: 'right' } }, fmtDuration(b - a)));
  });
  return h('div', null,
    h('table', { class: 'kv' }, h('tbody', null,
      h('tr', null, h('td', null, 'Started'), h('td', { colspan: 2 }, new Date(t.start).toLocaleString() + ' ' + fmtTime(t.start).slice(8))),
      h('tr', null, h('td', null, 'Total duration'), h('td', { colspan: 2 }, fmtDuration(t.end ? total : null) || 'In progress…')),
      ...rows)));
}

function wsView(d) {
  const msgs = d.wsMessages || [];
  if (!msgs.length) return h('div', { class: 'pane-empty' }, 'No messages yet');
  return h('div', null, msgs.map((m) => h('div', { class: 'ws-msg' },
    h('span', { class: m.dir }, m.dir === 'out' ? '↑' : '↓'),
    h('span', { class: 'dim', style: { color: 'var(--fg-faint)' } }, fmtTime(m.time)),
    h('span', { class: 'data' }, m.text !== undefined ? m.text : m.base64 !== undefined ? `<binary ${fmtBytes(m.length)}> ${m.base64.slice(0, 120)}` : `<${m.type}>`),
    h('span', { style: { textAlign: 'right', color: 'var(--fg-faint)' } }, `${m.type} · ${fmtBytes(m.length)}`))));
}

function rawRequest(d) {
  const u = new URL(d.url);
  const body = b64ToBytes(d.reqBody);
  const head = `${d.method} ${d.tunnel ? u.host : u.pathname + u.search} HTTP/${d.httpVersion}\n${headersToText(d.reqHeaders)}`;
  return h('pre', { class: 'code' }, head + '\n\n' + (looksBinary(body) ? `<binary ${fmtBytes(body.length)}>` : bytesToText(body)));
}

function rawResponse(d) {
  if (!d.status) return h('div', { class: 'pane-empty' }, d.error || 'No response');
  const body = d.resBody ? b64ToBytes(d.resBody) : new Uint8Array();
  const head = `HTTP/${d.httpVersion} ${d.status} ${d.statusMessage || ''}\n${headersToText(d.resHeaders)}`;
  return h('pre', { class: 'code' }, head + '\n\n' + (looksBinary(body) ? `<binary ${fmtBytes(body.length)}>` : bytesToText(body)));
}
