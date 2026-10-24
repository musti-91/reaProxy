// Rewrite tool: Charles-style rule-based header/status/body/URL edits, no scripting required.
const { setHeader, removeHeader, getHeader } = require('./http-util');

function applyBodyAction(body, a) {
  if (!body || !body.length) return body;
  const text = body.toString('utf8');
  let next;
  if (a.regex) {
    let re;
    try { re = new RegExp(a.find, 'g'); } catch { return body; }
    next = text.replace(re, a.replace ?? '');
  } else if (a.find) {
    next = text.split(a.find).join(a.replace ?? '');
  } else {
    return body;
  }
  return next === text ? body : Buffer.from(next, 'utf8');
}

function applyHeaderAction(headers, a) {
  if (!a.name) return headers;
  if (a.op === 'remove') return removeHeader(headers, a.name);
  // 'set' overwrites any existing header with this name; 'add' appends regardless.
  if (a.op === 'add') return [...headers, [a.name, a.value ?? '']];
  return setHeader(headers, a.name, a.value ?? '');
}

function applyUrlAction(url, a) {
  try {
    const u = new URL(url);
    if (a.host) u.hostname = a.host;
    if (a.path) u.pathname = a.path;
    if (a.query !== undefined && a.query !== '') u.search = a.query.startsWith('?') ? a.query : '?' + a.query;
    return u.toString();
  } catch {
    return url;
  }
}

// r: { method, url, headers, body }
function applyRequest(rule, r) {
  let { url, headers, body, method } = r;
  for (const a of rule.actions || []) {
    if (a.phase !== 'request') continue;
    if (a.type === 'header') headers = applyHeaderAction(headers, a);
    else if (a.type === 'body') body = applyBodyAction(body, a);
    else if (a.type === 'url') url = applyUrlAction(url, a);
    else if (a.type === 'method' && a.value) method = a.value.toUpperCase();
  }
  if (body !== r.body) headers = setHeader(headers, 'Content-Length', body.length);
  return { ...r, method, url, headers, body };
}

// resp: { status, statusMessage, headers, body } — body is already decoded (unzipped)
function applyResponse(rule, resp) {
  let { status, statusMessage, headers, body } = resp;
  let changed = false;
  for (const a of rule.actions || []) {
    if (a.phase !== 'response') continue;
    if (a.type === 'header') { headers = applyHeaderAction(headers, a); changed = true; }
    else if (a.type === 'body') { const nb = applyBodyAction(body, a); if (nb !== body) { body = nb; changed = true; } }
    else if (a.type === 'status' && a.value) { status = Number(a.value) || status; statusMessage = undefined; changed = true; }
  }
  if (!changed) return resp;
  if (body !== resp.body) headers = setHeader(headers, 'Content-Length', body.length);
  return { ...resp, status, statusMessage, headers, body };
}

const TEMPLATE_ACTION = { id: '', phase: 'request', type: 'header', op: 'set', name: '', value: '', find: '', replace: '', regex: false };

module.exports = { applyRequest, applyResponse, TEMPLATE_ACTION };
