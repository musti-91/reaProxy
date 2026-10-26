// JavaScript scripting tool: user scripts define onRequest / onResponse hooks.
const vm = require("vm");
const { getHeader, isTextual, setHeader } = require("./http-util");

const TEMPLATE = `/// Rae Proxy script
/// Runs on every request/response that matches this rule.
/// Return the (modified) object. Objects assigned to body are JSON-encoded.

async function onRequest(context, url, request) {
  // request.headers["X-Debug"] = "1";
  // request.queries["page"] = "2";
  // request.method = "POST";
  return request;
}

async function onResponse(context, url, request, response) {
  // response.statusCode = 200;
  // response.headers["Cache-Control"] = "no-store";
  // if (typeof response.body === "object") response.body.injected = true;
  return response;
}
`;

const sharedState = {};
const compiled = new Map();

function contextFor(rule, log) {
  const key = rule.id + ":" + rule.code;
  let entry = compiled.get(key);
  if (!entry) {
    const sandbox = {
      console: {
        log: (...a) => log(rule, "log", a),
        info: (...a) => log(rule, "info", a),
        warn: (...a) => log(rule, "warn", a),
        error: (...a) => log(rule, "error", a),
      },
      sharedState,
      URL,
      URLSearchParams,
      TextEncoder,
      TextDecoder,
      atob,
      btoa,
      setTimeout,
      clearTimeout,
    };
    const ctx = vm.createContext(sandbox);
    new vm.Script(rule.code || "", {
      filename: `${rule.name || "script"}.js`,
    }).runInContext(ctx, { timeout: 2000 });
    entry = ctx;
    for (const k of compiled.keys())
      if (k.startsWith(rule.id + ":")) compiled.delete(k);
    compiled.set(key, entry);
  }
  return entry;
}

function parseBody(buf, contentType) {
  if (!buf || !buf.length) return "";
  if (!isTextual(contentType)) return null;
  const text = buf.toString("utf8");
  if (/json/i.test(contentType || "")) {
    try {
      return JSON.parse(text);
    } catch {}
  }
  return text;
}

function encodeBody(body, original) {
  if (body === null || body === undefined) return original;
  if (Buffer.isBuffer(body)) return body;
  if (typeof body === "object") return Buffer.from(JSON.stringify(body));
  return Buffer.from(String(body));
}

function headersToObject(pairs) {
  const o = {};
  for (const [k, v] of pairs) o[k] = k in o ? o[k] + ", " + v : v;
  return o;
}

function objectToPairs(obj) {
  return Object.entries(obj || {})
    .filter(([, v]) => v !== undefined && v !== null)
    .map(([k, v]) => [k, String(v)]);
}

function withTimeout(p, ms) {
  return Promise.race([
    p,
    new Promise((_, rej) =>
      setTimeout(() => rej(new Error(`Script timed out after ${ms}ms`)), ms),
    ),
  ]);
}

async function runRequest(rule, r, log) {
  const ctx = contextFor(rule, log);
  if (typeof ctx.onRequest !== "function") return r;
  const u = new URL(r.url);
  const queries = Object.fromEntries(u.searchParams);
  const ct = getHeader(r.headers, "content-type");
  const req = {
    method: r.method,
    url: r.url,
    scheme: u.protocol.replace(":", ""),
    host: u.hostname,
    port: u.port,
    path: u.pathname,
    queries: { ...queries },
    headers: headersToObject(r.headers),
    body: parseBody(r.body, ct),
  };
  const snapshot = JSON.stringify({
    q: req.queries,
    h: req.host,
    p: req.path,
    s: req.scheme,
    port: req.port,
  });
  const out =
    (await withTimeout(
      Promise.resolve(
        ctx.onRequest({ rule: rule.name, sharedState }, r.url, req),
      ),
      10000,
    )) || req;
  let url = out.url;
  if (
    url === r.url &&
    JSON.stringify({
      q: out.queries,
      h: out.host,
      p: out.path,
      s: out.scheme,
      port: out.port,
    }) !== snapshot
  ) {
    const nu = new URL(r.url);
    nu.protocol = out.scheme + ":";
    nu.hostname = out.host;
    nu.port = out.port || "";
    nu.pathname = out.path;
    nu.search = new URLSearchParams(out.queries || {}).toString();
    url = nu.toString();
  }
  const bodyChanged =
    out.body !== req.body ||
    (typeof out.body === "object" && out.body !== null);
  let headers = objectToPairs(out.headers);
  const body = bodyChanged ? encodeBody(out.body, r.body) : r.body;
  if (bodyChanged) headers = setHeader(headers, "Content-Length", body.length);
  return {
    ...r,
    method: (out.method || r.method).toUpperCase(),
    url,
    headers,
    body,
  };
}

async function runResponse(rule, r, resp, log) {
  const ctx = contextFor(rule, log);
  if (typeof ctx.onResponse !== "function") return resp;
  const ct = getHeader(resp.headers, "content-type");
  const req = {
    method: r.method,
    url: r.url,
    headers: headersToObject(r.headers),
    body: parseBody(r.body, getHeader(r.headers, "content-type")),
  };
  const res = {
    statusCode: resp.status,
    headers: headersToObject(resp.headers),
    body: parseBody(resp.body, ct),
  };
  const origBody = res.body;
  const out =
    (await withTimeout(
      Promise.resolve(
        ctx.onResponse({ rule: rule.name, sharedState }, r.url, req, res),
      ),
      10000,
    )) || res;
  const bodyChanged =
    out.body !== origBody ||
    (typeof out.body === "object" && out.body !== null);
  return {
    ...resp,
    status: Number(out.statusCode) || resp.status,
    statusMessage:
      Number(out.statusCode) !== resp.status ? undefined : resp.statusMessage,
    headers: objectToPairs(out.headers),
    body: bodyChanged ? encodeBody(out.body, resp.body) : resp.body,
  };
}

module.exports = { TEMPLATE, runRequest, runResponse };
