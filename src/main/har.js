// HAR 1.2 export/import + native session format.
const { getHeader, isTextual } = require('./proxy/http-util');

function toHar(flows, version) {
  const entries = flows.filter((f) => !f.tunnel).map((f) => {
    const u = safeURL(f.url);
    const reqCT = getHeader(f.reqHeaders, 'content-type') || '';
    const resCT = getHeader(f.resHeaders, 'content-type') || '';
    const t = f.timing;
    const total = t.end ? t.end - t.start : -1;
    const content = { size: f.resBody ? f.resBody.length : 0, mimeType: resCT };
    if (f.resBody && f.resBody.length) {
      if (isTextual(resCT)) content.text = f.resBody.toString('utf8');
      else { content.text = f.resBody.toString('base64'); content.encoding = 'base64'; }
    }
    return {
      startedDateTime: new Date(t.start).toISOString(),
      time: total,
      request: {
        method: f.method,
        url: f.url,
        httpVersion: `HTTP/${f.httpVersion}`,
        headers: f.reqHeaders.map(([name, value]) => ({ name, value })),
        queryString: u ? [...u.searchParams].map(([name, value]) => ({ name, value })) : [],
        cookies: [],
        headersSize: -1,
        bodySize: f.reqBody ? f.reqBody.length : 0,
        ...(f.reqBody && f.reqBody.length ? { postData: { mimeType: reqCT, text: f.reqBody.toString('utf8') } } : {}),
      },
      response: {
        status: f.status || 0,
        statusText: f.statusMessage || '',
        httpVersion: `HTTP/${f.httpVersion}`,
        headers: f.resHeaders.map(([name, value]) => ({ name, value })),
        cookies: [],
        content,
        redirectURL: getHeader(f.resHeaders, 'location') || '',
        headersSize: -1,
        bodySize: f.resSize || 0,
        ...(f.error ? { _error: f.error } : {}),
      },
      cache: {},
      timings: {
        send: t.sent ? Math.max(0, t.sent - t.start) : 0,
        wait: t.firstByte && t.sent ? t.firstByte - t.sent : 0,
        receive: t.end && t.firstByte ? t.end - t.firstByte : 0,
      },
      ...(f.ws ? { _webSocketMessages: f.wsMessages.map((m) => ({ type: m.dir === 'out' ? 'send' : 'receive', time: m.time / 1000, opcode: m.type === 'text' ? 1 : 2, data: m.text ?? m.base64 })) } : {}),
    };
  });
  return { log: { version: '1.2', creator: { name: 'Rae Proxy', version }, entries } };
}

function fromHar(har) {
  return (har.log?.entries || []).map((e) => {
    const start = Date.parse(e.startedDateTime) || Date.now();
    const u = safeURL(e.request.url);
    const c = e.response?.content || {};
    const resBody = c.text ? (c.encoding === 'base64' ? c.text : Buffer.from(c.text).toString('base64')) : null;
    return {
      method: e.request.method,
      url: e.request.url,
      httpVersion: String(e.request.httpVersion || '1.1').replace(/^HTTP\//i, ''),
      scheme: u ? u.protocol.replace(':', '') : 'http',
      host: u ? u.hostname : '',
      port: u ? u.port : '',
      path: u ? u.pathname + u.search : e.request.url,
      clientAddr: '',
      reqHeaders: (e.request.headers || []).map((h) => [h.name, h.value]),
      reqBody: e.request.postData?.text ? Buffer.from(e.request.postData.text).toString('base64') : '',
      status: e.response?.status || null,
      statusMessage: e.response?.statusText || '',
      resHeaders: (e.response?.headers || []).map((h) => [h.name, h.value]),
      resBody,
      resSize: e.response?.bodySize > 0 ? e.response.bodySize : c.size || 0,
      state: e.response?.status ? 'done' : 'error',
      error: e.response?._error || null,
      tags: [],
      ws: !!e._webSocketMessages,
      wsMessages: e._webSocketMessages ? e._webSocketMessages.map((m) => ({ dir: m.type === 'send' ? 'out' : 'in', time: m.time * 1000, type: m.opcode === 1 ? 'text' : 'binary', text: m.opcode === 1 ? m.data : undefined, base64: m.opcode !== 1 ? m.data : undefined, length: (m.data || '').length })) : undefined,
      tunnel: false,
      timing: { start, sent: start + (e.timings?.send || 0), firstByte: start + (e.timings?.send || 0) + (e.timings?.wait || 0), end: e.time >= 0 ? start + e.time : start },
    };
  });
}

function toSession(flows) {
  return {
    format: 'rae-proxy-session',
    version: 1,
    flows: flows.map((f) => ({ ...f, recorded: undefined, reqBody: f.reqBody ? f.reqBody.toString('base64') : '', resBody: f.resBody ? f.resBody.toString('base64') : null })),
  };
}

function safeURL(s) {
  try { return new URL(s); } catch { return null; }
}

module.exports = { toHar, fromHar, toSession };
