// HTTP/2 client for upstream servers, with one pooled session per origin.
const http2 = require('http2');

const HOP_BY_HOP = new Set(['connection', 'keep-alive', 'proxy-connection', 'proxy-authorization', 'transfer-encoding', 'upgrade', 'host', 'http2-settings']);
const H1_ONLY_TTL = 10 * 60 * 1000;

class H2Client {
  constructor(upstream) {
    this.upstream = upstream;
    this.sessions = new Map(); // key -> Promise<ClientHttp2Session>
    this.h1Only = new Map(); // origin -> timestamp
  }

  // Returns a session, or null if the origin doesn't speak HTTP/2 (caller falls back to HTTP/1.1).
  async session(u, { rejectUnauthorized, ca }) {
    const origin = u.origin;
    const seen = this.h1Only.get(origin);
    if (seen && Date.now() - seen < H1_ONLY_TTL) return null;
    const key = `${origin}|${rejectUnauthorized}|${JSON.stringify(this.upstream.settings)}`;
    let p = this.sessions.get(key);
    if (!p) {
      p = this.open(u, { rejectUnauthorized, ca }).catch((e) => { this.sessions.delete(key); throw e; });
      this.sessions.set(key, p);
      p.then((s) => {
        if (!s) return this.sessions.delete(key);
        const drop = () => { if (this.sessions.get(key) === p) this.sessions.delete(key); };
        s.on('close', drop);
        s.on('goaway', drop);
        s.on('error', drop);
      }, () => {});
    }
    const s = await p;
    if (s && (s.closed || s.destroyed)) {
      this.sessions.delete(key);
      return this.session(u, { rejectUnauthorized, ca });
    }
    return s;
  }

  async open(u, { rejectUnauthorized, ca }) {
    const host = u.hostname.replace(/^\[|\]$/g, '');
    const secure = u.protocol === 'https:';
    const port = Number(u.port) || (secure ? 443 : 80);
    let socket;
    if (secure) {
      socket = await this.upstream.connectTLS(host, port, { rejectUnauthorized, alpn: ['h2', 'http/1.1'], ca });
      if (socket.alpnProtocol !== 'h2') {
        socket.destroy();
        this.h1Only.set(u.origin, Date.now());
        return null;
      }
    } else {
      socket = await this.upstream.connect(host, port, { secure: false }); // h2c prior knowledge
    }
    const session = http2.connect(u.origin, { createConnection: () => socket });
    session.on('error', () => {});
    await new Promise((resolve, reject) => {
      session.once('connect', resolve);
      session.once('error', reject);
    });
    return session;
  }

  // body: Buffer, or a Readable to stream (gRPC).
  async request(u, { method, headers, body, rejectUnauthorized, ca }) {
    const session = await this.session(u, { rejectUnauthorized, ca });
    if (!session) return null;
    const h = {
      ':method': method,
      ':path': u.pathname + u.search,
      ':scheme': u.protocol.replace(':', ''),
      ':authority': u.host,
    };
    for (const [k, v] of headers) {
      const lk = k.toLowerCase();
      if (lk.startsWith(':')) continue;
      if (lk === 'host') { h[':authority'] = v; continue; }
      if (HOP_BY_HOP.has(lk) || (lk === 'te' && String(v).toLowerCase() !== 'trailers')) continue;
      if (lk === 'cookie' && h.cookie) h.cookie += '; ' + v;
      else if (h[lk] !== undefined) h[lk] = [].concat(h[lk], v);
      else h[lk] = v;
    }
    if (Buffer.isBuffer(body) && !body.length && ['GET', 'HEAD', 'DELETE', 'OPTIONS'].includes(method)) delete h['content-length'];
    const stream = session.request(h, { endStream: false });
    return new Promise((resolve, reject) => {
      let trailersResolve;
      const trailers = new Promise((r) => { trailersResolve = r; });
      stream.on('trailers', (t) => trailersResolve(toPairs(t)));
      stream.on('close', () => trailersResolve(null));
      stream.once('response', (hdrs) => {
        resolve({ protocol: 'h2', status: Number(hdrs[':status']), statusMessage: '', headers: toPairs(hdrs), stream, trailers });
      });
      stream.once('error', reject);
      if (Buffer.isBuffer(body)) stream.end(body);
      else body.pipe(stream);
    });
  }

  close() {
    for (const p of this.sessions.values()) p.then((s) => s && s.close(), () => {});
    this.sessions.clear();
  }
}

function toPairs(hdrs) {
  const out = [];
  for (const [k, v] of Object.entries(hdrs || {})) {
    if (k.startsWith(':')) continue;
    for (const one of [].concat(v)) out.push([k, String(one)]);
  }
  return out;
}

module.exports = { H2Client, toPairs };
