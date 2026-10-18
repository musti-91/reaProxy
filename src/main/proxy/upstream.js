// Outbound connections: direct, or through an upstream HTTP proxy (Charles: External Proxy).
const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const { hostMatches } = require('../match');

const DEFAULT_BYPASS = ['localhost', '127.0.0.1', '::1', '*.local'];

class Upstream {
  // getCfg() returns the full app config; getPassword() returns the decrypted upstream password.
  constructor(getCfg, getPassword = () => '') {
    this.getCfg = getCfg;
    this.getPassword = getPassword;
    this.agentCache = new Map();
  }

  get settings() {
    return this.getCfg().upstreamProxy || {};
  }

  // Returns { host, port, auth } for the proxy to use for this target, or null to go direct.
  route(host, secure) {
    const s = this.settings;
    if (!s.enabled) return null;
    const bypass = [...DEFAULT_BYPASS, ...(s.bypass || [])];
    if (bypass.some((p) => hostMatches(p, host))) return null;
    const useHttps = secure && !s.sameForHttps && s.httpsHost;
    const proxyHost = useHttps ? s.httpsHost : s.host;
    const proxyPort = Number(useHttps ? s.httpsPort : s.port);
    if (!proxyHost || !proxyPort) return null;
    // Never chain Rae to itself (e.g. after importing settings while System Proxy is on).
    if (/^(127\.|localhost$|::1$)/.test(proxyHost) && proxyPort === Number(this.getCfg().port)) return null;
    const password = s.password ?? this.getPassword();
    const auth = s.username ? 'Basic ' + Buffer.from(`${s.username}:${password || ''}`).toString('base64') : null;
    return { host: proxyHost, port: proxyPort, auth, label: `${proxyHost}:${proxyPort}` };
  }

  // Raw TCP socket to host:port (via CONNECT when routed through a proxy).
  connect(host, port, { secure = true, timeout = 30000 } = {}) {
    const via = this.route(host, secure);
    if (!via) {
      return new Promise((resolve, reject) => {
        const s = net.connect({ host, port });
        s.setTimeout(timeout, () => s.destroy(new Error(`Connection to ${host}:${port} timed out`)));
        s.once('connect', () => { s.setTimeout(0); resolve(s); });
        s.once('error', reject);
      });
    }
    return new Promise((resolve, reject) => {
      const target = `${net.isIPv6(host) ? `[${host}]` : host}:${port}`;
      const headers = { Host: target, 'Proxy-Connection': 'Keep-Alive' };
      if (via.auth) headers['Proxy-Authorization'] = via.auth;
      const req = http.request({ host: via.host, port: via.port, method: 'CONNECT', path: target, headers, agent: false, timeout });
      req.once('connect', (res, socket, head) => {
        if (res.statusCode !== 200) {
          socket.destroy();
          return reject(upstreamError(via, res.statusCode, res.statusMessage));
        }
        if (head && head.length) socket.unshift(head);
        resolve(socket);
      });
      req.once('timeout', () => req.destroy(new Error(`Upstream proxy ${via.label} timed out`)));
      req.once('error', (e) => reject(new Error(`Upstream proxy ${via.label}: ${e.message}`)));
      req.end();
    });
  }

  // TLS socket to host:port. `alpn` lists protocols to offer (default http/1.1 only).
  async connectTLS(host, port, { servername, rejectUnauthorized = true, alpn = ['http/1.1'], ca } = {}) {
    const raw = await this.connect(host, port, { secure: true });
    return new Promise((resolve, reject) => {
      const s = tls.connect({ socket: raw, servername: servername || (net.isIP(host) ? undefined : host), rejectUnauthorized, ALPNProtocols: alpn, ...(ca ? { ca } : {}) });
      s.once('secureConnect', () => resolve(s));
      s.once('error', (e) => { raw.destroy(); reject(e); });
    });
  }

  // Agents for http(s).request. Rebuilt when proxy settings change.
  agents(rejectUnauthorized, ca) {
    const key = JSON.stringify([this.settings, rejectUnauthorized, !!ca]);
    let a = this.agentCache.get(key);
    if (a) return a;
    for (const old of this.agentCache.values()) { old.http.destroy(); old.https.destroy(); old.proxyHttp.destroy(); }
    this.agentCache.clear();
    const self = this;
    class TunnelingAgent extends https.Agent {
      createConnection(opts, cb) {
        self.connectTLS(opts.host, opts.port, { servername: opts.servername, rejectUnauthorized, ca }).then((s) => cb(null, s), cb);
      }
    }
    a = {
      http: new http.Agent({ keepAlive: true, maxSockets: 256 }),
      https: new TunnelingAgent({ keepAlive: true, maxSockets: 256, rejectUnauthorized }),
      proxyHttp: new http.Agent({ keepAlive: true, maxSockets: 256 }),
    };
    this.agentCache.set(key, a);
    return a;
  }

  // Options for a plain-HTTP request: absolute-URI request to the proxy, or direct.
  httpOptions(u, base, rejectUnauthorized, ca) {
    const via = this.route(u.hostname.replace(/^\[|\]$/g, ''), false);
    const agents = this.agents(rejectUnauthorized, ca);
    if (!via) return { opts: { ...base, agent: agents.http }, via: null };
    const headers = { ...base.headers };
    if (via.auth) headers['Proxy-Authorization'] = via.auth;
    if (!Object.keys(headers).some((k) => k.toLowerCase() === 'host')) headers.Host = u.host;
    return { opts: { ...base, hostname: via.host, port: via.port, path: u.href, headers, agent: agents.proxyHttp, setHost: false }, via };
  }
}

function upstreamError(via, status, message) {
  if (status === 407) return new Error(`Upstream proxy ${via.label} requires authentication (407). Check the username and password in Tools → Upstream Proxy.`);
  return new Error(`Upstream proxy ${via.label} refused the connection: ${status} ${message || ''}`.trim());
}

module.exports = { Upstream, DEFAULT_BYPASS, upstreamError };
