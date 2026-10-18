// HTTP/HTTPS intercepting proxy engine.
const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { EventEmitter } = require('events');
const { hostMatches, findRule, findRules, urlMatches } = require('../match');
const H = require('./http-util');
const scripting = require('./scripting');
const { FrameParser } = require('./ws-frames');
const { BodyStore, attachBodies } = require('./body-store');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const LOCAL_HOSTS = new Set(['rae.proxy', 'cert.rae.proxy', 'proxy.rae']);

class ProxyEngine extends EventEmitter {
  constructor({ ca, config, bodyFile }) {
    super();
    this.ca = ca;
    this.config = config;
    this.store = new BodyStore(bodyFile || path.join(os.tmpdir(), `rae-proxy-bodies-${process.pid}.bin`));
    this.lastBlockedNotice = new Map();
    this.flows = new Map();
    this.seq = 0;
    this.pending = new Map();
    this.servers = [];
    this.reverseServers = new Map();
    this.sockets = new Set();
    this.agents = {
      http: new http.Agent({ keepAlive: true, maxSockets: 256 }),
      https: new https.Agent({ keepAlive: true, maxSockets: 256 }),
    };
    this.status = { running: false, port: null, error: null };

    // Inner server receives decrypted (MITM) traffic and plain traffic tunneled via CONNECT.
    this.inner = http.createServer({ keepAlive: true }, (req, res) => this.handleHttp(req, res, req.socket.__target));
    this.inner.on('upgrade', (req, socket, head) => this.handleUpgrade(req, socket, head, req.socket.__target));
    this.inner.on('clientError', (err, socket) => socket.destroy());
  }

  get cfg() {
    return this.config.get();
  }

  // ---------- lifecycle ----------
  async start() {
    await this.stop();
    const { port, listenAll } = this.cfg;
    const server = http.createServer({ keepAlive: true }, (req, res) => this.handleHttp(req, res, null));
    server.on('connect', (req, socket, head) => this.handleConnect(req, socket, head));
    server.on('upgrade', (req, socket, head) => this.handleUpgrade(req, socket, head, null));
    server.on('clientError', (err, socket) => socket.destroy());
    server.on('connection', (s) => {
      const ip = normalizeIP(s.remoteAddress);
      if (!this.clientAllowed(ip)) {
        s.destroy();
        return this.noticeBlockedClient(ip);
      }
      this.sockets.add(s);
      s.on('close', () => this.sockets.delete(s));
    });
    await new Promise((resolve) => {
      server.once('error', (err) => {
        this.status = { running: false, port, error: err.code === 'EADDRINUSE' ? `Port ${port} is already in use` : err.message };
        resolve();
      });
      server.listen(port, listenAll ? '0.0.0.0' : '127.0.0.1', () => {
        this.status = { running: true, port, error: null };
        this.servers.push(server);
        resolve();
      });
    });
    this.syncReverseProxies();
    this.emit('status', this.status);
    return this.status;
  }

  async stop() {
    for (const s of this.sockets) s.destroy();
    this.sockets.clear();
    await Promise.all(this.servers.map((s) => new Promise((r) => s.close(() => r()))));
    this.servers = [];
    this.status = { running: false, port: null, error: null };
  }

  syncReverseProxies() {
    const wanted = new Map((this.cfg.reverseProxies || []).filter((r) => r.enabled !== false && r.localPort && r.remoteHost).map((r) => [r.id, r]));
    for (const [id, entry] of this.reverseServers) {
      const want = wanted.get(id);
      if (!want || JSON.stringify(want) !== JSON.stringify(entry.rule)) {
        entry.server.close();
        this.reverseServers.delete(id);
      }
    }
    for (const [id, rule] of wanted) {
      if (this.reverseServers.has(id)) continue;
      const target = { host: rule.remoteHost, port: Number(rule.remotePort) || (rule.secure ? 443 : 80), secure: !!rule.secure, reverse: true };
      const server = http.createServer((req, res) => this.handleHttp(req, res, target));
      server.on('upgrade', (req, socket, head) => this.handleUpgrade(req, socket, head, target));
      server.on('error', (err) => this.emit('log', { level: 'error', message: `Reverse proxy :${rule.localPort} — ${err.message}` }));
      server.listen(Number(rule.localPort), '127.0.0.1');
      this.reverseServers.set(id, { server, rule });
    }
  }

  // ---------- LAN access control ----------
  clientAllowed(ip) {
    if (isLoopback(ip)) return true;
    const cfg = this.cfg;
    if (!cfg.listenAll) return false;
    if (ipListMatches(cfg.deniedClients, ip)) return false;
    return ipListMatches(cfg.allowedClients, ip);
  }

  noticeBlockedClient(ip) {
    if (!this.cfg.listenAll || ipListMatches(this.cfg.deniedClients, ip)) return;
    const last = this.lastBlockedNotice.get(ip) || 0;
    if (Date.now() - last < 10000) return;
    this.lastBlockedNotice.set(ip, Date.now());
    this.emit('client:blocked', { ip });
  }

  addresses() {
    const out = [];
    for (const [name, list] of Object.entries(os.networkInterfaces())) {
      for (const a of list || []) if (a.family === 'IPv4' && !a.internal) out.push({ name, address: a.address });
    }
    return out;
  }

  // ---------- flow bookkeeping ----------
  createFlow(init) {
    const u = safeURL(init.url);
    const flow = attachBodies({
      id: ++this.seq,
      method: init.method,
      url: init.url,
      originalUrl: null,
      httpVersion: init.httpVersion || '1.1',
      scheme: u ? u.protocol.replace(':', '') : 'http',
      host: u ? u.hostname : '',
      port: u ? u.port : '',
      path: u ? u.pathname + u.search : init.url,
      clientAddr: (init.clientAddr || '').replace(/^::ffff:/, ''),
      reqHeaders: init.headers || [],
      status: null,
      statusMessage: '',
      resHeaders: [],
      resSize: 0,
      state: 'active',
      error: null,
      tags: [],
      ws: !!init.ws,
      wsMessages: init.ws ? [] : undefined,
      tunnel: !!init.tunnel,
      timing: { start: Date.now(), sent: null, firstByte: null, end: null },
      composed: !!init.composed,
    }, this.store);
    flow.reqBody = init.body || Buffer.alloc(0);
    flow.resBody = null;
    flow.recorded = this.shouldRecord(flow);
    if (flow.recorded) {
      this.flows.set(flow.id, flow);
      this.trim();
      this.emit('flow', flow);
    }
    return flow;
  }

  shouldRecord(flow) {
    const cfg = this.cfg;
    if (!cfg.recording && !flow.composed) return false;
    if (cfg.allowList.enabled && cfg.allowList.rules.some((r) => r.enabled !== false)) {
      return !!findRule(cfg.allowList, flow.method, flow.url);
    }
    return true;
  }

  trim() {
    const max = this.cfg.maxFlows || 20000;
    if (this.flows.size <= max) return;
    while (this.flows.size > max) this.dropFlow(this.flows.keys().next().value);
    this.store.maybeCompact();
  }

  dropFlow(id) {
    const f = this.flows.get(id);
    if (!f) return;
    this.flows.delete(id);
    if (f.state === 'done' || f.state === 'error') f.releaseBodies();
    else f.recorded = false; // in flight: let it finish, but stop tracking it
  }

  deleteFlows(ids) {
    for (const id of ids) this.dropFlow(id);
    this.store.maybeCompact();
  }

  touch(flow) {
    if (flow.recorded) this.emit('flow', flow);
  }

  finish(flow, patch = {}) {
    Object.assign(flow, patch);
    flow.timing.end = Date.now();
    if (flow.state !== 'error') flow.state = 'done';
    this.touch(flow);
    if (!flow.recorded) flow.releaseBodies();
  }

  fail(flow, err, res) {
    flow.state = 'error';
    flow.error = err.message || String(err);
    flow.timing.end = Date.now();
    this.touch(flow);
    if (!flow.recorded) flow.releaseBodies();
    if (res && !res.headersSent && !res.destroyed) {
      const body = Buffer.from(`Rae Proxy error: ${flow.error}\n`);
      try {
        res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8', 'Content-Length': body.length, 'X-Rae-Proxy-Error': '1' });
        res.end(body);
      } catch {}
    } else if (res) res.destroy();
  }

  clear() {
    for (const f of this.flows.values()) f.recorded = false;
    this.flows.clear();
    this.store.reset();
  }

  memoryStats() {
    return { flows: this.flows.size, diskBytes: this.store.diskBytes, liveDiskBytes: this.store.liveBytes };
  }

  // ---------- local pages (cert download for devices) ----------
  serveLocal(req, res) {
    const p = (req.url || '/').replace(/^https?:\/\/[^/]+/i, '');
    if (/^\/(cert|ssl|ca)(\.pem|\.crt)?\/?$/i.test(p)) {
      res.writeHead(200, {
        'Content-Type': 'application/x-x509-ca-cert',
        'Content-Disposition': 'attachment; filename="rae-proxy-ca.pem"',
      });
      return res.end(this.ca.caCertPem);
    }
    const html = `<!doctype html><meta name=viewport content="width=device-width,initial-scale=1"><title>Rae Proxy</title>
<body style="font:16px -apple-system,system-ui;max-width:560px;margin:40px auto;padding:0 16px">
<h1>Rae Proxy is running</h1><p>Install the root certificate on this device to inspect HTTPS traffic.</p>
<p><a href="/cert.pem" style="display:inline-block;padding:12px 20px;background:#ff6b3d;color:#fff;border-radius:10px;text-decoration:none">Download certificate</a></p>
<ol><li>iOS: Settings → General → VPN &amp; Device Management → install profile.</li>
<li>Then Settings → General → About → Certificate Trust Settings → enable full trust for <b>${this.ca.commonName}</b>.</li>
<li>Android: Settings → Security → Encryption &amp; credentials → Install a certificate → CA certificate.</li></ol></body>`;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
  }

  // ---------- plain HTTP / decrypted HTTPS ----------
  async handleHttp(req, res, target) {
    let url;
    if (target) {
      const scheme = target.secure ? 'https' : 'http';
      const defPort = target.secure ? 443 : 80;
      const hostPort = target.reverse || !req.headers.host
        ? `${target.host}${Number(target.port) === defPort ? '' : ':' + target.port}`
        : req.headers.host;
      url = `${scheme}://${hostPort}${req.url}`;
    } else if (/^https?:\/\//i.test(req.url)) {
      url = req.url;
    } else {
      return this.serveLocal(req, res);
    }
    const u = safeURL(url);
    if (!u) {
      res.writeHead(400);
      return res.end('Bad request URL');
    }
    if (LOCAL_HOSTS.has(u.hostname)) return this.serveLocal(req, res);

    let body;
    try {
      body = await H.readBody(req);
    } catch (e) {
      return res.destroy();
    }
    let headers = H.rawToPairs(req.rawHeaders);
    if (target && target.reverse) headers = H.setHeader(headers, 'Host', u.host);
    const flow = this.createFlow({ method: req.method, url, httpVersion: req.httpVersion, headers, body, clientAddr: req.socket.remoteAddress });
    try {
      await this.exchange(flow, res);
    } catch (e) {
      this.fail(flow, e, res);
    }
  }

  // Runs the full rule pipeline for a request and writes the response to `res` (if given).
  async exchange(flow, res) {
    const cfg = this.cfg;
    let r = { method: flow.method, url: flow.url, headers: flow.reqHeaders, body: flow.reqBody };

    // Block list
    const block = findRule(cfg.blockList, r.method, r.url);
    if (block) {
      flow.tags.push('blocked');
      if (block.action === 'drop') {
        if (res) res.destroy();
        return this.fail(flow, new Error('Blocked by Block List (connection dropped)'));
      }
      const resp = { status: 403, statusMessage: 'Forbidden', headers: [['Content-Type', 'text/plain'], ['X-Rae-Proxy', 'blocked']], body: Buffer.from('Blocked by Rae Proxy\n'), modified: true };
      await this.respond(flow, res, resp, r);
      return;
    }

    // Map Remote
    const mr = findRule(cfg.mapRemote, r.method, r.url);
    if (mr) {
      const to = mapRemoteURL(r.url, mr);
      if (to !== r.url) {
        flow.originalUrl = r.url;
        r = { ...r, url: to };
        if (!mr.preserveHost) r.headers = H.setHeader(r.headers, 'Host', new URL(to).host);
        flow.tags.push('map-remote');
      }
    }

    // No caching
    if (cfg.noCache) {
      for (const h of ['If-None-Match', 'If-Modified-Since']) r.headers = H.removeHeader(r.headers, h);
      r.headers = H.setHeader(r.headers, 'Cache-Control', 'no-cache');
      r.headers = H.setHeader(r.headers, 'Pragma', 'no-cache');
    }

    // Scripting (request)
    for (const rule of findRules(cfg.scripting, r.method, r.url, (x) => x.request !== false)) {
      try {
        r = await scripting.runRequest(rule, r, this.scriptLog);
        if (!flow.tags.includes('script')) flow.tags.push('script');
      } catch (e) {
        this.scriptLog(rule, 'error', [e.message]);
      }
    }

    // Breakpoint (request)
    const bpReq = findRule(cfg.breakpoints, r.method, r.url, (x) => x.request);
    if (bpReq) {
      flow.tags.push('breakpoint');
      const edited = await this.pause(flow, 'request', r);
      if (!edited) {
        if (res) res.destroy();
        return this.fail(flow, new Error('Aborted at request breakpoint'));
      }
      r = edited;
    }

    this.applyRequest(flow, r);

    // Map Local or upstream
    let resp;
    const ml = findRule(cfg.mapLocal, r.method, r.url);
    if (ml) {
      flow.tags.push('map-local');
      resp = mapLocalResponse(ml);
      flow.timing.sent = flow.timing.firstByte = Date.now();
    } else {
      resp = await this.upstream(flow, r, res);
      if (resp.streamed) return;
    }

    if (!resp.modified) resp.decoded = H.decodeBody(resp.body, H.getHeader(resp.headers, 'content-encoding'));
    else resp.decoded = resp.body;

    // Scripting (response)
    for (const rule of findRules(cfg.scripting, r.method, r.url, (x) => x.response !== false)) {
      try {
        const before = resp;
        const out = await scripting.runResponse(rule, r, { ...resp, body: resp.decoded }, this.scriptLog);
        resp = { ...out, decoded: out.body, modified: true, rawBody: before.body };
        if (!flow.tags.includes('script')) flow.tags.push('script');
      } catch (e) {
        this.scriptLog(rule, 'error', [e.message]);
      }
    }

    // Breakpoint (response)
    const bpRes = findRule(cfg.breakpoints, r.method, r.url, (x) => x.response);
    if (bpRes) {
      if (!flow.tags.includes('breakpoint')) flow.tags.push('breakpoint');
      const edited = await this.pause(flow, 'response', { status: resp.status, statusMessage: resp.statusMessage, headers: resp.headers, body: resp.decoded });
      if (!edited) {
        if (res) res.destroy();
        return this.fail(flow, new Error('Aborted at response breakpoint'));
      }
      resp = { ...resp, ...edited, decoded: edited.body, modified: true };
    }

    if (resp.modified) {
      resp.headers = H.removeHeader(resp.headers, 'content-encoding');
      resp.body = resp.decoded;
    }
    await this.respond(flow, res, resp, r);
  }

  applyRequest(flow, r) {
    if (r.url !== flow.url && !flow.originalUrl) flow.originalUrl = flow.url;
    const u = safeURL(r.url);
    Object.assign(flow, { method: r.method, url: r.url, reqHeaders: r.headers, reqBody: r.body });
    if (u) Object.assign(flow, { scheme: u.protocol.replace(':', ''), host: u.hostname, port: u.port, path: u.pathname + u.search });
    this.touch(flow);
  }

  async respond(flow, res, resp, r) {
    const cfg = this.cfg;
    const decoded = resp.decoded || (resp.modified ? resp.body : H.decodeBody(resp.body, H.getHeader(resp.headers, 'content-encoding')));
    flow.status = resp.status;
    flow.statusMessage = resp.statusMessage || http.STATUS_CODES[resp.status] || '';
    flow.resHeaders = resp.headers;
    flow.resBody = capBody(decoded, cfg.maxBodySize);
    flow.resSize = resp.body ? resp.body.length : 0;
    flow.timing.firstByte = flow.timing.firstByte || Date.now();

    if (res && !res.destroyed) {
      let headers = H.stripHopByHop(resp.headers);
      const noBody = r.method === 'HEAD' || resp.status === 204 || resp.status === 304 || (resp.status >= 100 && resp.status < 200);
      if (!noBody) headers = H.setHeader(headers, 'Content-Length', resp.body.length);
      const t = cfg.throttle;
      if (t.enabled && t.latency > 0) await sleep(Number(t.latency));
      try {
        res.writeHead(resp.status, resp.statusMessage || undefined, H.pairsToObject(headers));
      } catch (e) {
        res.writeHead(resp.status, H.pairsToObject(headers.filter(([k, v]) => /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(k) && !/[\r\n]/.test(v))));
      }
      if (noBody) res.end();
      else await writeThrottled(res, resp.body, t.enabled ? Number(t.downloadKbps) : 0);
    }
    this.finish(flow);
  }

  upstream(flow, r, clientRes) {
    const cfg = this.cfg;
    return new Promise((resolve, reject) => {
      const u = new URL(r.url);
      const secure = u.protocol === 'https:';
      let headers = H.stripHopByHop(r.headers);
      const hasBody = r.body.length > 0 || ['POST', 'PUT', 'PATCH'].includes(r.method);
      if (hasBody) headers = H.setHeader(headers, 'Content-Length', r.body.length);
      else headers = H.removeHeader(headers, 'Content-Length');
      const opts = {
        method: r.method,
        hostname: u.hostname.replace(/^\[|\]$/g, ''),
        port: u.port || (secure ? 443 : 80),
        path: u.pathname + u.search,
        headers: H.pairsToObject(headers),
        agent: secure ? this.agents.https : this.agents.http,
        setHost: !headers.some(([k]) => k.toLowerCase() === 'host'),
      };
      if (secure) {
        opts.rejectUnauthorized = !!cfg.verifyUpstreamTLS;
        if (!net.isIP(opts.hostname)) opts.servername = opts.hostname;
        opts.agent = cfg.verifyUpstreamTLS ? this.agents.https : (this.agents.httpsInsecure ||= new https.Agent({ keepAlive: true, rejectUnauthorized: false }));
      }
      const up = (secure ? https : http).request(opts, (upRes) => {
        flow.timing.firstByte = Date.now();
        const resHeaders = H.rawToPairs(upRes.rawHeaders);
        const ct = upRes.headers['content-type'] || '';
        const len = Number(upRes.headers['content-length'] || 0);
        if (/text\/event-stream|application\/grpc/i.test(ct) || len > cfg.maxBodySize) {
          return this.streamThrough(flow, upRes, resHeaders, clientRes, cfg).then(() => resolve({ streamed: true }), reject);
        }
        const chunks = [];
        upRes.on('data', (c) => chunks.push(c));
        upRes.on('end', () => resolve({ status: upRes.statusCode, statusMessage: upRes.statusMessage, headers: resHeaders, body: Buffer.concat(chunks), modified: false }));
        upRes.on('error', reject);
      });
      up.on('error', reject);
      up.setTimeout(120000, () => up.destroy(new Error('Upstream timed out after 120s')));
      if (clientRes) clientRes.on('close', () => { if (!clientRes.writableFinished) up.destroy(); });
      flow.timing.sent = Date.now();
      up.end(r.body);
    });
  }

  streamThrough(flow, upRes, resHeaders, clientRes, cfg) {
    flow.status = upRes.statusCode;
    flow.statusMessage = upRes.statusMessage;
    flow.resHeaders = resHeaders;
    flow.tags.push('streamed');
    this.touch(flow);
    if (clientRes) clientRes.writeHead(upRes.statusCode, upRes.statusMessage, H.pairsToObject(H.stripHopByHop(resHeaders)));
    const captured = [];
    let size = 0;
    return new Promise((resolve) => {
      upRes.on('data', (c) => {
        size += c.length;
        if (size <= cfg.maxBodySize) captured.push(c);
        flow.resSize = size;
        if (clientRes) clientRes.write(c);
      });
      const done = () => {
        if (clientRes) clientRes.end();
        flow.resBody = H.decodeBody(Buffer.concat(captured), upRes.headers['content-encoding']);
        this.finish(flow);
        resolve();
      };
      upRes.on('end', done);
      upRes.on('error', done);
    });
  }

  // ---------- breakpoints ----------
  pause(flow, phase, data) {
    return new Promise((resolve) => {
      const id = `${flow.id}:${phase}`;
      flow.state = 'paused';
      this.touch(flow);
      this.pending.set(id, { resolve, phase, data });
      this.emit('breakpoint', {
        id, flowId: flow.id, phase,
        method: data.method, url: data.url, status: data.status, statusMessage: data.statusMessage,
        headers: data.headers,
        body: bodyForEditor(data.body, H.getHeader(data.headers, 'content-type')),
      });
    }).then((result) => {
      flow.state = 'active';
      this.touch(flow);
      return result;
    });
  }

  resolveBreakpoint(id, action, edit) {
    const p = this.pending.get(id);
    if (!p) return false;
    this.pending.delete(id);
    if (action === 'abort') return p.resolve(null), true;
    const base = p.data;
    if (action !== 'execute' || !edit) return p.resolve(base), true;
    const body = edit.bodyText !== undefined && edit.bodyText !== null ? Buffer.from(edit.bodyText) : base.body;
    let headers = edit.headers || base.headers;
    if (p.phase === 'request') {
      if (body.length || H.getHeader(headers, 'content-length')) headers = H.setHeader(headers, 'Content-Length', body.length);
      p.resolve({ method: (edit.method || base.method).toUpperCase(), url: edit.url || base.url, headers, body });
    } else {
      const status = Number(edit.status) || base.status;
      p.resolve({ status, statusMessage: status === base.status ? base.statusMessage : http.STATUS_CODES[status], headers, body });
    }
    return true;
  }

  pendingBreakpoints() {
    return [...this.pending.entries()].map(([id, p]) => ({ id, phase: p.phase }));
  }

  // ---------- CONNECT / tunnels / MITM ----------
  shouldIntercept(host) {
    const ssl = this.cfg.ssl;
    if (LOCAL_HOSTS.has(host)) return true;
    if ((ssl.exclude || []).some((p) => hostMatches(p, host))) return false;
    if (ssl.interceptAll) return true;
    return (ssl.include || []).some((p) => hostMatches(p, host));
  }

  handleConnect(req, clientSocket, head) {
    const [host, portStr] = splitHostPort(req.url);
    const port = Number(portStr) || 443;
    clientSocket.on('error', () => {});

    if (!this.shouldIntercept(host)) return this.tunnel(req, clientSocket, head, host, port);

    clientSocket.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: Rae-Proxy\r\n\r\n');
    if (head && head.length) clientSocket.unshift(head);
    clientSocket.once('readable', () => {
      const chunk = clientSocket.read(1);
      if (!chunk) return clientSocket.destroy();
      clientSocket.unshift(chunk);
      if (chunk[0] === 0x16) {
        // TLS ClientHello → terminate TLS with a certificate for this host
        let sni = null;
        const tlsSocket = new tls.TLSSocket(clientSocket, {
          isServer: true,
          ALPNProtocols: ['http/1.1'],
          secureContext: this.ca.contextFor(host),
          SNICallback: (servername, cb) => {
            sni = servername;
            try { cb(null, this.ca.contextFor(servername || host)); } catch (e) { cb(e); }
          },
        });
        tlsSocket.__target = { host, port, secure: true };
        let secured = false;
        tlsSocket.on('secure', () => { secured = true; });
        tlsSocket.on('error', (err) => {
          if (!secured) this.recordHandshakeFailure(sni || host, port, err, req.socket.remoteAddress);
          tlsSocket.destroy();
        });
        this.inner.emit('connection', tlsSocket);
      } else {
        const plain = wrapSocket(clientSocket);
        plain.__target = { host, port: Number(portStr) || 80, secure: false };
        this.inner.emit('connection', plain);
      }
    });
  }

  tunnel(req, clientSocket, head, host, port) {
    const flow = this.createFlow({ method: 'CONNECT', url: `https://${host}${port === 443 ? '' : ':' + port}`, tunnel: true, headers: H.rawToPairs(req.rawHeaders), clientAddr: req.socket.remoteAddress });
    flow.tags.push('tunnel');
    const upstream = net.connect(port, host, () => {
      flow.status = 200;
      flow.statusMessage = 'Connection Established';
      flow.timing.firstByte = Date.now();
      this.touch(flow);
      clientSocket.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: Rae-Proxy\r\n\r\n');
      if (head && head.length) upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    });
    let bytes = 0;
    upstream.on('data', (c) => { bytes += c.length; });
    const close = () => {
      if (flow.timing.end) return;
      flow.resSize = bytes;
      this.finish(flow);
      upstream.destroy();
      clientSocket.destroy();
    };
    upstream.on('error', (err) => {
      if (!flow.status) {
        this.fail(flow, err);
        try { clientSocket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n'); } catch {}
      } else close();
    });
    upstream.on('close', close);
    clientSocket.on('close', close);
  }

  recordHandshakeFailure(host, port, err, clientAddr) {
    const flow = this.createFlow({ method: 'CONNECT', url: `https://${host}${port === 443 ? '' : ':' + port}`, tunnel: true, clientAddr });
    flow.tags.push('ssl-error');
    const msg = /certificate|unknown ca|bad certificate|alert/i.test(err.message)
      ? `TLS handshake failed — the client does not trust the Rae Proxy certificate or uses certificate pinning (${err.message}). Install & trust the CA, or exclude ${host} from SSL Proxying.`
      : `TLS handshake failed: ${err.message}`;
    this.fail(flow, new Error(msg));
  }

  // ---------- WebSocket ----------
  handleUpgrade(req, clientSocket, head, target) {
    let url;
    if (target) {
      const hostPort = target.reverse || !req.headers.host ? `${target.host}:${target.port}` : req.headers.host;
      url = `${target.secure ? 'wss' : 'ws'}://${hostPort}${req.url}`;
    } else url = req.url.replace(/^http/i, 'ws');
    const u = safeURL(url);
    if (!u) return clientSocket.destroy();
    const secure = u.protocol === 'wss:';
    const port = Number(u.port) || (secure ? 443 : 80);

    // Drop permessage-deflate so frames stay readable in the inspector.
    let headers = H.removeHeader(H.rawToPairs(req.rawHeaders), 'Sec-WebSocket-Extensions');
    if (target && target.reverse) headers = H.setHeader(headers, 'Host', u.host);
    const flow = this.createFlow({ method: req.method, url, headers, ws: true, clientAddr: req.socket.remoteAddress });
    flow.tags.push('websocket');

    const blocked = findRule(this.cfg.blockList, req.method, url);
    if (blocked) {
      flow.tags.push('blocked');
      clientSocket.destroy();
      return this.fail(flow, new Error('Blocked by Block List'));
    }

    const onConnect = () => {
      flow.timing.sent = Date.now();
      const path = u.pathname + u.search;
      const lines = [`${req.method} ${path} HTTP/1.1`, ...headers.map(([k, v]) => `${k}: ${v}`)];
      upstream.write(lines.join('\r\n') + '\r\n\r\n');
      if (head && head.length) upstream.write(head);
    };
    const upstream = secure
      ? tls.connect({ host: u.hostname, port, servername: net.isIP(u.hostname) ? undefined : u.hostname, rejectUnauthorized: !!this.cfg.verifyUpstreamTLS, ALPNProtocols: ['http/1.1'] }, onConnect)
      : net.connect(port, u.hostname, onConnect);

    const record = (dir) => (m) => {
      if (flow.wsMessages.length < 5000) flow.wsMessages.push({ dir, time: Date.now(), ...m });
      flow.resSize += m.length;
      this.touch(flow);
    };
    const inParser = new FrameParser(record('in'));
    const outParser = new FrameParser(record('out'));
    let headerBuf = Buffer.alloc(0);
    let handshakeDone = false;

    upstream.on('data', (chunk) => {
      if (!handshakeDone) {
        headerBuf = Buffer.concat([headerBuf, chunk]);
        const idx = headerBuf.indexOf('\r\n\r\n');
        if (idx === -1) return;
        handshakeDone = true;
        const [statusLine, ...hl] = headerBuf.subarray(0, idx).toString('latin1').split('\r\n');
        const m = statusLine.match(/HTTP\/[\d.]+\s+(\d+)\s*(.*)/);
        flow.status = m ? Number(m[1]) : 0;
        flow.statusMessage = m ? m[2] : '';
        flow.resHeaders = hl.map((l) => { const i = l.indexOf(':'); return [l.slice(0, i).trim(), l.slice(i + 1).trim()]; });
        flow.timing.firstByte = Date.now();
        this.touch(flow);
        clientSocket.write(headerBuf.subarray(0, idx + 4));
        const rest = headerBuf.subarray(idx + 4);
        if (rest.length) { inParser.push(rest); clientSocket.write(rest); }
        return;
      }
      inParser.push(chunk);
      clientSocket.write(chunk);
    });
    clientSocket.on('data', (chunk) => {
      if (handshakeDone) outParser.push(chunk);
      upstream.write(chunk);
    });
    const close = () => {
      upstream.destroy();
      clientSocket.destroy();
      if (!flow.timing.end) this.finish(flow);
    };
    upstream.on('error', (err) => (flow.status ? close() : (this.fail(flow, err), clientSocket.destroy())));
    clientSocket.on('error', close);
    upstream.on('close', close);
    clientSocket.on('close', close);
  }

  // ---------- compose / repeat / import ----------
  async compose({ method, url, headers, body }) {
    if (!safeURL(url)) throw new Error('Invalid URL');
    let pairs = headers || [];
    if (!H.getHeader(pairs, 'host')) pairs = [['Host', new URL(url).host], ...pairs];
    const flow = this.createFlow({ method: (method || 'GET').toUpperCase(), url, headers: pairs, body: Buffer.from(body || ''), composed: true, clientAddr: 'Rae Proxy' });
    flow.tags.push('composed');
    try {
      await this.exchange(flow, null);
    } catch (e) {
      this.fail(flow, e);
    }
    return flow.id;
  }

  repeat(id) {
    const f = this.flows.get(id);
    if (!f) throw new Error('Flow not found');
    return this.compose({ method: f.method, url: f.url, headers: f.reqHeaders, body: f.reqBody });
  }

  importFlows(list) {
    for (const f of list) {
      const { reqBody, resBody, ...rest } = f;
      const flow = attachBodies({
        ...rest,
        id: ++this.seq,
        recorded: true,
        tags: [...(f.tags || []).filter((t) => t !== 'imported'), 'imported'],
      }, this.store);
      flow.reqBody = Buffer.from(reqBody || '', 'base64');
      flow.resBody = resBody != null ? Buffer.from(resBody, 'base64') : null;
      this.flows.set(flow.id, flow);
    }
    this.trim();
  }

  scriptLog = (rule, level, args) => {
    this.emit('log', {
      level,
      source: rule.name || 'script',
      message: args.map((a) => (typeof a === 'string' ? a : safeStringify(a))).join(' '),
      time: Date.now(),
    });
  };
}

// ---------- helpers ----------
function normalizeIP(ip) {
  return String(ip || '').replace(/^::ffff:/i, '');
}

function isLoopback(ip) {
  return ip === '::1' || /^127\./.test(ip);
}

// Entries are exact IPs or IPv4 wildcards like 192.168.1.*
function ipListMatches(list, ip) {
  return (list || []).some((p) => {
    p = String(p).trim();
    if (!p) return false;
    if (!p.includes('*')) return p === ip;
    return new RegExp('^' + p.replace(/\./g, '\\.').replace(/\*/g, '[0-9a-f:]+') + '$', 'i').test(ip);
  });
}

// JS-level duplex around a socket so already-buffered bytes are not bypassed by native consumers.
function wrapSocket(sock) {
  const { Duplex } = require('stream');
  const d = new Duplex({
    read() { sock.resume(); },
    write(chunk, enc, cb) { sock.write(chunk, enc, cb); },
    final(cb) { sock.end(); cb(); },
    destroy(err, cb) { sock.destroy(); cb(err); },
  });
  sock.on('data', (c) => { if (!d.push(c)) sock.pause(); });
  sock.on('end', () => d.push(null));
  sock.on('close', () => d.destroy());
  sock.on('error', (e) => d.destroy(e));
  d.remoteAddress = sock.remoteAddress;
  d.remotePort = sock.remotePort;
  for (const fn of ['setTimeout', 'setNoDelay', 'setKeepAlive', 'ref', 'unref']) d[fn] = () => d;
  return d;
}

function safeURL(s) {
  try { return new URL(s); } catch { return null; }
}

function splitHostPort(s) {
  const m = s.match(/^\[([^\]]+)\]:(\d+)$/) || s.match(/^([^:]+):(\d+)$/);
  return m ? [m[1], m[2]] : [s, '443'];
}

function capBody(buf, max) {
  if (!buf) return buf;
  return buf.length > max ? buf.subarray(0, max) : buf;
}

function safeStringify(v) {
  try { return JSON.stringify(v, null, 2); } catch { return String(v); }
}

function bodyForEditor(buf, ct) {
  if (!buf || !buf.length) return { text: '', binary: false };
  const text = buf.toString('utf8');
  const binary = !H.isTextual(ct) && /[\x00-\x08\x0e-\x1f]/.test(text.slice(0, 2000));
  return binary ? { binary: true, size: buf.length } : { text, binary: false };
}

function mapRemoteURL(url, rule) {
  const u = new URL(url);
  if (rule.toProtocol) u.protocol = rule.toProtocol.replace(/:?$/, ':');
  if (rule.toHost) u.hostname = rule.toHost;
  if (rule.toPort !== undefined && rule.toPort !== '') u.port = String(rule.toPort);
  else if (rule.toHost || rule.toProtocol) u.port = '';
  if (rule.toPath) u.pathname = rule.toPath;
  if (rule.toQuery) u.search = rule.toQuery;
  return u.toString();
}

function mapLocalResponse(rule) {
  let body;
  if (rule.filePath) {
    try { body = fs.readFileSync(rule.filePath); } catch (e) { body = Buffer.from(`Map Local: cannot read ${rule.filePath}: ${e.message}`); }
  } else body = Buffer.from(rule.body || '');
  const headers = String(rule.headers || '')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => { const i = l.indexOf(':'); return [l.slice(0, i).trim(), l.slice(i + 1).trim()]; })
    .filter(([k]) => k);
  if (!H.getHeader(headers, 'content-type')) headers.push(['Content-Type', guessType(rule.filePath, body)]);
  headers.push(['X-Rae-Proxy', 'map-local']);
  const status = Number(rule.status) || 200;
  return { status, statusMessage: http.STATUS_CODES[status], headers, body, modified: true };
}

function guessType(file, body) {
  const ext = (file || '').split('.').pop().toLowerCase();
  const map = { json: 'application/json', html: 'text/html; charset=utf-8', js: 'application/javascript', css: 'text/css', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', svg: 'image/svg+xml', xml: 'application/xml', txt: 'text/plain' };
  if (map[ext]) return map[ext];
  const s = body.toString('utf8', 0, 64).trim();
  return s.startsWith('{') || s.startsWith('[') ? 'application/json' : 'text/plain; charset=utf-8';
}

async function writeThrottled(res, body, kbps) {
  if (!kbps || kbps <= 0) return new Promise((r) => res.end(body, r));
  const perTick = Math.max(64, Math.floor((kbps * 1024) / 8 / 10));
  for (let i = 0; i < body.length && !res.destroyed; i += perTick) {
    res.write(body.subarray(i, i + perTick));
    await sleep(100);
  }
  res.end();
}

module.exports = { ProxyEngine, urlMatches, ipListMatches, TEMPLATE: scripting.TEMPLATE };
