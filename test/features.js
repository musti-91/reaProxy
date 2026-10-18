// End-to-end checks for HTTP/2 (incl. gRPC-style streaming), upstream proxy and app detection.
const assert = require('assert');
const http = require('http');
const https = require('https');
const http2 = require('http2');
const net = require('net');
const tls = require('tls');
const os = require('os');
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const { Config } = require('../src/main/config');
const { CertAuthority } = require('../src/main/proxy/ca');
const { ProxyEngine } = require('../src/main/proxy/engine');
const { AppResolver, appFromPath, parseLsof } = require('../src/main/apps');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rae-proxy-features-'));
const ca = new CertAuthority(tmp);
const config = new Config(tmp);
const PORT = 19091;
config.set({ port: PORT, listenAll: false, ssl: { interceptAll: true, exclude: [] }, verifyUpstreamTLS: true, http2: true });
const apps = new AppResolver({ proxyPorts: () => [PORT] });
const engine = new ProxyEngine({ ca, config, extraCA: [ca.caCertPem], resolveApp: (p) => apps.resolve(p) });
const lastFlow = (pred) => [...engine.flows.values()].reverse().find(pred);
const sni = (n, cb) => cb(null, ca.contextFor(n || 'localhost'));

// ---------- upstream test servers ----------
function echoJSON(req, res, extra = {}) {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ proto: req.httpVersion, method: req.method, url: req.url, body, ...extra }));
  });
}

// HTTP/2 server (TLS, ALPN h2 only). /grpc echoes each frame immediately and ends with trailers.
const h2Server = http2.createSecureServer({ SNICallback: sni, allowHTTP1: false }, (req, res) => {
  if (req.url === '/grpc') {
    res.writeHead(200, { 'content-type': 'application/grpc' });
    req.on('data', (c) => res.write(Buffer.concat([Buffer.from('echo:'), c])));
    req.on('end', () => {
      res.addTrailers({ 'grpc-status': '0', 'grpc-message': 'OK' });
      res.end();
    });
    return;
  }
  echoJSON(req, res);
});
const h1Server = https.createServer({ SNICallback: sni }, (req, res) => echoJSON(req, res));
const h2cServer = http2.createServer((req, res) => echoJSON(req, res));

// Upstream proxy requiring Basic auth u:p. Every target host is mapped to 127.0.0.1.
const upstreamStats = { http: 0, connect: 0, hosts: [] };
const AUTH = 'Basic ' + Buffer.from('u:p').toString('base64');
const upstreamProxy = http.createServer((req, res) => {
  if (req.headers['proxy-authorization'] !== AUTH) { res.writeHead(407, { 'Proxy-Authenticate': 'Basic' }); return res.end(); }
  upstreamStats.http++;
  const u = new URL(req.url);
  upstreamStats.hosts.push(u.hostname);
  const headers = { ...req.headers };
  delete headers['proxy-authorization'];
  const up = http.request({ host: '127.0.0.1', port: u.port, path: u.pathname + u.search, method: req.method, headers }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
  up.on('error', () => res.destroy());
  req.pipe(up);
});
upstreamProxy.on('connect', (req, sock, head) => {
  if (req.headers['proxy-authorization'] !== AUTH) return sock.end('HTTP/1.1 407 Proxy Authentication Required\r\n\r\n');
  upstreamStats.connect++;
  upstreamStats.hosts.push(req.url.split(':')[0]);
  const t = net.connect(Number(req.url.split(':').pop()), '127.0.0.1', () => {
    sock.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head.length) t.write(head);
    t.pipe(sock);
    sock.pipe(t);
  });
  t.on('error', () => sock.destroy());
  sock.on('error', () => t.destroy());
});

// ---------- clients ----------
function connectTunnel(hostPort) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: PORT, method: 'CONNECT', path: hostPort });
    req.on('connect', (res, socket) => (res.statusCode === 200 ? resolve(socket) : reject(new Error('CONNECT ' + res.statusCode))));
    req.on('error', reject);
    req.end();
  });
}

// HTTP/2 client through Rae. Returns { alpn, status, headers, body, trailers }.
async function h2ViaProxy(url, { method = 'GET', headers = {}, body, alpn = ['h2'], onStream } = {}) {
  const u = new URL(url);
  const raw = await connectTunnel(`${u.hostname}:${u.port}`);
  let socket = raw;
  if (u.protocol === 'https:') {
    socket = await new Promise((resolve, reject) => {
      const s = tls.connect({ socket: raw, servername: u.hostname, ca: ca.caCertPem, ALPNProtocols: alpn }, () => resolve(s));
      s.on('error', reject);
    });
    if (socket.alpnProtocol !== 'h2') return { alpn: socket.alpnProtocol };
  }
  const session = http2.connect(u.origin, { createConnection: () => socket });
  return new Promise((resolve, reject) => {
    const stream = session.request({ ':method': method, ':path': u.pathname + u.search, ...headers }, { endStream: false });
    const out = { alpn: socket.alpnProtocol || 'h2c', chunks: [], trailers: null };
    stream.on('response', (h) => { out.status = h[':status']; out.headers = h; });
    stream.on('data', (c) => out.chunks.push(c));
    stream.on('trailers', (t) => { out.trailers = t; });
    stream.on('end', () => { out.body = Buffer.concat(out.chunks).toString(); session.close(); resolve(out); });
    stream.on('error', reject);
    session.on('error', reject);
    if (onStream) onStream(stream, out);
    else stream.end(body);
  });
}

function h1ViaProxy(url, { method = 'GET', body } = {}) {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const done = (res) => {
      let b = '';
      res.on('data', (c) => (b += c));
      res.on('end', () => resolve({ status: res.statusCode, body: b }));
    };
    if (u.protocol === 'http:') {
      const req = http.request({ host: '127.0.0.1', port: PORT, method, path: url, headers: { Host: u.host } }, done);
      req.on('error', reject);
      return req.end(body);
    }
    connectTunnel(`${u.hostname}:${u.port}`).then((socket) => {
      const s = tls.connect({ socket, servername: u.hostname, ca: ca.caCertPem, ALPNProtocols: ['http/1.1'] }, () => {
        const req = https.request({ createConnection: () => s, method, path: u.pathname + u.search, headers: { Host: u.host } }, done);
        req.on('error', reject);
        req.end(body);
      });
      s.on('error', reject);
    }, reject);
  });
}

const listen = (srv) => new Promise((r) => srv.listen(0, '127.0.0.1', () => r(srv.address().port)));

(async () => {
  const h2p = await listen(h2Server);
  const h1p = await listen(h1Server);
  const h2cp = await listen(h2cServer);
  const upp = await listen(upstreamProxy);
  assert.ok((await engine.start()).running);

  const results = [];
  const check = async (name, fn) => {
    try {
      await Promise.race([fn(), new Promise((_, rej) => setTimeout(() => rej(new Error('timed out after 10s')), 10000))]);
      results.push(['PASS', name]);
    } catch (e) { results.push(['FAIL', name, e.stack.split('\n').slice(0, 2).join(' ')]); }
    console.log(results[results.length - 1].join('  '));
  };

  // ---------- HTTP/2 ----------
  await check('HTTP/2 client → HTTP/2 server (end to end)', async () => {
    const r = await h2ViaProxy(`https://localhost:${h2p}/h2?x=1`, { method: 'POST', body: 'hello', headers: { 'content-type': 'text/plain' } });
    assert.strictEqual(r.alpn, 'h2', 'Rae negotiates h2 with the client');
    assert.strictEqual(r.status, 200);
    const j = JSON.parse(r.body);
    assert.strictEqual(j.proto, '2.0', 'server received HTTP/2');
    assert.strictEqual(j.body, 'hello');
    const f = lastFlow((x) => x.url.includes('/h2?x=1'));
    assert.strictEqual(f.httpVersion, '2.0');
    assert.strictEqual(f.upstreamProtocol, 'h2');
    assert.ok(f.tags.includes('h2'));
    assert.ok(!f.reqHeaders.some(([k]) => k.startsWith(':')), 'pseudo-headers not shown as headers');
  });

  await check('HTTP/2 client → HTTP/1.1-only server falls back', async () => {
    const r = await h2ViaProxy(`https://localhost:${h1p}/fallback`);
    assert.strictEqual(r.status, 200);
    assert.strictEqual(JSON.parse(r.body).proto, '1.1');
    assert.strictEqual(lastFlow((x) => x.url.endsWith('/fallback')).upstreamProtocol, 'http/1.1');
  });

  await check('HTTP/1.1 client stays HTTP/1.1 upstream', async () => {
    const r = await h1ViaProxy(`https://localhost:${h1p}/h1`);
    assert.strictEqual(JSON.parse(r.body).proto, '1.1');
    const f = lastFlow((x) => x.url.endsWith('/h1'));
    assert.strictEqual(f.httpVersion, '1.1');
    assert.strictEqual(f.upstreamProtocol, 'http/1.1');
  });

  await check('gRPC-style bidirectional streaming + trailers', async () => {
    const r = await h2ViaProxy(`https://localhost:${h2p}/grpc`, {
      method: 'POST',
      headers: { 'content-type': 'application/grpc', te: 'trailers' },
      onStream: (stream, out) => {
        stream.write('one');
        // The echo must arrive before the request ends; buffering the request would deadlock here.
        stream.once('data', () => { out.echoedBeforeEnd = true; stream.end('two'); });
      },
    });
    assert.ok(r.echoedBeforeEnd, 'response streamed while request still open');
    assert.strictEqual(r.body, 'echo:oneecho:two');
    assert.strictEqual(r.trailers['grpc-status'], '0', 'trailers forwarded to client');
    const f = lastFlow((x) => x.url.endsWith('/grpc'));
    assert.strictEqual(f.reqBody.toString(), 'onetwo', 'request body captured');
    assert.ok(f.resTrailers.some(([k, v]) => k === 'grpc-status' && v === '0'));
    assert.ok(f.tags.includes('streamed'));
  });

  await check('Cleartext HTTP/2 (h2c prior knowledge) via CONNECT', async () => {
    const r = await h2ViaProxy(`http://localhost:${h2cp}/h2c`);
    assert.strictEqual(r.status, 200);
    assert.strictEqual(JSON.parse(r.body).proto, '2.0');
    assert.strictEqual(lastFlow((x) => x.url.endsWith('/h2c')).upstreamProtocol, 'h2');
  });

  await check('HTTP/2 can be switched off', async () => {
    config.set({ http2: false });
    const r = await h2ViaProxy(`https://localhost:${h2p}/off`, { alpn: ['h2', 'http/1.1'] });
    assert.strictEqual(r.alpn, 'http/1.1', 'only http/1.1 offered');
    config.set({ http2: true });
  });

  // ---------- upstream proxy ----------
  const useUpstream = (extra = {}) => config.set({ upstreamProxy: { enabled: true, host: '127.0.0.1', port: upp, sameForHttps: true, username: 'u', password: 'p', bypass: [], ...extra } });

  await check('Upstream proxy: plain HTTP (absolute-URI request with auth)', async () => {
    useUpstream();
    const before = upstreamStats.http;
    const plain = http.createServer((req, res) => echoJSON(req, res));
    const pp = await listen(plain);
    const r = await h1ViaProxy(`http://corp-http.test:${pp}/via`);
    assert.strictEqual(r.status, 200);
    assert.strictEqual(upstreamStats.http, before + 1);
    assert.strictEqual(lastFlow((x) => x.url.endsWith('/via')).via, `127.0.0.1:${upp}`);
    plain.close();
  });

  await check('Upstream proxy: decrypted HTTPS, HTTP/2 and tunnels use CONNECT', async () => {
    const before = upstreamStats.connect;
    const r1 = await h1ViaProxy(`https://corp-h1.test:${h1p}/mitm`);
    assert.strictEqual(JSON.parse(r1.body).url, '/mitm');
    const r2 = await h2ViaProxy(`https://corp-h2.test:${h2p}/mitm2`);
    assert.strictEqual(JSON.parse(r2.body).proto, '2.0');
    config.set({ ssl: { interceptAll: false, include: [], exclude: [] } });
    const sock = await connectTunnel(`corp-tunnel.test:${h1p}`);
    sock.destroy();
    config.set({ ssl: { interceptAll: true } });
    assert.ok(upstreamStats.connect >= before + 3, `CONNECTs through upstream: ${upstreamStats.connect - before}`);
    assert.ok(['corp-h1.test', 'corp-h2.test', 'corp-tunnel.test'].every((h) => upstreamStats.hosts.includes(h)));
  });

  await check('Upstream proxy: WebSocket goes through it', async () => {
    const wsServer = http.createServer();
    wsServer.on('upgrade', (req, sock) => {
      const accept = require('crypto').createHash('sha1').update(req.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
      sock.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    });
    const wp = await listen(wsServer);
    const before = upstreamStats.connect;
    const status = await new Promise((resolve, reject) => {
      const s = net.connect(PORT, '127.0.0.1', () => s.write(`GET http://corp-ws.test:${wp}/ws HTTP/1.1\r\nHost: corp-ws.test:${wp}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n`));
      s.once('data', (d) => { resolve(d.toString().split(' ')[1]); s.destroy(); });
      s.on('error', reject);
    });
    assert.strictEqual(status, '101');
    assert.strictEqual(upstreamStats.connect, before + 1);
    wsServer.close();
  });

  await check('Upstream proxy: wrong password gives a clear 407 error', async () => {
    useUpstream({ password: 'wrong' });
    const r = await h1ViaProxy(`https://corp-auth.test:${h1p}/auth`);
    assert.strictEqual(r.status, 502);
    assert.match(lastFlow((x) => x.url.includes('corp-auth.test')).error, /requires authentication \(407\)/);
  });

  await check('Upstream proxy: bypass list goes direct', async () => {
    useUpstream({ bypass: ['*.direct.test'] });
    const before = upstreamStats.connect + upstreamStats.http;
    await h1ViaProxy(`https://a.direct.test:${h1p}/direct`).catch(() => {});
    assert.strictEqual(upstreamStats.connect + upstreamStats.http, before, 'not sent to upstream');
    const f = lastFlow((x) => x.url.includes('a.direct.test'));
    assert.strictEqual(f.via, null);
    config.set({ upstreamProxy: { enabled: false } });
  });

  await check('Upstream proxy: import from macOS settings ignores Rae itself', async () => {
    const { detectUpstreamProxy } = require('../src/main/system');
    const corp = { enabled: true, server: 'proxy.corp', port: '3128' };
    const rae = { enabled: true, server: '127.0.0.1', port: '9090' };
    const off = { enabled: false, server: '', port: '0' };
    assert.strictEqual(await detectUpstreamProxy([{ service: 'Wi-Fi', web: rae, secure: rae, bypass: [] }]), null);
    const found = await detectUpstreamProxy([
      { service: 'Wi-Fi', web: off, secure: off, bypass: [] },
      { service: 'Ethernet', web: corp, secure: corp, bypass: ['*.local', '*.corp.internal'] },
    ]);
    assert.deepStrictEqual(found, { service: 'Ethernet', host: 'proxy.corp', port: 3128, sameForHttps: true, httpsHost: '', httpsPort: '', bypass: ['*.corp.internal'] });
    // Rae never chains to itself
    config.set({ upstreamProxy: { enabled: true, host: '127.0.0.1', port: PORT } });
    assert.strictEqual(engine.upstreamConn.route('example.com', true), null);
    config.set({ upstreamProxy: { enabled: false } });
  });

  // ---------- app names ----------
  await check('App helpers: bundle name from executable path', async () => {
    assert.deepStrictEqual(appFromPath('/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper'), { name: 'Google Chrome', bundle: '/Applications/Google Chrome.app' });
    assert.deepStrictEqual(appFromPath('/usr/bin/curl'), { name: 'curl', bundle: null });
    assert.deepStrictEqual(appFromPath('/Applications/Slack.app/Contents/MacOS/Slack'), { name: 'Slack', bundle: '/Applications/Slack.app' });
    assert.deepStrictEqual(appFromPath('/Applications/Xcode.app/Contents/Developer/usr/bin/git'), { name: 'git', bundle: null });
    const py = '/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app';
    assert.deepStrictEqual(appFromPath(py + '/Contents/MacOS/Python'), { name: 'Python', bundle: py });
    assert.strictEqual(appFromPath('/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)').name, 'Visual Studio Code');
    assert.strictEqual(appFromPath('/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking').name, 'Safari / WebKit');
    assert.deepStrictEqual(parseLsof('p12\nf5\nn127.0.0.1:5000->127.0.0.1:9090\np34\nf9\nn127.0.0.1:9090->127.0.0.1:5000\n'), [
      { pid: 12, local: '127.0.0.1:5000', remote: '127.0.0.1:9090' },
      { pid: 34, local: '127.0.0.1:9090', remote: '127.0.0.1:5000' },
    ]);
  });

  if (process.platform === 'darwin') {
    await check('App detection: a real curl process is identified', async () => {
      // Lookup takes ~50 ms; real apps keep connections open far longer than a local one-shot curl.
      const plain = http.createServer((req, res) => setTimeout(() => echoJSON(req, res), 500));
      const pp = await listen(plain);
      await new Promise((resolve, reject) => execFile('curl', ['-s', '-x', `http://127.0.0.1:${PORT}`, `http://localhost:${pp}/from-curl`], (e) => (e ? reject(e) : resolve())));
      await new Promise((r) => setTimeout(r, 300));
      const f = lastFlow((x) => x.url.endsWith('/from-curl'));
      assert.strictEqual(f.app, 'curl', `app=${f.app} path=${f.appPath}`);
      assert.match(f.appPath, /curl$/);
      plain.close();
    });
  }

  await engine.stop();
  engine.store.close();
  engine.h2client.close();
  for (const s of [h2Server, h1Server, h2cServer, upstreamProxy]) s.close();
  process.exit(results.some((r) => r[0] === 'FAIL') ? 1 : 0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
