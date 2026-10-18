// Headless end-to-end checks for the proxy engine (run with: npm test)
const assert = require('assert');
const http = require('http');
const https = require('https');
const tls = require('tls');
const zlib = require('zlib');
const os = require('os');
const fs = require('fs');
const path = require('path');
const { Config } = require('../src/main/config');
const { CertAuthority } = require('../src/main/proxy/ca');
const { ProxyEngine } = require('../src/main/proxy/engine');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rae-proxy-test-'));
const ca = new CertAuthority(tmp);
const config = new Config(tmp);
const PORT = 19090;
config.set({ port: PORT, listenAll: false, ssl: { interceptAll: true, exclude: [] }, verifyUpstreamTLS: true });
const engine = new ProxyEngine({ ca, config });

function handler(req, res) {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    if (req.url === '/gzip') {
      const z = zlib.gzipSync(JSON.stringify({ hello: 'gzip' }));
      res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' });
      return res.end(z);
    }
    res.writeHead(200, { 'Content-Type': 'application/json', 'X-Upstream': '1' });
    res.end(JSON.stringify({ method: req.method, url: req.url, body, xdebug: req.headers['x-debug'] || null }));
  });
}

const plainServer = http.createServer(handler);
// Upstream HTTPS server uses a cert issued by our CA for "localhost"
const ctx = ca.contextFor('localhost');
const secureServer = https.createServer({ SNICallback: (n, cb) => cb(null, ctx) }, handler);

function viaProxy(url, { method = 'GET', body, headers = {} } = {}) {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const done = (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    };
    if (u.protocol === 'http:') {
      const req = http.request({ host: '127.0.0.1', port: PORT, method, path: url, headers: { Host: u.host, ...headers } }, done);
      req.on('error', reject);
      return req.end(body);
    }
    const connect = http.request({ host: '127.0.0.1', port: PORT, method: 'CONNECT', path: `${u.hostname}:${u.port || 443}` });
    connect.on('connect', (res, socket) => {
      const tlsSock = tls.connect({ socket, servername: u.hostname, ca: ca.caCertPem }, () => {
        const req = https.request({ createConnection: () => tlsSock, method, path: u.pathname + u.search, headers: { Host: u.host, ...headers } }, done);
        req.on('error', reject);
        req.end(body);
      });
      tlsSock.on('error', reject);
    });
    connect.on('error', reject);
    connect.end();
  });
}

(async () => {
  await new Promise((r) => plainServer.listen(0, '127.0.0.1', r));
  await new Promise((r) => secureServer.listen(0, '127.0.0.1', r));
  const hp = plainServer.address().port;
  const sp = secureServer.address().port;
  // upstream cert is signed by our CA; trust it for this test via NODE_EXTRA_CA_CERTS-equivalent
  engine.agents.https.options.ca = [ca.caCertPem];

  const st = await engine.start();
  assert.ok(st.running, 'proxy should start: ' + st.error);
  const results = [];
  const check = async (name, fn) => {
    try { await fn(); results.push(['PASS', name]); } catch (e) { results.push(['FAIL', name, e.message]); }
  };

  await check('plain HTTP GET', async () => {
    const r = await viaProxy(`http://localhost:${hp}/hello?x=1`);
    assert.strictEqual(r.status, 200);
    assert.strictEqual(JSON.parse(r.body).url, '/hello?x=1');
  });

  await check('HTTP POST body forwarded', async () => {
    const r = await viaProxy(`http://localhost:${hp}/post`, { method: 'POST', body: 'abc', headers: { 'Content-Type': 'text/plain' } });
    assert.strictEqual(JSON.parse(r.body).body, 'abc');
  });

  await check('HTTPS MITM GET', async () => {
    const r = await viaProxy(`https://localhost:${sp}/secure`);
    assert.strictEqual(r.status, 200);
    assert.strictEqual(JSON.parse(r.body).url, '/secure');
    const f = [...engine.flows.values()].find((x) => x.url.endsWith('/secure'));
    assert.ok(f && f.scheme === 'https' && f.status === 200, 'flow recorded as https');
  });

  await check('gzip body decoded for inspection, forwarded intact', async () => {
    const r = await viaProxy(`http://localhost:${hp}/gzip`, { headers: { 'Accept-Encoding': 'gzip' } });
    assert.strictEqual(r.headers['content-encoding'], 'gzip');
    const f = [...engine.flows.values()].find((x) => x.url.endsWith('/gzip'));
    assert.strictEqual(JSON.parse(f.resBody.toString()).hello, 'gzip');
  });

  await check('Map Local', async () => {
    config.set({ mapLocal: { enabled: true, rules: [{ id: 'm1', pattern: '*/mocked', status: 201, headers: 'Content-Type: application/json', body: '{"mock":true}' }] } });
    const r = await viaProxy(`https://localhost:${sp}/mocked`);
    assert.strictEqual(r.status, 201);
    assert.deepStrictEqual(JSON.parse(r.body), { mock: true });
  });

  await check('Block List', async () => {
    config.set({ blockList: { enabled: true, rules: [{ id: 'b1', pattern: '*/blocked*' }] } });
    const r = await viaProxy(`http://localhost:${hp}/blocked`);
    assert.strictEqual(r.status, 403);
  });

  await check('Map Remote', async () => {
    config.set({ mapRemote: { enabled: true, rules: [{ id: 'r1', pattern: 'http://example.invalid/*', toProtocol: 'http', toHost: 'localhost', toPort: String(hp) }] } });
    const r = await viaProxy('http://example.invalid/remapped');
    assert.strictEqual(JSON.parse(r.body).url, '/remapped');
  });

  await check('Scripting modifies request and response', async () => {
    config.set({
      scripting: {
        enabled: true,
        rules: [{
          id: 's1', name: 'test', pattern: '*/scripted', request: true, response: true,
          code: `async function onRequest(c,u,req){ req.headers['X-Debug']='yes'; return req; }
                 async function onResponse(c,u,req,res){ res.body.injected = true; res.statusCode = 202; return res; }`,
        }],
      },
    });
    const r = await viaProxy(`http://localhost:${hp}/scripted`, { headers: { 'Accept-Encoding': 'identity' } });
    const j = JSON.parse(r.body);
    assert.strictEqual(r.status, 202);
    assert.strictEqual(j.xdebug, 'yes');
    assert.strictEqual(j.injected, true);
  });

  await check('Breakpoint edits request', async () => {
    config.set({ breakpoints: { enabled: true, rules: [{ id: 'bp1', pattern: '*/paused', request: true, response: false }] } });
    const once = (bp) => engine.resolveBreakpoint(bp.id, 'execute', { method: 'PUT', url: bp.url, headers: bp.headers, bodyText: 'edited' });
    engine.once('breakpoint', once);
    const r = await viaProxy(`http://localhost:${hp}/paused`, { method: 'POST', body: 'orig' });
    const j = JSON.parse(r.body);
    assert.strictEqual(j.method, 'PUT');
    assert.strictEqual(j.body, 'edited');
  });

  await check('Compose request', async () => {
    const id = await engine.compose({ method: 'POST', url: `http://localhost:${hp}/composed`, headers: [['Content-Type', 'text/plain']], body: 'hi' });
    const f = engine.flows.get(id);
    assert.strictEqual(f.status, 200);
    assert.strictEqual(JSON.parse(f.resBody.toString()).body, 'hi');
  });

  await check('Tunnel when SSL proxying disabled for host', async () => {
    config.set({ ssl: { interceptAll: false, include: [], exclude: [] } });
    const u = `https://localhost:${sp}/tunneled`;
    // client must now verify the *upstream* cert directly (also CA-signed here) — passes through untouched
    const r = await viaProxy(u);
    assert.strictEqual(r.status, 200);
    const f = [...engine.flows.values()].find((x) => x.tunnel && x.url.includes(String(sp)));
    assert.ok(f, 'tunnel flow recorded');
  });

  await check('WebSocket proxied and frames captured', async () => {
    const net = require('net');
    const crypto = require('crypto');
    const wsServer = http.createServer();
    wsServer.on('upgrade', (req, sock) => {
      const accept = crypto.createHash('sha1').update(req.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
      sock.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
      sock.on('data', (b) => {
        const len = b[1] & 0x7f, mask = b.subarray(2, 6), p = Buffer.from(b.subarray(6, 6 + len));
        for (let i = 0; i < p.length; i++) p[i] ^= mask[i & 3];
        const reply = Buffer.from('echo:' + p.toString());
        sock.write(Buffer.concat([Buffer.from([0x81, reply.length]), reply]));
      });
    });
    await new Promise((r) => wsServer.listen(0, '127.0.0.1', r));
    const wp = wsServer.address().port;
    const reply = await new Promise((resolve, reject) => {
      const s = net.connect(PORT, '127.0.0.1', () => {
        s.write(`GET http://localhost:${wp}/socket HTTP/1.1\r\nHost: localhost:${wp}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n`);
      });
      let buf = Buffer.alloc(0), upgraded = false;
      s.on('data', (c) => {
        buf = Buffer.concat([buf, c]);
        if (!upgraded) {
          const i = buf.indexOf('\r\n\r\n');
          if (i === -1) return;
          upgraded = true;
          buf = buf.subarray(i + 4);
          const payload = Buffer.from('hi'), mask = Buffer.from([1, 2, 3, 4]);
          const masked = Buffer.from(payload.map((b, j) => b ^ mask[j & 3]));
          s.write(Buffer.concat([Buffer.from([0x81, 0x80 | payload.length]), mask, masked]));
        }
        if (buf.length >= 2 && buf.length >= 2 + (buf[1] & 0x7f)) { resolve(buf.subarray(2, 2 + (buf[1] & 0x7f)).toString()); s.destroy(); }
      });
      s.on('error', reject);
      setTimeout(() => reject(new Error('ws timeout')), 5000);
    });
    assert.strictEqual(reply, 'echo:hi');
    await new Promise((r) => setTimeout(r, 100));
    const f = [...engine.flows.values()].find((x) => x.ws);
    assert.ok(f && f.status === 101, 'ws flow recorded with 101');
    assert.deepStrictEqual(f.wsMessages.map((m) => [m.dir, m.text]), [['out', 'hi'], ['in', 'echo:hi']]);
    wsServer.close();
  });

  await check('Cert download page', async () => {
    const r = await viaProxy('http://rae.proxy/cert.pem');
    assert.ok(r.body.includes('BEGIN CERTIFICATE'));
  });

  // ---------- memory: disk-backed bodies ----------
  await check('Large bodies are stored on disk, not in RAM', async () => {
    const big = 'x'.repeat(200 * 1024);
    const r = await viaProxy(`http://localhost:${hp}/big`, { method: 'POST', body: big, headers: { 'Content-Type': 'text/plain' } });
    assert.strictEqual(r.status, 200);
    const f = [...engine.flows.values()].find((x) => x.url.endsWith('/big'));
    assert.strictEqual(f.reqBodyLength, big.length);
    assert.strictEqual(f.reqBody.toString(), big, 'body reads back from disk');
    assert.ok(engine.store.liveBytes >= big.length, 'body lives in the store file');
    const own = Object.getOwnPropertyDescriptor(f, 'reqBody');
    assert.ok(own.get && !('value' in own), 'flow holds an accessor, not a Buffer');
  });

  await check('Deleting flows releases disk space; compaction rewrites live bodies', async () => {
    const { BodyStore } = require('../src/main/proxy/body-store');
    const st = new BodyStore(path.join(tmp, 'c.bin'), { inlineMax: 4, compactMinBytes: 1 });
    const a = st.put(Buffer.from('aaaaaaaaaa'));
    const b = st.put(Buffer.from('bbbbbbbbbb'));
    const small = st.put(Buffer.from('hi'));
    assert.ok(Buffer.isBuffer(small), 'small bodies stay inline');
    st.release(a);
    assert.strictEqual(st.liveBytes, 10);
    assert.ok(st.maybeCompact(), 'compacts when mostly dead');
    assert.strictEqual(st.diskBytes, 10);
    assert.strictEqual(st.get(b).toString(), 'bbbbbbbbbb', 'live ref still valid after compaction');
    st.close();

    const before = engine.store.liveBytes;
    const ids = [...engine.flows.values()].filter((x) => x.url.endsWith('/big')).map((x) => x.id);
    engine.deleteFlows(ids);
    assert.ok(engine.store.liveBytes < before, 'live bytes drop after delete');
  });

  await check('Imported sessions use the body store', async () => {
    engine.importFlows([{ method: 'GET', url: 'https://x.test/', reqHeaders: [], resHeaders: [], reqBody: '', resBody: Buffer.from('y'.repeat(20000)).toString('base64'), timing: { start: Date.now() }, tags: [] }]);
    const f = [...engine.flows.values()].pop();
    assert.strictEqual(f.resBodyLength, 20000);
    assert.strictEqual(f.resBody.length, 20000);
  });

  // ---------- LAN access control ----------
  await check('Access control: loopback always allowed, LAN needs listenAll + approval', async () => {
    const { ipListMatches } = require('../src/main/proxy/engine');
    config.set({ listenAll: false, allowedClients: [], deniedClients: [] });
    assert.ok(engine.clientAllowed('127.0.0.1'));
    assert.ok(engine.clientAllowed('::1'));
    assert.ok(!engine.clientAllowed('192.168.1.5'), 'LAN refused when listenAll is off');
    config.set({ listenAll: true });
    assert.ok(!engine.clientAllowed('192.168.1.5'), 'unknown device refused');
    config.set({ allowedClients: ['192.168.1.*'] });
    assert.ok(engine.clientAllowed('192.168.1.5'), 'wildcard allow');
    config.set({ deniedClients: ['192.168.1.5'] });
    assert.ok(!engine.clientAllowed('192.168.1.5'), 'deny wins over allow');
    assert.ok(!ipListMatches(['192.168.1.*'], '192.168.10.5'));
  });

  const lan = engine.addresses()[0];
  if (lan) {
    await check(`Real LAN connection (${lan.address}) refused until approved`, async () => {
      config.set({ listenAll: true, allowedClients: [], deniedClients: [] });
      await engine.start();
      const tryGet = () => new Promise((resolve) => {
        const req = http.request({ host: lan.address, port: PORT, method: 'GET', path: `http://localhost:${hp}/lan`, headers: { Host: `localhost:${hp}` } }, (res) => { res.resume(); resolve(res.statusCode); });
        req.on('error', () => resolve('refused'));
        req.end();
      });
      const blocked = new Promise((r) => engine.once('client:blocked', r));
      assert.strictEqual(await tryGet(), 'refused');
      assert.strictEqual((await blocked).ip, lan.address, 'UI is asked about the device');
      config.set({ allowedClients: [lan.address] });
      assert.strictEqual(await tryGet(), 200);
      config.set({ listenAll: false, allowedClients: [] });
      await engine.start();
    });
  }

  // ---------- system proxy snapshot / restore ----------
  await check('System proxy: snapshot is restored exactly, others untouched', async () => {
    const sys = require('../src/main/system');
    assert.deepStrictEqual(sys.parseBypass("There aren't any bypass domains set on Wi-Fi.\n"), []);
    assert.deepStrictEqual(sys.parseBypass('*.local\n169.254/16\n'), ['*.local', '169.254/16']);
    assert.deepStrictEqual(sys.parseProxy('Enabled: Yes\nServer: corp.proxy\nPort: 8080\nAuthenticated Proxy Enabled: 0\n'), { enabled: true, server: 'corp.proxy', port: '8080' });

    const corp = { enabled: true, server: 'corp.proxy', port: '8080' };
    const none = { enabled: false, server: '', port: '0' };
    const user = [
      { service: 'Wi-Fi', web: corp, secure: corp, bypass: ['*.corp.internal'] },
      { service: 'Ethernet', web: none, secure: none, bypass: [] },
    ];
    const snap = sys.buildSnapshot(user, null);
    const enable = sys.planEnable(snap, 9090);
    const wifiBypass = enable.find((c) => c[1] === '-setproxybypassdomains' && c[2] === 'Wi-Fi');
    assert.ok(wifiBypass.includes('*.corp.internal') && wifiBypass.includes('localhost'), 'user bypass list kept and extended');

    const rae = { enabled: true, server: '127.0.0.1', port: '9090' };
    const nowOn = user.map((u) => ({ ...u, web: rae, secure: rae, bypass: [...u.bypass, 'localhost'] }));
    // Re-enabling (port change / relaunch) must keep the original snapshot, not capture Rae's settings.
    assert.deepStrictEqual(sys.buildSnapshot(nowOn, snap), snap);
    // Without a snapshot, Rae's own settings are never recorded as the user's.
    assert.strictEqual(sys.buildSnapshot(nowOn, null)[0].web.server, '');

    const restore = sys.planRestore(snap, [...nowOn, { service: 'VPN', web: corp, secure: corp, bypass: [] }]);
    const s = (c) => c.slice(1).join(' ');
    const lines = restore.map(s);
    assert.ok(lines.includes('-setwebproxy Wi-Fi corp.proxy 8080 off'), 'corp proxy restored');
    assert.ok(lines.includes('-setsecurewebproxy Wi-Fi corp.proxy 8080 off'));
    assert.ok(!lines.includes('-setwebproxystate Wi-Fi off'), 'enabled proxy not switched off');
    assert.ok(lines.includes('-setproxybypassdomains Wi-Fi *.corp.internal'), 'bypass restored exactly');
    assert.ok(lines.includes('-setwebproxystate Ethernet off'));
    assert.ok(lines.includes('-setproxybypassdomains Ethernet Empty'), 'empty bypass list cleared');
    assert.ok(!lines.some((l) => l.includes('VPN')), 'service Rae never touched is left alone');
  });

  await check('Config migration turns off LAN access from v1', async () => {
    const { migrate, DEFAULTS } = require('../src/main/config');
    assert.strictEqual(DEFAULTS.listenAll, false);
    assert.strictEqual(migrate({ listenAll: true }).listenAll, false);
    assert.strictEqual(migrate({ configVersion: 2, listenAll: true }).listenAll, true, 'later choices are respected');
  });

  for (const r of results) console.log(r.join('  '));
  await engine.stop();
  engine.store.close();
  plainServer.close();
  secureServer.close();
  process.exit(results.some((r) => r[0] === 'FAIL') ? 1 : 0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
