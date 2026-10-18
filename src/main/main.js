const { app, BrowserWindow, ipcMain, Menu, dialog, shell, nativeTheme, clipboard } = require('electron');
const path = require('path');
const fs = require('fs');
const { Config } = require('./config');
const { CertAuthority } = require('./proxy/ca');
const { ProxyEngine, TEMPLATE } = require('./proxy/engine');
const { getHeader } = require('./proxy/http-util');
const system = require('./system');
const har = require('./har');

app.setName('Rae Proxy');
const dataDir = app.getPath('userData');
const config = new Config(dataDir);
let ca;
let engine;
let win;
let systemProxyOn = false;

// ---------- flow serialization ----------
function isGraphQL(f) {
  if (f._gql !== undefined) return f._gql;
  f._gql = false;
  if (/graphql/i.test(f.path)) f._gql = true;
  else if (f.reqBody && f.reqBody.length && f.reqBody.length < 1e6 && /json/i.test(getHeader(f.reqHeaders, 'content-type') || '')) {
    const s = f.reqBody.toString('utf8', 0, 200);
    f._gql = /"query"\s*:\s*"\s*(query|mutation|subscription|\{)/.test(s) || /"operationName"/.test(s);
  }
  return f._gql;
}

function summarize(f) {
  return {
    id: f.id,
    method: f.method,
    url: f.url,
    scheme: f.scheme,
    host: f.host,
    port: f.port,
    path: f.path,
    status: f.status,
    statusMessage: f.statusMessage,
    state: f.state,
    error: f.error,
    tags: f.tags,
    ws: f.ws,
    tunnel: f.tunnel,
    start: f.timing.start,
    duration: f.timing.end ? f.timing.end - f.timing.start : null,
    reqSize: f.reqBody ? f.reqBody.length : 0,
    resSize: f.resSize || 0,
    contentType: getHeader(f.resHeaders || [], 'content-type') || '',
    reqContentType: getHeader(f.reqHeaders || [], 'content-type') || '',
    clientAddr: f.clientAddr,
    graphql: isGraphQL(f),
    wsCount: f.wsMessages ? f.wsMessages.length : 0,
  };
}

function detail(f) {
  return {
    ...summarize(f),
    httpVersion: f.httpVersion,
    originalUrl: f.originalUrl,
    reqHeaders: f.reqHeaders,
    resHeaders: f.resHeaders,
    reqBody: f.reqBody ? f.reqBody.toString('base64') : '',
    resBody: f.resBody ? f.resBody.toString('base64') : null,
    timing: f.timing,
    wsMessages: f.wsMessages,
  };
}

// Batch flow updates to the renderer (~10/s) to stay smooth under heavy traffic.
const dirty = new Map();
let flushTimer = null;
function queueFlow(f) {
  dirty.set(f.id, f);
  if (!flushTimer) flushTimer = setTimeout(flush, 100);
}
function flush() {
  flushTimer = null;
  if (!win || win.isDestroyed() || !dirty.size) return dirty.clear();
  win.webContents.send('flows:update', [...dirty.values()].map(summarize));
  dirty.clear();
}

function send(channel, payload) {
  if (win && !win.isDestroyed()) win.webContents.send(channel, payload);
}

// ---------- state ----------
async function caInfo() {
  return { path: ca.certPath, commonName: ca.commonName, trusted: await system.isCATrusted(ca.certPath) };
}

async function fullState() {
  return {
    config: config.get(),
    proxy: { ...engine.status, addresses: engine.addresses() },
    ca: await caInfo(),
    systemProxy: systemProxyOn,
    flows: [...engine.flows.values()].map(summarize),
    scriptTemplate: TEMPLATE,
    version: app.getVersion(),
    pendingBreakpoints: engine.pendingBreakpoints(),
  };
}

async function setSystemProxy(on) {
  if (on) await system.enableSystemProxy(config.get().port);
  else await system.disableSystemProxy();
  systemProxyOn = on;
  config.set({ systemProxy: on });
  send('systemProxy:status', on);
  buildMenu();
  return on;
}

// ---------- window ----------
function createWindow() {
  win = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 960,
    minHeight: 600,
    title: 'Rae Proxy',
    titleBarStyle: 'hiddenInset',
    trafficLightPosition: { x: 14, y: 16 },
    backgroundColor: nativeTheme.shouldUseDarkColors ? '#1e1e20' : '#f5f5f7',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  win.loadFile(path.join(__dirname, '../renderer/index.html'));
  if (process.env.RAE_DEBUG) {
    win.webContents.on('console-message', (e) => console.log(`[renderer:${e.level}] ${e.message} (${e.sourceId}:${e.lineNumber})`));
    win.webContents.on('preload-error', (_e, p, err) => console.log('[preload-error]', p, err));
    if (process.env.RAE_SCREENSHOT) {
      const shoot = async () => fs.writeFileSync(process.env.RAE_SCREENSHOT, (await win.webContents.capturePage()).toPNG());
      setInterval(() => shoot().catch(() => {}), 2000);
    }
    if (process.env.RAE_DEBUG_CMD) {
      // Dev-only: run JS in the renderer whenever this file changes.
      fs.watchFile(process.env.RAE_DEBUG_CMD, { interval: 500 }, async () => {
        try { console.log('[eval]', JSON.stringify(await win.webContents.executeJavaScript(fs.readFileSync(process.env.RAE_DEBUG_CMD, 'utf8')))); } catch (e) { console.log('[eval-error]', e.message); }
      });
    }
  }
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:/.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  win.on('closed', () => { win = null; });
}

function buildMenu() {
  const cfg = config.get();
  const m = (action) => () => send('menu', action);
  const template = [
    {
      label: 'Rae Proxy',
      submenu: [
        { role: 'about' },
        { type: 'separator' },
        { label: 'Settings…', accelerator: 'Cmd+,', click: m('settings') },
        { type: 'separator' },
        { role: 'services' },
        { type: 'separator' },
        { role: 'hide' }, { role: 'hideOthers' }, { role: 'unhide' },
        { type: 'separator' },
        { role: 'quit' },
      ],
    },
    {
      label: 'File',
      submenu: [
        { label: 'New Request…', accelerator: 'Cmd+N', click: m('compose') },
        { type: 'separator' },
        { label: 'Open Session…', accelerator: 'Cmd+O', click: m('session:open') },
        { label: 'Save Session…', accelerator: 'Cmd+S', click: m('session:save') },
        { type: 'separator' },
        { label: 'Import HAR…', click: m('har:import') },
        { label: 'Export All as HAR…', accelerator: 'Shift+Cmd+E', click: m('har:export') },
        { type: 'separator' },
        { label: 'Clear Session', accelerator: 'Cmd+K', click: m('clear') },
      ],
    },
    { role: 'editMenu' },
    {
      label: 'View',
      submenu: [
        { label: 'Filter', accelerator: 'Cmd+F', click: m('focus-filter') },
        { label: 'Toggle Sidebar', accelerator: 'Cmd+Alt+S', click: m('toggle-sidebar') },
        { label: 'Toggle Detail Layout', accelerator: 'Cmd+Alt+D', click: m('toggle-layout') },
        { type: 'separator' },
        { role: 'reload' }, { role: 'toggleDevTools' },
        { type: 'separator' },
        { role: 'resetZoom' }, { role: 'zoomIn' }, { role: 'zoomOut' },
        { type: 'separator' },
        { role: 'togglefullscreen' },
      ],
    },
    {
      label: 'Proxy',
      submenu: [
        { label: 'Recording', type: 'checkbox', checked: cfg.recording, accelerator: 'Cmd+R', click: m('toggle-recording') },
        { label: 'macOS System Proxy', type: 'checkbox', checked: systemProxyOn, accelerator: 'Shift+Cmd+P', click: m('toggle-system-proxy') },
        { type: 'separator' },
        { label: 'Network Conditions (Throttle)', type: 'checkbox', checked: cfg.throttle.enabled, accelerator: 'Alt+Cmd+T', click: m('toggle-throttle') },
        { label: 'No Caching', type: 'checkbox', checked: cfg.noCache, click: m('toggle-nocache') },
        { type: 'separator' },
        { label: 'SSL Proxying List…', accelerator: 'Alt+Cmd+P', click: m('tool:ssl') },
        { label: 'Reverse Proxy…', click: m('tool:reverse') },
      ],
    },
    {
      label: 'Tools',
      submenu: [
        { label: 'Breakpoints…', accelerator: 'Alt+Cmd+B', click: m('tool:breakpoints') },
        { label: 'Map Local…', accelerator: 'Alt+Cmd+L', click: m('tool:mapLocal') },
        { label: 'Map Remote…', accelerator: 'Alt+Cmd+R', click: m('tool:mapRemote') },
        { label: 'Scripting…', accelerator: 'Alt+Cmd+I', click: m('tool:scripting') },
        { label: 'Block List…', click: m('tool:blockList') },
        { label: 'Allow List…', click: m('tool:allowList') },
        { label: 'Network Conditions…', click: m('tool:throttle') },
        { type: 'separator' },
        { label: 'Compose Request…', accelerator: 'Cmd+N', click: m('compose'), visible: false },
        { label: 'Script Console', accelerator: 'Alt+Cmd+C', click: m('console') },
      ],
    },
    {
      label: 'Certificate',
      submenu: [
        { label: 'Install Certificate on this Mac…', click: m('cert:install') },
        { label: 'Install Certificate on iOS / Android…', click: m('cert:device') },
        { type: 'separator' },
        { label: 'Export Root Certificate…', click: m('cert:export') },
        { label: 'Reveal Certificate in Finder', click: () => shell.showItemInFolder(ca.certPath) },
        { label: 'Regenerate Root Certificate…', click: m('cert:regenerate') },
      ],
    },
    { role: 'windowMenu' },
    { role: 'help', submenu: [{ label: 'Proxy Setup Guide', click: m('cert:device') }] },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

// ---------- IPC ----------
function registerIpc() {
  const h = (ch, fn) => ipcMain.handle(ch, (_e, ...a) => fn(...a));

  h('state:get', fullState);
  h('config:set', async (patch) => {
    const prev = config.get();
    const next = config.set(patch);
    if (patch.port !== undefined || patch.listenAll !== undefined) {
      if (prev.port !== next.port || prev.listenAll !== next.listenAll) {
        await engine.start();
        if (systemProxyOn) await system.enableSystemProxy(next.port).catch(() => {});
      }
    }
    if (patch.reverseProxies) engine.syncReverseProxies();
    buildMenu();
    return next;
  });
  h('flows:clear', () => { engine.clear(); return true; });
  h('flows:delete', (ids) => { for (const id of ids) engine.flows.delete(id); return true; });
  h('flow:get', (id) => { const f = engine.flows.get(id); return f ? detail(f) : null; });
  h('flow:repeat', (id) => engine.repeat(id));
  h('compose:send', (req) => engine.compose(req));
  h('breakpoint:resolve', ({ id, action, data }) => engine.resolveBreakpoint(id, action, data));
  h('systemProxy:set', (on) => setSystemProxy(on));
  h('proxy:restart', () => engine.start());

  h('ca:info', caInfo);
  h('ca:install', async () => {
    await system.installCA(ca.certPath);
    return caInfo();
  });
  h('ca:export', async () => {
    const r = await dialog.showSaveDialog(win, { defaultPath: 'rae-proxy-ca.pem', filters: [{ name: 'Certificate', extensions: ['pem', 'crt'] }] });
    if (r.canceled) return false;
    fs.writeFileSync(r.filePath, ca.caCertPem);
    return true;
  });
  h('ca:regenerate', async () => {
    const { response } = await dialog.showMessageBox(win, {
      type: 'warning', buttons: ['Regenerate', 'Cancel'], defaultId: 1,
      message: 'Regenerate the root certificate?',
      detail: 'Devices and this Mac will need to trust the new certificate again. The old certificate will remain in your keychain until you delete it.',
    });
    if (response !== 0) return caInfo();
    ca.regenerate();
    return caInfo();
  });

  const saveJSON = async (name, ext, data) => {
    const r = await dialog.showSaveDialog(win, { defaultPath: name, filters: [{ name: ext.toUpperCase(), extensions: [ext] }] });
    if (r.canceled) return false;
    fs.writeFileSync(r.filePath, JSON.stringify(data, null, 2));
    return r.filePath;
  };
  const pick = (ids) => (ids && ids.length ? ids.map((id) => engine.flows.get(id)).filter(Boolean) : [...engine.flows.values()]);
  h('har:export', (ids) => saveJSON(`rae-proxy-${stamp()}.har`, 'har', har.toHar(pick(ids), app.getVersion())));
  h('session:save', () => saveJSON(`rae-proxy-${stamp()}.raesession`, 'raesession', har.toSession(pick())));
  h('har:import', async () => {
    const r = await dialog.showOpenDialog(win, { properties: ['openFile'], filters: [{ name: 'HAR / Rae Session', extensions: ['har', 'json', 'raesession'] }] });
    if (r.canceled) return 0;
    const data = JSON.parse(fs.readFileSync(r.filePaths[0], 'utf8'));
    const list = data.format === 'rae-proxy-session' ? data.flows : har.fromHar(data);
    engine.importFlows(list);
    send('flows:reset', [...engine.flows.values()].map(summarize));
    return list.length;
  });
  h('mapLocal:pickFile', async () => {
    const r = await dialog.showOpenDialog(win, { properties: ['openFile'] });
    return r.canceled ? null : r.filePaths[0];
  });
  h('mapLocal:saveBody', async ({ id }) => {
    // Save a flow's response body to a file and return path (for "Map Local from response").
    const f = engine.flows.get(id);
    if (!f || !f.resBody) return null;
    const dir = path.join(dataDir, 'map-local');
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, `${f.host}-${f.id}-${(f.path.split('?')[0].split('/').pop() || 'index').replace(/[^\w.-]/g, '_')}`);
    fs.writeFileSync(file, f.resBody);
    return file;
  });
  h('body:save', async ({ id, which }) => {
    const f = engine.flows.get(id);
    if (!f) return false;
    const buf = which === 'request' ? f.reqBody : f.resBody;
    const r = await dialog.showSaveDialog(win, { defaultPath: (f.path.split('?')[0].split('/').pop() || 'body') });
    if (r.canceled) return false;
    fs.writeFileSync(r.filePath, buf || Buffer.alloc(0));
    return true;
  });
  h('clipboard:write', (text) => { clipboard.writeText(text); return true; });
  h('contextMenu', (items) => new Promise((resolve) => {
    const build = (list) => list.map((it) => (it.type === 'separator'
      ? { type: 'separator' }
      : { label: it.label, enabled: it.enabled !== false, type: it.checked !== undefined ? 'checkbox' : 'normal', checked: it.checked, submenu: it.submenu ? build(it.submenu) : undefined, click: it.submenu ? undefined : () => resolve(it.id) }));
    const menu = Menu.buildFromTemplate(build(items));
    menu.popup({ window: win, callback: () => setTimeout(() => resolve(null), 50) });
  }));
  h('openExternal', (url) => shell.openExternal(url));
}

function stamp() {
  return new Date().toISOString().replace(/[:T]/g, '-').slice(0, 19);
}

// ---------- boot ----------
app.whenReady().then(async () => {
  ca = new CertAuthority(path.join(dataDir, 'certificates'));
  engine = new ProxyEngine({ ca, config });
  engine.on('flow', queueFlow);
  engine.on('status', (s) => send('proxy:status', { ...s, addresses: engine.addresses() }));
  engine.on('breakpoint', (bp) => {
    send('breakpoint:hit', bp);
    if (win) { if (win.isMinimized()) win.restore(); win.focus(); app.dock?.bounce('informational'); }
  });
  engine.on('log', (entry) => send('script:log', entry));

  registerIpc();
  buildMenu();
  createWindow();
  await engine.start();

  // Restore system proxy state (and clean up after a crash that left it pointing at us).
  const cfg = config.get();
  if (cfg.systemProxy && engine.status.running) setSystemProxy(true).catch(() => {});
  else if (await system.isSystemProxyOurs(cfg.port)) system.disableSystemProxy().catch(() => {});

  app.on('activate', () => { if (!win) createWindow(); });
});

let quitting = false;
app.on('before-quit', async (e) => {
  if (quitting) return;
  if (systemProxyOn) {
    e.preventDefault();
    quitting = true;
    try { await system.disableSystemProxy(); } catch {}
    config.set({ systemProxy: true }); // remember to re-enable next launch
    config.flush();
    app.quit();
  } else config.flush();
});

app.on('window-all-closed', () => app.quit());
