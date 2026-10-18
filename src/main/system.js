// macOS integration: system proxy via networksetup, CA trust via security(1).
const { execFile } = require('child_process');
const os = require('os');
const path = require('path');

function run(cmd, args) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { timeout: 60000 }, (err, stdout, stderr) => {
      if (err) reject(new Error((stderr || err.message).trim()));
      else resolve(stdout);
    });
  });
}

const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;

function runAsAdmin(commands, prompt) {
  const script = commands.map((c) => c.map(shq).join(' ')).join(' && ');
  const as = `do shell script ${JSON.stringify(script)} with administrator privileges with prompt ${JSON.stringify(prompt)}`;
  return run('osascript', ['-e', as]);
}

async function services() {
  const out = await run('networksetup', ['-listallnetworkservices']);
  return out.split('\n').slice(1).map((s) => s.trim()).filter((s) => s && !s.startsWith('*'));
}

async function getProxyState(service) {
  const parse = (txt) => {
    const o = {};
    for (const line of txt.split('\n')) {
      const i = line.indexOf(':');
      if (i > 0) o[line.slice(0, i).trim()] = line.slice(i + 1).trim();
    }
    return { enabled: o.Enabled === 'Yes', server: o.Server, port: o.Port };
  };
  const [web, secure] = await Promise.all([
    run('networksetup', ['-getwebproxy', service]).then(parse),
    run('networksetup', ['-getsecurewebproxy', service]).then(parse),
  ]);
  return { web, secure };
}

async function applyCommands(cmds) {
  try {
    for (const c of cmds) await run(c[0], c.slice(1));
  } catch {
    await runAsAdmin(cmds, 'Rae Proxy wants to change your network proxy settings.');
  }
}

async function enableSystemProxy(port) {
  const list = await services();
  const cmds = [];
  for (const s of list) {
    cmds.push(['networksetup', '-setwebproxy', s, '127.0.0.1', String(port), 'off']);
    cmds.push(['networksetup', '-setsecurewebproxy', s, '127.0.0.1', String(port), 'off']);
    cmds.push(['networksetup', '-setproxybypassdomains', s, '*.local', '169.254/16', '127.0.0.1', 'localhost']);
  }
  await applyCommands(cmds);
}

async function disableSystemProxy() {
  const list = await services();
  const cmds = [];
  for (const s of list) {
    cmds.push(['networksetup', '-setwebproxystate', s, 'off']);
    cmds.push(['networksetup', '-setsecurewebproxystate', s, 'off']);
  }
  await applyCommands(cmds);
}

async function isSystemProxyOurs(port) {
  try {
    for (const s of await services()) {
      const st = await getProxyState(s);
      if (st.web.enabled && st.web.server === '127.0.0.1' && st.web.port === String(port)) return true;
    }
  } catch {}
  return false;
}

async function isCATrusted(certPath) {
  try {
    await run('security', ['verify-cert', '-c', certPath, '-p', 'ssl', '-L', '-q']);
    return true;
  } catch {
    return false;
  }
}

async function installCA(certPath) {
  const keychain = path.join(os.homedir(), 'Library/Keychains/login.keychain-db');
  // Prompts the user for their password via the standard macOS trust dialog.
  await run('security', ['add-trusted-cert', '-r', 'trustRoot', '-k', keychain, certPath]);
}

async function removeCA(commonName) {
  const keychain = path.join(os.homedir(), 'Library/Keychains/login.keychain-db');
  await run('security', ['delete-certificate', '-c', commonName, keychain]);
}

module.exports = { enableSystemProxy, disableSystemProxy, isSystemProxyOurs, isCATrusted, installCA, removeCA };
