// macOS integration: system proxy via networksetup, CA trust via security(1).
const { execFile } = require("child_process");
const os = require("os");
const path = require("path");

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
  const script = commands.map((c) => c.map(shq).join(" ")).join(" && ");
  const as = `do shell script ${JSON.stringify(script)} with administrator privileges with prompt ${JSON.stringify(prompt)}`;
  return run("osascript", ["-e", as]);
}

async function services() {
  const out = await run("networksetup", ["-listallnetworkservices"]);
  return out
    .split("\n")
    .slice(1)
    .map((s) => s.trim())
    .filter((s) => s && !s.startsWith("*"));
}

function parseProxy(txt) {
  const o = {};
  for (const line of String(txt).split("\n")) {
    const i = line.indexOf(":");
    if (i > 0) o[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  return {
    enabled: o.Enabled === "Yes",
    server: o.Server || "",
    port: o.Port || "",
  };
}

function parseBypass(txt) {
  if (/there aren't any bypass domains/i.test(txt)) return [];
  return String(txt)
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
}

async function getProxyState(service) {
  const [web, secure, bypass] = await Promise.all([
    run("networksetup", ["-getwebproxy", service]).then(parseProxy),
    run("networksetup", ["-getsecurewebproxy", service]).then(parseProxy),
    run("networksetup", ["-getproxybypassdomains", service]).then(parseBypass),
  ]);
  return { service, web, secure, bypass };
}

const RAE_BYPASS = ["*.local", "169.254/16", "127.0.0.1", "localhost"];
const isRae = (p) => p.enabled && p.server === "127.0.0.1";

// Snapshot = the user's settings per service before Rae touched them.
// Services already in the previous snapshot keep their original entry, so
// re-enabling (port change, relaunch after a crash) never captures Rae's own settings.
function buildSnapshot(current, previous) {
  const prev = new Map((previous || []).map((e) => [e.service, e]));
  const off = { enabled: false, server: "", port: "" };
  return current.map(
    (st) =>
      prev.get(st.service) || {
        ...st,
        web: isRae(st.web) ? off : st.web,
        secure: isRae(st.secure) ? off : st.secure,
      },
  );
}

function planEnable(snapshot, port) {
  const cmds = [];
  for (const { service, bypass } of snapshot) {
    cmds.push([
      "networksetup",
      "-setwebproxy",
      service,
      "127.0.0.1",
      String(port),
      "off",
    ]);
    cmds.push([
      "networksetup",
      "-setsecurewebproxy",
      service,
      "127.0.0.1",
      String(port),
      "off",
    ]);
    cmds.push([
      "networksetup",
      "-setproxybypassdomains",
      service,
      ...[...new Set([...(bypass || []), ...RAE_BYPASS])],
    ]);
  }
  return cmds;
}

function restoreOne(service, kind, p) {
  const cmds = [];
  if (p.server && Number(p.port) > 0)
    cmds.push([
      "networksetup",
      `-set${kind}`,
      service,
      p.server,
      String(p.port),
      "off",
    ]);
  if (!p.enabled || !p.server)
    cmds.push(["networksetup", `-set${kind}state`, service, "off"]);
  return cmds;
}

// Restores snapshot entries; services without one are only switched off if they point at Rae.
function planRestore(snapshot, current) {
  const snap = new Map((snapshot || []).map((e) => [e.service, e]));
  const cmds = [];
  for (const st of current) {
    const orig = snap.get(st.service);
    if (orig) {
      cmds.push(...restoreOne(st.service, "webproxy", orig.web));
      cmds.push(...restoreOne(st.service, "securewebproxy", orig.secure));
      cmds.push([
        "networksetup",
        "-setproxybypassdomains",
        st.service,
        ...(orig.bypass.length ? orig.bypass : ["Empty"]),
      ]);
    } else {
      if (isRae(st.web))
        cmds.push(["networksetup", "-setwebproxystate", st.service, "off"]);
      if (isRae(st.secure))
        cmds.push([
          "networksetup",
          "-setsecurewebproxystate",
          st.service,
          "off",
        ]);
    }
  }
  return cmds;
}

async function currentStates() {
  return Promise.all((await services()).map(getProxyState));
}

async function applyCommands(cmds) {
  if (!cmds.length) return;
  try {
    for (const c of cmds) await run(c[0], c.slice(1));
  } catch {
    await runAsAdmin(
      cmds,
      "Rae Proxy wants to change your network proxy settings.",
    );
  }
}

// Returns the snapshot to persist so disable (even after a crash) can restore it.
// `persist` is called with the snapshot *before* anything changes, so a crash mid-way can still be undone.
async function enableSystemProxy(port, previousSnapshot, persist) {
  const snapshot = buildSnapshot(await currentStates(), previousSnapshot);
  if (persist) persist(snapshot);
  await applyCommands(planEnable(snapshot, port));
  return snapshot;
}

async function disableSystemProxy(snapshot) {
  await applyCommands(planRestore(snapshot, await currentStates()));
}

// Finds the proxy macOS was using before Rae (snapshot) or right now, ignoring Rae itself.
async function detectUpstreamProxy(snapshot) {
  const states = snapshot && snapshot.length ? snapshot : await currentStates();
  const usable = (p) =>
    p.enabled && p.server && p.server !== "127.0.0.1" && Number(p.port) > 0;
  const st = states.find((x) => usable(x.web) || usable(x.secure));
  if (!st) return null;
  const web = usable(st.web) ? st.web : st.secure;
  const secure = usable(st.secure) ? st.secure : web;
  const same = web.server === secure.server && web.port === secure.port;
  return {
    service: st.service,
    host: web.server,
    port: Number(web.port),
    sameForHttps: same,
    httpsHost: same ? "" : secure.server,
    httpsPort: same ? "" : Number(secure.port),
    bypass: (st.bypass || []).filter(
      (b) => !["*.local", "169.254/16", "127.0.0.1", "localhost"].includes(b),
    ),
  };
}

async function isSystemProxyOurs(port) {
  try {
    for (const st of await currentStates()) {
      if (isRae(st.web) && st.web.port === String(port)) return true;
    }
  } catch {}
  return false;
}

async function isCATrusted(certPath) {
  try {
    await run("security", [
      "verify-cert",
      "-c",
      certPath,
      "-p",
      "ssl",
      "-L",
      "-q",
    ]);
    return true;
  } catch {
    return false;
  }
}

async function installCA(certPath) {
  const keychain = path.join(
    os.homedir(),
    "Library/Keychains/login.keychain-db",
  );
  // Prompts the user for their password via the standard macOS trust dialog.
  await run("security", [
    "add-trusted-cert",
    "-r",
    "trustRoot",
    "-k",
    keychain,
    certPath,
  ]);
}

async function removeCA(commonName) {
  const keychain = path.join(
    os.homedir(),
    "Library/Keychains/login.keychain-db",
  );
  await run("security", ["delete-certificate", "-c", commonName, keychain]);
}

module.exports = {
  detectUpstreamProxy,
  enableSystemProxy,
  disableSystemProxy,
  isSystemProxyOurs,
  isCATrusted,
  installCA,
  removeCA,
  parseProxy,
  parseBypass,
  buildSnapshot,
  planEnable,
  planRestore,
};
