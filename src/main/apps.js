// Maps a local client connection to the macOS app that opened it (via lsof + ps).
const { execFile } = require("child_process");

function run(cmd, args) {
  return new Promise((resolve) => {
    execFile(
      cmd,
      args,
      { timeout: 5000, maxBuffer: 4 * 1024 * 1024 },
      (err, stdout) => resolve(stdout || ""),
    );
  });
}

// Helper processes count as their parent app; other nested apps (Xcode's Python.app) as themselves.
//   …/Google Chrome.app/…/Google Chrome Helper (Renderer).app/…   → Google Chrome
//   …/Xcode.app/…/Python.app/Contents/MacOS/Python                 → Python
//   …/Xcode.app/Contents/Developer/usr/bin/git                       → git (a tool shipped inside an app)
const FRIENDLY = { "com.apple.WebKit.Networking": "Safari / WebKit" };

function appFromPath(exe) {
  exe = String(exe);
  const base = exe.split("/").pop() || exe;
  const apps = [...exe.matchAll(/\/([^/]+)\.app(?=\/|$)/g)].map((m) => ({
    name: m[1],
    bundle: exe.slice(0, m.index + m[0].length),
  }));
  if (!apps.length) return { name: FRIENDLY[base] || base, bundle: null };
  const inner = apps[apps.length - 1];
  if (/helper/i.test(inner.name) && apps.length > 1) return apps[0];
  const rest = exe.slice(inner.bundle.length);
  return rest === "" || /^\/Contents\/MacOS\/[^/]+$/.test(rest)
    ? inner
    : { name: base, bundle: null };
}

// Parses `lsof -F pn` output into [{ pid, local, remote }].
function parseLsof(out) {
  const rows = [];
  let pid = null;
  for (const line of out.split("\n")) {
    if (line[0] === "p") pid = Number(line.slice(1));
    else if (line[0] === "n" && pid) {
      const [local, remote] = line.slice(1).split("->");
      if (remote) rows.push({ pid, local, remote });
    }
  }
  return rows;
}

const portOf = (addr) => Number(String(addr).split(":").pop());

class AppResolver {
  // proxyPorts(): ports Rae listens on, so we only match connections *to* Rae.
  constructor({ proxyPorts, ownPid = process.pid, batchMs = 25 }) {
    this.proxyPorts = proxyPorts;
    this.ownPid = ownPid;
    this.batchMs = batchMs;
    this.pending = new Map(); // client port -> [resolve]
    this.byPid = new Map(); // pid -> Promise<app>
    this.timer = null;
  }

  resolve(clientPort) {
    return new Promise((resolve) => {
      const list = this.pending.get(clientPort) || [];
      list.push(resolve);
      this.pending.set(clientPort, list);
      if (!this.timer)
        this.timer = setTimeout(() => this.flush(), this.batchMs);
    });
  }

  async flush() {
    this.timer = null;
    const batch = this.pending;
    this.pending = new Map();
    const ports = [...batch.keys()];
    const args = ["-nP", "-F", "pn", ...ports.flatMap((p) => ["-iTCP:" + p])];
    const rows = parseLsof(await run("lsof", args));
    const servers = new Set(this.proxyPorts());
    const pidFor = new Map();
    for (const r of rows) {
      if (r.pid === this.ownPid) continue;
      const lp = portOf(r.local);
      if (batch.has(lp) && servers.has(portOf(r.remote))) pidFor.set(lp, r.pid);
    }
    await Promise.all(
      ports.map(async (p) => {
        const pid = pidFor.get(p);
        const app = pid ? await this.appForPid(pid) : null;
        for (const res of batch.get(p)) res(app);
      }),
    );
  }

  appForPid(pid) {
    let p = this.byPid.get(pid);
    if (!p) {
      p = run("ps", ["-o", "comm=", "-p", String(pid)]).then((out) => {
        const exe = out.trim();
        return exe ? { pid, path: exe, ...appFromPath(exe) } : null;
      });
      this.byPid.set(pid, p);
      if (this.byPid.size > 2000)
        this.byPid.delete(this.byPid.keys().next().value);
    }
    return p;
  }
}

module.exports = { AppResolver, appFromPath, parseLsof };
