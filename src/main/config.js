const fs = require('fs');
const path = require('path');

const DEFAULTS = {
  port: 9090,
  listenAll: true,
  recording: true,
  verifyUpstreamTLS: true,
  maxBodySize: 50 * 1024 * 1024,
  maxFlows: 20000,
  noCache: false,
  systemProxy: false,
  pinned: [],
  ssl: {
    interceptAll: true,
    include: [],
    exclude: ['*.apple.com', '*.icloud.com', '*.mzstatic.com', '*.apple-cloudkit.com'],
  },
  breakpoints: { enabled: true, rules: [] },
  mapLocal: { enabled: true, rules: [] },
  mapRemote: { enabled: true, rules: [] },
  blockList: { enabled: true, rules: [] },
  allowList: { enabled: false, rules: [] },
  scripting: { enabled: true, rules: [] },
  throttle: { enabled: false, preset: '3G', latency: 300, downloadKbps: 780, uploadKbps: 330 },
  reverseProxies: [],
};

function merge(base, patch) {
  if (Array.isArray(patch) || typeof patch !== 'object' || patch === null) return patch;
  const out = { ...base };
  for (const [k, v] of Object.entries(patch)) {
    out[k] = base && typeof base[k] === 'object' && !Array.isArray(base[k]) && base[k] !== null ? merge(base[k], v) : v;
  }
  return out;
}

class Config {
  constructor(dir) {
    this.file = path.join(dir, 'config.json');
    this.listeners = [];
    let saved = {};
    try { saved = JSON.parse(fs.readFileSync(this.file, 'utf8')); } catch {}
    this.data = merge(DEFAULTS, saved);
  }
  get() { return this.data; }
  set(patch) {
    const prev = this.data;
    this.data = merge(this.data, patch);
    this.save();
    for (const fn of this.listeners) fn(this.data, prev);
    return this.data;
  }
  onChange(fn) { this.listeners.push(fn); }
  save() {
    clearTimeout(this.timer);
    this.timer = setTimeout(() => {
      fs.mkdirSync(path.dirname(this.file), { recursive: true });
      fs.writeFileSync(this.file, JSON.stringify(this.data, null, 2));
    }, 200);
  }
  flush() {
    clearTimeout(this.timer);
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    fs.writeFileSync(this.file, JSON.stringify(this.data, null, 2));
  }
}

module.exports = { Config, DEFAULTS };
