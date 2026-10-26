// Keeps captured bodies out of RAM: small bodies stay inline, larger ones are
// appended to a single session file and read back on demand.
const fs = require("fs");
const path = require("path");

class BodyStore {
  constructor(
    file,
    { inlineMax = 8 * 1024, compactMinBytes = 256 * 1024 * 1024 } = {},
  ) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    this.file = file;
    this.fd = fs.openSync(file, "w+");
    this.offset = 0;
    this.inlineMax = inlineMax;
    this.compactMinBytes = compactMinBytes;
    this.live = new Set();
    this.liveBytes = 0;
  }

  // Returns a ref: a small Buffer (copied, so it never pins a larger parent buffer) or { off, len }.
  put(buf) {
    if (buf === null || buf === undefined) return null;
    if (buf.length <= this.inlineMax) return Buffer.from(buf);
    const ref = { off: this.offset, len: buf.length };
    fs.writeSync(this.fd, buf, 0, buf.length, ref.off);
    this.offset += buf.length;
    this.live.add(ref);
    this.liveBytes += ref.len;
    return ref;
  }

  get(ref) {
    if (ref === null || ref === undefined) return null;
    if (Buffer.isBuffer(ref)) return ref;
    const out = Buffer.allocUnsafe(ref.len);
    fs.readSync(this.fd, out, 0, ref.len, ref.off);
    return out;
  }

  size(ref) {
    if (ref === null || ref === undefined) return 0;
    return Buffer.isBuffer(ref) ? ref.length : ref.len;
  }

  release(ref) {
    if (ref && !Buffer.isBuffer(ref) && this.live.delete(ref))
      this.liveBytes -= ref.len;
  }

  get diskBytes() {
    return this.offset;
  }

  // Rewrite live bodies into a fresh file once mostly dead space. Refs are updated in place.
  maybeCompact() {
    if (this.offset < this.compactMinBytes || this.liveBytes * 2 > this.offset)
      return false;
    const tmp = this.file + ".compact";
    const fd = fs.openSync(tmp, "w+");
    let off = 0;
    for (const ref of [...this.live].sort((a, b) => a.off - b.off)) {
      const buf = this.get(ref);
      fs.writeSync(fd, buf, 0, buf.length, off);
      ref.off = off;
      off += buf.length;
    }
    fs.closeSync(this.fd);
    fs.renameSync(tmp, this.file);
    this.fd = fd;
    this.offset = off;
    return true;
  }

  reset() {
    fs.ftruncateSync(this.fd, 0);
    this.offset = 0;
    this.live.clear();
    this.liveBytes = 0;
  }

  close() {
    try {
      fs.closeSync(this.fd);
      fs.unlinkSync(this.file);
    } catch {}
  }
}

// Gives a flow `reqBody` / `resBody` accessors backed by the store, plus sizes that don't touch disk.
function attachBodies(flow, store) {
  let req = null;
  let res = null;
  Object.defineProperties(flow, {
    reqBody: {
      enumerable: true,
      configurable: true,
      get: () => store.get(req) || Buffer.alloc(0),
      set: (b) => {
        store.release(req);
        req = store.put(b || Buffer.alloc(0));
      },
    },
    resBody: {
      enumerable: true,
      configurable: true,
      get: () => store.get(res),
      set: (b) => {
        store.release(res);
        res = store.put(b);
      },
    },
    reqBodyLength: { get: () => store.size(req) },
    resBodyLength: { get: () => store.size(res) },
    releaseBodies: {
      value: () => {
        store.release(req);
        store.release(res);
        req = res = null;
      },
    },
  });
  return flow;
}

module.exports = { BodyStore, attachBodies };
