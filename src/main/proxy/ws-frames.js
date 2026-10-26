// Passive WebSocket frame parser: observes a byte stream and reports messages.
const OPCODES = {
  0: "continuation",
  1: "text",
  2: "binary",
  8: "close",
  9: "ping",
  10: "pong",
};

class FrameParser {
  constructor(onMessage, maxPayload = 1024 * 1024) {
    this.buf = Buffer.alloc(0);
    this.onMessage = onMessage;
    this.maxPayload = maxPayload;
    this.fragments = null;
    this.broken = false;
  }

  push(chunk) {
    if (this.broken) return;
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    try {
      while (this.parseOne());
    } catch {
      this.broken = true;
    }
  }

  parseOne() {
    const b = this.buf;
    if (b.length < 2) return false;
    const fin = (b[0] & 0x80) !== 0;
    const opcode = b[0] & 0x0f;
    const masked = (b[1] & 0x80) !== 0;
    let len = b[1] & 0x7f;
    let off = 2;
    if (len === 126) {
      if (b.length < 4) return false;
      len = b.readUInt16BE(2);
      off = 4;
    } else if (len === 127) {
      if (b.length < 10) return false;
      len = Number(b.readBigUInt64BE(2));
      off = 10;
    }
    let mask;
    if (masked) {
      if (b.length < off + 4) return false;
      mask = b.subarray(off, off + 4);
      off += 4;
    }
    if (b.length < off + len) return false;
    let payload = Buffer.from(b.subarray(off, off + len));
    if (masked)
      for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
    this.buf = b.subarray(off + len);

    if (opcode === 0 && this.fragments) {
      this.fragments.parts.push(payload);
      if (fin) {
        const msg = Buffer.concat(this.fragments.parts);
        this.emit(this.fragments.opcode, msg);
        this.fragments = null;
      }
    } else if (!fin && (opcode === 1 || opcode === 2)) {
      this.fragments = { opcode, parts: [payload] };
    } else {
      this.emit(opcode, payload);
    }
    return true;
  }

  emit(opcode, payload) {
    const type = OPCODES[opcode] || `op${opcode}`;
    const truncated = payload.length > this.maxPayload;
    const data = truncated ? payload.subarray(0, this.maxPayload) : payload;
    this.onMessage({
      type,
      length: payload.length,
      truncated,
      text:
        type === "text" || type === "close" ? data.toString("utf8") : undefined,
      base64: type === "binary" ? data.toString("base64") : undefined,
    });
  }
}

module.exports = { FrameParser };
