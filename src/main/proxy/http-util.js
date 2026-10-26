const zlib = require("zlib");

const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-connection",
  "proxy-authorization",
  "proxy-authenticate",
  "transfer-encoding",
  "te",
  "trailer",
  "upgrade",
]);

// Headers are kept as ordered [name, value] pairs so duplicates and casing survive.
function rawToPairs(raw) {
  const out = [];
  for (let i = 0; i < raw.length; i += 2) out.push([raw[i], raw[i + 1]]);
  return out;
}

function getHeader(pairs, name) {
  name = name.toLowerCase();
  const h = pairs.find(([k]) => k.toLowerCase() === name);
  return h ? h[1] : undefined;
}

function removeHeader(pairs, name) {
  name = name.toLowerCase();
  return pairs.filter(([k]) => k.toLowerCase() !== name);
}

function setHeader(pairs, name, value) {
  const lower = name.toLowerCase();
  const idx = pairs.findIndex(([k]) => k.toLowerCase() === lower);
  const out = removeHeader(pairs, name);
  out.splice(idx === -1 ? out.length : idx, 0, [name, String(value)]);
  return out;
}

function stripHopByHop(pairs) {
  return pairs.filter(([k]) => !HOP_BY_HOP.has(k.toLowerCase()));
}

// Node wants an object; merge duplicates case-insensitively into arrays.
function pairsToObject(pairs) {
  const out = {};
  const casing = {};
  for (const [k, v] of pairs) {
    const lower = k.toLowerCase();
    const key = casing[lower] || (casing[lower] = k);
    if (key in out) out[key] = [].concat(out[key], v);
    else out[key] = v;
  }
  return out;
}

function decodeBody(buf, encoding) {
  if (!buf || !buf.length || !encoding) return buf || Buffer.alloc(0);
  try {
    let out = buf;
    for (const enc of String(encoding)
      .toLowerCase()
      .split(",")
      .map((s) => s.trim())
      .reverse()) {
      if (enc === "gzip" || enc === "x-gzip")
        out = zlib.gunzipSync(out, {
          finishFlush: zlib.constants.Z_SYNC_FLUSH,
        });
      else if (enc === "deflate") {
        try {
          out = zlib.inflateSync(out);
        } catch {
          out = zlib.inflateRawSync(out);
        }
      } else if (enc === "br") out = zlib.brotliDecompressSync(out);
      else if (enc === "zstd" && zlib.zstdDecompressSync)
        out = zlib.zstdDecompressSync(out);
      else if (enc !== "identity") return buf;
    }
    return out;
  } catch {
    return buf;
  }
}

function isTextual(contentType) {
  if (!contentType) return false;
  return /^text\/|json|xml|javascript|ecmascript|x-www-form-urlencoded|graphql|yaml|csv|html|svg/i.test(
    contentType,
  );
}

function readBody(stream) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    stream.on("data", (c) => chunks.push(c));
    stream.on("end", () => resolve(Buffer.concat(chunks)));
    stream.on("error", reject);
  });
}

module.exports = {
  rawToPairs,
  getHeader,
  setHeader,
  removeHeader,
  stripHopByHop,
  pairsToObject,
  decodeBody,
  isTextual,
  readBody,
};
