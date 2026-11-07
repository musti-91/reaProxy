/* Body / header / timing viewers used by the detail panes. */

function highlightJSON(text) {
  return esc(text).replace(
    /(&quot;(?:\\.|[^&\\]|&(?!quot;))*?&quot;)(\s*:)?|\b(true|false)\b|\bnull\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g,
    (m, str, colon, bool) => {
      if (str)
        return colon
          ? `<span class="j-key">${str}</span>${colon}`
          : `<span class="j-str">${str}</span>`;
      if (bool) return `<span class="j-bool">${m}</span>`;
      if (m === "null") return `<span class="j-null">null</span>`;
      return `<span class="j-num">${m}</span>`;
    },
  );
}

// Wraps occurrences of `needle` (case-insensitive) in plain text with <mark class="hl">.
// Returns an array of strings/Nodes suitable as h() children.
function markMatches(text, needle) {
  if (!needle) return [text];
  const lower = text.toLowerCase();
  const nlen = needle.length;
  const out = [];
  let i = 0,
    idx;
  while ((idx = lower.indexOf(needle, i)) !== -1) {
    if (idx > i) out.push(text.slice(i, idx));
    out.push(h("mark", { class: "hl" }, text.slice(idx, idx + nlen)));
    i = idx + nlen;
  }
  if (i < text.length) out.push(text.slice(i));
  return out.length ? out : [text];
}

// Same, but for an already-escaped HTML string (e.g. highlightJSON output) —
// only touches text between tags so existing markup/classes are untouched.
function highlightInHtml(html, needle) {
  if (!needle) return html;
  const escNeedle = esc(needle).toLowerCase();
  if (!escNeedle) return html;
  return html.replace(/(<[^>]+>)|([^<]+)/g, (m, tag, text) => {
    if (tag) return tag;
    const lower = text.toLowerCase();
    let i = 0,
      idx,
      out = "";
    while ((idx = lower.indexOf(escNeedle, i)) !== -1) {
      out +=
        text.slice(i, idx) +
        '<mark class="hl">' +
        text.slice(idx, idx + escNeedle.length) +
        "</mark>";
      i = idx + escNeedle.length;
    }
    out += text.slice(i);
    return out;
  });
}

// Whether `value`'s own text, or anything nested inside it, contains `needle`.
// Memoized per search (via `cache`) so expanding a large tree stays O(n).
function subtreeMatches(value, needle, cache) {
  if (!needle) return false;
  if (value === null || typeof value !== "object")
    return String(value).toLowerCase().includes(needle);
  if (cache && cache.has(value)) return cache.get(value);
  const entries = Array.isArray(value)
    ? value.map((v) => [undefined, v])
    : Object.entries(value);
  const result = entries.some(
    ([k, v]) =>
      (k !== undefined && String(k).toLowerCase().includes(needle)) ||
      subtreeMatches(v, needle, cache),
  );
  if (cache) cache.set(value, result);
  return result;
}

function jsonTree(
  value,
  key,
  depth = 0,
  inArray = false,
  needle = "",
  cache = null,
) {
  const keyText =
    key !== undefined
      ? inArray
        ? String(key)
        : JSON.stringify(String(key))
      : null;
  const label =
    key !== undefined
      ? h(
          "span",
          { class: inArray ? "meta" : "j-key" },
          ...markMatches(keyText, needle),
          ": ",
        )
      : null;
  if (value === null || typeof value !== "object") {
    let cls = "j-str",
      txt = JSON.stringify(value);
    if (typeof value === "number") cls = "j-num";
    else if (typeof value === "boolean") cls = "j-bool";
    else if (value === null) cls = "j-null";
    return h(
      "div",
      { class: "leaf" },
      label,
      h("span", { class: cls }, ...markMatches(txt, needle)),
    );
  }
  const isArr = Array.isArray(value);
  const entries = isArr ? value.map((v, i) => [i, v]) : Object.entries(value);
  const forceOpen = needle && subtreeMatches(value, needle, cache);
  const d = h("details", { open: depth < 2 || forceOpen });
  d.append(
    h(
      "summary",
      null,
      label,
      isArr ? "[" : "{",
      h(
        "span",
        { class: "meta" },
        ` ${entries.length} ${isArr ? "items" : "keys"} `,
      ),
      isArr ? "]" : "}",
    ),
  );
  let rendered = false;
  const fill = () => {
    if (rendered) return;
    rendered = true;
    for (const [k, v] of entries.slice(0, 5000))
      d.append(jsonTree(v, k, depth + 1, isArr, needle, cache));
    if (entries.length > 5000)
      d.append(
        h("div", { class: "leaf meta" }, `… ${entries.length - 5000} more`),
      );
  };
  if (d.open) fill();
  d.addEventListener("toggle", fill);
  return d;
}

function hexDump(bytes, max = 64 * 1024) {
  const n = Math.min(bytes.length, max);
  let out = "";
  for (let i = 0; i < n; i += 16) {
    const slice = bytes.subarray(i, Math.min(i + 16, n));
    const hex = [...slice]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(" ")
      .padEnd(47, " ");
    const asc = [...slice]
      .map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : "."))
      .join("");
    out += `<span class="off">${i.toString(16).padStart(8, "0")}</span>  ${hex}  <span class="asc">${esc(asc)}</span>\n`;
  }
  if (bytes.length > max) out += `\n… ${fmtBytes(bytes.length - max)} more`;
  return h("div", { class: "hex", html: out });
}

function formatXML(xml) {
  let pad = 0;
  return xml
    .replace(/>\s*</g, ">\n<")
    .split("\n")
    .map((line) => {
      if (/^<\/\w/.test(line)) pad = Math.max(0, pad - 1);
      const out = "  ".repeat(pad) + line;
      if (
        /^<\w[^>]*[^/]>.*$/.test(line) &&
        !/<\/\w/.test(line) &&
        !/^<(br|img|meta|link|input|hr)\b/i.test(line)
      )
        pad++;
      return out;
    })
    .join("\n");
}

function availableModes(bytes, ct) {
  if (!bytes || !bytes.length) return [];
  const modes = [];
  const text = !looksBinary(bytes) || isTextType(ct);
  if (/^image\//i.test(ct) && !/svg/i.test(ct)) return ["Preview", "Hex"];
  if (text) {
    const s = bytesToText(bytes.subarray(0, 1)).trim();
    const isJson = /json|graphql/i.test(ct) || s === "{" || s === "[";
    if (isJson) modes.push("Tree", "Pretty");
    else if (/x-www-form-urlencoded/i.test(ct)) modes.push("Form");
    else if (/xml|html|svg/i.test(ct)) modes.push("Pretty");
    if (/svg/i.test(ct)) modes.push("Preview");
    modes.push("Text");
  }
  modes.push("Hex");
  return [...new Set(modes)];
}

function renderBody(bytes, ct, mode, needle = "") {
  if (!bytes || !bytes.length)
    return h("div", { class: "pane-empty body-empty" }, "No body");
  if (mode === "Hex") return hexDump(bytes);
  if (mode === "Preview") {
    const url = URL.createObjectURL(
      new Blob([bytes], { type: (ct || "").split(";")[0] || "image/png" }),
    );
    return h(
      "div",
      { class: "preview-img" },
      h("img", {
        src: url,
        onload: () => setTimeout(() => URL.revokeObjectURL(url), 1000),
      }),
    );
  }
  const text = bytesToText(bytes.length > 5e6 ? bytes.subarray(0, 5e6) : bytes);
  if (mode === "Tree" || mode === "Pretty") {
    if (/xml|html|svg/i.test(ct) && mode === "Pretty")
      return h(
        "pre",
        { class: "code" },
        ...markMatches(formatXML(text), needle),
      );
    try {
      const v = JSON.parse(text);
      if (mode === "Tree")
        return h(
          "div",
          { class: "jtree" },
          jsonTree(
            v,
            undefined,
            0,
            false,
            needle,
            needle ? new WeakMap() : null,
          ),
        );
      return h("pre", {
        class: "code",
        html: highlightInHtml(
          highlightJSON(JSON.stringify(v, null, 2)),
          needle,
        ),
      });
    } catch {
      return h("pre", { class: "code" }, ...markMatches(text, needle));
    }
  }
  if (mode === "Form") {
    const params = [...new URLSearchParams(text)];
    return kvTable(params);
  }
  return h(
    "pre",
    { class: "code" },
    ...markMatches(text, needle),
    bytes.length > 5e6 ? `\n\n… truncated (${fmtBytes(bytes.length)})` : "",
  );
}

// Search bar + rendered body for the Body tab. Highlights matches and lets
// the user step through them without losing focus of the search input.
function searchableBody(side, bytes, ct, mode) {
  if (!bytes || !bytes.length) return renderBody(bytes, ct, mode);
  const needle = (S.bodySearch[side] || "").trim().toLowerCase();
  const content = renderBody(bytes, ct, mode, needle);
  const bar = bodySearchBar(side, content, needle);
  return h("div", { class: "body-search-wrap" }, bar, content);
}

function bodySearchBar(side, contentEl, needle) {
  const marks = needle ? [...contentEl.querySelectorAll("mark.hl")] : [];
  const cur = marks.length
    ? (((S.bodySearchIdx[side] || 0) % marks.length) + marks.length) %
      marks.length
    : 0;
  S.bodySearchIdx[side] = cur;
  if (marks.length) {
    marks[cur].classList.add("cur");
    requestAnimationFrame(() =>
      marks[cur]?.scrollIntoView({ block: "center" }),
    );
  }
  const nav = (delta) => {
    if (!marks.length) return;
    S.bodySearchIdx[side] = cur + delta;
    S.bodySearchFocus = side;
    renderDetail();
  };
  const input = h("input", {
    type: "text",
    class: "body-search-input",
    placeholder: "Find in body…",
    title:
      "Find text in the body below — Enter for next, Shift+Enter for previous",
    value: S.bodySearch[side] || "",
    oninput: (e) => {
      S.bodySearch[side] = e.target.value;
      S.bodySearchIdx[side] = 0;
      S.bodySearchFocus = side;
      renderDetail();
    },
    onkeydown: (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        nav(e.shiftKey ? -1 : 1);
      } else if (e.key === "Escape") {
        S.bodySearch[side] = "";
        renderDetail();
      }
    },
  });
  return h(
    "div",
    { class: "body-search-bar" },
    h("span", { class: "body-search-icon" }, "🔎"),
    input,
    needle
      ? h(
          "span",
          { class: "body-search-count" },
          marks.length ? `${cur + 1} / ${marks.length}` : "No matches",
        )
      : null,
    h(
      "button",
      {
        class: "btn small",
        title: "Jump to the previous match",
        disabled: !marks.length,
        onclick: () => nav(-1),
      },
      "‹",
    ),
    h(
      "button",
      {
        class: "btn small",
        title: "Jump to the next match",
        disabled: !marks.length,
        onclick: () => nav(1),
      },
      "›",
    ),
  );
}

function kvTable(pairs, emptyText = "None") {
  if (!pairs || !pairs.length)
    return h("div", { class: "pane-empty" }, emptyText);
  return h(
    "table",
    { class: "kv" },
    h(
      "tbody",
      null,
      pairs.map(([k, v]) =>
        h("tr", null, h("td", null, k), h("td", { class: "mono" }, v)),
      ),
    ),
  );
}

function parseCookies(str) {
  return String(str || "")
    .split(";")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => {
      const i = s.indexOf("=");
      return i === -1
        ? [s, ""]
        : [s.slice(0, i), decodeURIComponentSafe(s.slice(i + 1))];
    });
}

function decodeURIComponentSafe(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

function setCookieTable(pairs) {
  const cookies = (pairs || [])
    .filter(([k]) => k.toLowerCase() === "set-cookie")
    .map(([, v]) => v);
  if (!cookies.length)
    return h("div", { class: "pane-empty" }, "No cookies set");
  return h(
    "table",
    { class: "kv" },
    h(
      "tbody",
      null,
      cookies.map((c) => {
        const [first, ...attrs] = c.split(";");
        const i = first.indexOf("=");
        return h(
          "tr",
          null,
          h("td", null, first.slice(0, i)),
          h(
            "td",
            { class: "mono" },
            decodeURIComponentSafe(first.slice(i + 1)),
            h(
              "div",
              { class: "dim", style: { color: "var(--fg-faint)" } },
              attrs.join(";").trim(),
            ),
          ),
        );
      }),
    ),
  );
}

function timingView(d) {
  const t = d.timing || {};
  const total = (t.end || Date.now()) - t.start;
  const phases = [
    ["Request sent", t.start, t.sent],
    ["Waiting (TTFB)", t.sent, t.firstByte],
    ["Content download", t.firstByte, t.end],
  ].filter(([, a, b]) => a && b);
  const rows = phases.map(([name, a, b]) => {
    const left = ((a - t.start) / Math.max(total, 1)) * 100;
    const width = ((b - a) / Math.max(total, 1)) * 100;
    return h(
      "tr",
      null,
      h("td", null, name),
      h(
        "td",
        null,
        h(
          "div",
          { style: { position: "relative", height: "10px", marginTop: "4px" } },
          h("div", {
            class: "timing-bar",
            style: {
              position: "absolute",
              left: left + "%",
              width: Math.max(width, 0.5) + "%",
            },
          }),
        ),
      ),
      h(
        "td",
        { style: { width: "80px", textAlign: "right" } },
        fmtDuration(b - a),
      ),
    );
  });
  return h(
    "div",
    null,
    h(
      "table",
      { class: "kv" },
      h(
        "tbody",
        null,
        h(
          "tr",
          null,
          h("td", null, "Started"),
          h(
            "td",
            { colspan: 2 },
            new Date(t.start).toLocaleString() +
              " " +
              fmtTime(t.start).slice(8),
          ),
        ),
        h(
          "tr",
          null,
          h("td", null, "Total duration"),
          h(
            "td",
            { colspan: 2 },
            fmtDuration(t.end ? total : null) || "In progress…",
          ),
        ),
        ...rows,
      ),
    ),
  );
}

function wsView(d) {
  const msgs = d.wsMessages || [];
  if (!msgs.length) return h("div", { class: "pane-empty" }, "No messages yet");
  return h(
    "div",
    null,
    msgs.map((m) =>
      h(
        "div",
        { class: "ws-msg" },
        h("span", { class: m.dir }, m.dir === "out" ? "↑" : "↓"),
        h(
          "span",
          { class: "dim", style: { color: "var(--fg-faint)" } },
          fmtTime(m.time),
        ),
        h(
          "span",
          { class: "data" },
          m.text !== undefined
            ? m.text
            : m.base64 !== undefined
              ? `<binary ${fmtBytes(m.length)}> ${m.base64.slice(0, 120)}`
              : `<${m.type}>`,
        ),
        h(
          "span",
          { style: { textAlign: "right", color: "var(--fg-faint)" } },
          `${m.type} · ${fmtBytes(m.length)}`,
        ),
      ),
    ),
  );
}

function rawRequestText(d) {
  const u = new URL(d.url);
  const body = b64ToBytes(d.reqBody);
  const head = `${d.method} ${d.tunnel ? u.host : u.pathname + u.search} HTTP/${d.httpVersion}\n${headersToText(d.reqHeaders)}`;
  return (
    head +
    "\n\n" +
    (looksBinary(body)
      ? `<binary ${fmtBytes(body.length)}>`
      : bytesToText(body))
  );
}

function rawResponseText(d) {
  if (!d.status) return d.error || "No response";
  const body = d.resBody ? b64ToBytes(d.resBody) : new Uint8Array();
  const head = `HTTP/${d.httpVersion} ${d.status} ${d.statusMessage || ""}\n${headersToText(d.resHeaders)}`;
  return (
    head +
    "\n\n" +
    (looksBinary(body)
      ? `<binary ${fmtBytes(body.length)}>`
      : bytesToText(body))
  );
}

function rawRequest(d) {
  return h("pre", { class: "code" }, rawRequestText(d));
}
function rawResponse(d) {
  if (!d.status)
    return h("div", { class: "pane-empty" }, d.error || "No response");
  return h("pre", { class: "code" }, rawResponseText(d));
}
