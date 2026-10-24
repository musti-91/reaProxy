/* Tools window (rule editors, SSL proxying, throttle, reverse proxy, settings, certificate),
   Compose and Breakpoint dialogs. Relies on globals from app.js: S, saveConfig, selectFlow, refreshState. */

const METHODS = ['ANY', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
const MATCH_FIELDS = [
  { key: 'name', label: 'Name', type: 'text', placeholder: 'Untitled rule' },
  { key: 'pattern', label: 'Matching URL', type: 'text', placeholder: 'https://api.example.com/v1/*', hint: 'Wildcard: * matches anything, ? one character. Scheme is optional. Switch to Regex for full control.' },
  [
    { key: 'matchType', label: 'Match using', type: 'select', options: [['wildcard', 'Wildcard'], ['regex', 'Regex']] },
    { key: 'method', label: 'HTTP method', type: 'select', options: METHODS.map((m) => [m, m === 'ANY' ? 'Any method' : m]) },
  ],
];

const RULE_TOOLS = {
  breakpoints: {
    title: 'Breakpoints',
    desc: 'Pause matching requests and/or responses, edit method, URL, headers, body or status, then execute or abort.',
    defaults: { request: true, response: true },
    fields: [...MATCH_FIELDS, { key: 'request', label: 'Pause on Request', type: 'check' }, { key: 'response', label: 'Pause on Response', type: 'check' }],
    sub: (r) => [r.request && 'Request', r.response && 'Response'].filter(Boolean).join(' + '),
  },
  mapLocal: {
    title: 'Map Local',
    desc: 'Return a local file or custom content instead of contacting the server. Great for mocking APIs.',
    defaults: { status: 200, headers: 'Content-Type: application/json; charset=utf-8', body: '{\n  "message": "Hello from Rae Proxy"\n}' },
    fields: [
      ...MATCH_FIELDS,
      { key: 'status', label: 'Status code', type: 'number' },
      { key: 'headers', label: 'Response headers (one per line)', type: 'textarea' },
      { key: 'filePath', label: 'Local file (overrides body below)', type: 'file' },
      { key: 'body', label: 'Response body', type: 'code' },
    ],
    sub: (r) => `→ ${r.filePath ? r.filePath.split('/').pop() : r.status || 200}`,
  },
  mapRemote: {
    title: 'Map Remote',
    desc: 'Redirect matching requests to a different scheme, host, port, path or query — e.g. production → localhost.',
    defaults: { toProtocol: '', toHost: 'localhost', toPort: '3000', toPath: '', toQuery: '', preserveHost: false },
    fields: [
      ...MATCH_FIELDS,
      [
        { key: 'toProtocol', label: 'To protocol', type: 'select', options: [['', 'Keep'], ['http', 'http'], ['https', 'https']] },
        { key: 'toHost', label: 'To host', type: 'text', placeholder: 'Keep' },
        { key: 'toPort', label: 'To port', type: 'text', placeholder: 'Default' },
      ],
      [
        { key: 'toPath', label: 'To path', type: 'text', placeholder: 'Keep (e.g. /v2/users)' },
        { key: 'toQuery', label: 'To query', type: 'text', placeholder: 'Keep (e.g. ?debug=1)' },
      ],
      { key: 'preserveHost', label: 'Preserve original Host header', type: 'check' },
    ],
    sub: (r) => `→ ${r.toProtocol ? r.toProtocol + '://' : ''}${r.toHost || '*'}${r.toPort ? ':' + r.toPort : ''}${r.toPath || ''}`,
  },
  rewrite: {
    title: 'Rewrite',
    desc: 'Add, modify or remove headers, rewrite the status code, URL or body text — all without writing code. Each rule can have multiple actions, applied to the request and/or response.',
    defaults: { actions: [] },
    fields: [...MATCH_FIELDS, { key: 'actions', label: 'Actions', type: 'actions' }],
    sub: (r) => `${(r.actions || []).length} action${(r.actions || []).length === 1 ? '' : 's'}`,
  },
  scripting: {
    title: 'Scripting',
    desc: 'Modify requests and responses with JavaScript. Define onRequest(context, url, request) and onResponse(context, url, request, response). Use console.log — output appears in the Script Console. sharedState persists between runs.',
    defaults: () => ({ request: true, response: true, code: S.scriptTemplate }),
    fields: [...MATCH_FIELDS, { key: 'request', label: 'Run onRequest', type: 'check' }, { key: 'response', label: 'Run onResponse', type: 'check' }, { key: 'code', label: 'Script', type: 'code', tall: true }],
    sub: (r) => [r.request && 'Request', r.response && 'Response'].filter(Boolean).join(' + '),
  },
  blockList: {
    title: 'Block List',
    desc: 'Block matching requests — respond with 403 Forbidden or drop the connection.',
    defaults: { action: 'block' },
    fields: [...MATCH_FIELDS, { key: 'action', label: 'Action', type: 'select', options: [['block', 'Return 403 Forbidden'], ['drop', 'Drop connection']] }],
    sub: (r) => (r.action === 'drop' ? 'Drop' : '403'),
  },
  allowList: {
    title: 'Allow List',
    desc: 'When enabled, only matching requests are recorded. Everything else is still proxied, just hidden.',
    defaults: {},
    fields: [...MATCH_FIELDS],
  },
};

const NAV = [
  ['ssl', 'SSL Proxying'],
  ['breakpoints', 'Breakpoints'],
  ['mapLocal', 'Map Local'],
  ['mapRemote', 'Map Remote'],
  ['rewrite', 'Rewrite'],
  ['scripting', 'Scripting'],
  ['blockList', 'Block List'],
  ['allowList', 'Allow List'],
  ['throttle', 'Network Conditions'],
  ['reverse', 'Reverse Proxy'],
  ['upstream', 'Upstream Proxy'],
  ['certificate', 'Certificate'],
  ['general', 'Settings'],
];

let toolsModal = null;

function openTools(section = 'ssl', prefill) {
  if (toolsModal) toolsModal.close();
  const nav = h('div', { class: 'tools-nav' });
  const main = h('div', { class: 'tools-main' });
  toolsModal = openModal({
    title: 'Tools',
    sub: 'Everything is free & unlocked',
    cls: 'wide',
    body: h('div', { class: 'tools' }, nav, main),
    foot: [h('button', { class: 'btn primary', onclick: () => toolsModal.close() }, 'Done')],
    onClose: () => { toolsModal = null; },
  });
  toolsModal.modal.querySelector('.modal-body').style.padding = '0';
  let current = section;
  const drawNav = () => nav.replaceChildren(...NAV.map(([k, label]) => {
      const enabled = S.config[k]?.enabled && (S.config[k].rules ? S.config[k].rules.length > 0 : true);
      return h('div', { class: 'sb-item' + (k === current ? ' sel' : ''), onclick: () => show(k) }, h('span', { class: 'name' }, label), enabled ? h('span', { class: 'on-dot' }) : null);
    }));
  const show = (key, pf) => {
    current = key;
    drawNav();
    main.replaceChildren();
    if (RULE_TOOLS[key]) renderRuleTool(main, key, pf);
    else ({ ssl: renderSSL, throttle: renderThrottle, reverse: renderReverse, upstream: renderUpstream, certificate: renderCertificate, general: renderGeneral })[key](main);
  };
  toolsModal.show = show;
  toolsModal.drawNav = drawNav;
  show(section, prefill);
}

function toolHead(title, desc, enabled, onToggle) {
  return h('div', { class: 'tools-head' },
    h('h3', null, title, onToggle ? switchEl(enabled, onToggle) : null, onToggle ? h('span', { style: { fontWeight: 400, fontSize: '12px', color: 'var(--fg-dim)' } }, enabled ? 'Enabled' : 'Disabled') : null),
    h('p', null, desc));
}

const ACTION_TYPES = [['header', 'Header'], ['status', 'Status Code'], ['body', 'Body Text'], ['url', 'URL'], ['method', 'Method']];
const REQUEST_ONLY_TYPES = ['url', 'method'];
const RESPONSE_ONLY_TYPES = ['status'];

function newAction() {
  return { id: uid(), phase: 'request', type: 'header', op: 'set', name: '', value: '', find: '', replace: '', regex: false, host: '', path: '', query: '' };
}

function actionsField(rule, onChange) {
  if (!rule.actions) rule.actions = [];
  const list = h('div', { class: 'actions-list' });
  const commit = () => onChange('actions', rule.actions);
  const draw = () => {
    list.replaceChildren(...rule.actions.map((a, i) => actionRow(a, i)));
    if (!rule.actions.length) list.append(h('div', { class: 'note' }, 'No actions yet. Add one below — e.g. “Set header X-Debug: 1” or “Rewrite status to 500”.'));
  };
  function actionRow(a, i) {
    if (REQUEST_ONLY_TYPES.includes(a.type)) a.phase = 'request';
    if (RESPONSE_ONLY_TYPES.includes(a.type)) a.phase = 'response';
    const typeSel = h('select', { onchange: (e) => { a.type = e.target.value; draw(); commit(); } },
      ACTION_TYPES.map(([v, l]) => h('option', { value: v, selected: a.type === v }, l)));
    const phaseLocked = REQUEST_ONLY_TYPES.includes(a.type) || RESPONSE_ONLY_TYPES.includes(a.type);
    const phaseSel = phaseLocked
      ? h('span', { class: 'dim', style: { padding: '0 4px' } }, a.phase === 'request' ? 'Request' : 'Response')
      : h('select', { onchange: (e) => { a.phase = e.target.value; commit(); } },
          [['request', 'Request'], ['response', 'Response']].map(([v, l]) => h('option', { value: v, selected: a.phase === v }, l)));
    const extra = [];
    if (a.type === 'header') {
      extra.push(
        h('select', { onchange: (e) => { a.op = e.target.value; draw(); commit(); } },
          [['set', 'Set'], ['add', 'Add'], ['remove', 'Remove']].map(([v, l]) => h('option', { value: v, selected: (a.op || 'set') === v }, l))),
        h('input', { type: 'text', placeholder: 'Header name', value: a.name || '', oninput: (e) => { a.name = e.target.value; commit(); } }));
      if (a.op !== 'remove') extra.push(h('input', { type: 'text', placeholder: 'Value', value: a.value || '', oninput: (e) => { a.value = e.target.value; commit(); } }));
    } else if (a.type === 'status') {
      extra.push(h('input', { type: 'number', placeholder: '500', value: a.value || '', style: { maxWidth: '100px' }, oninput: (e) => { a.value = e.target.value; commit(); } }));
    } else if (a.type === 'body') {
      extra.push(
        h('input', { type: 'text', placeholder: a.regex ? 'Pattern (regex)' : 'Find text', value: a.find || '', oninput: (e) => { a.find = e.target.value; commit(); } }),
        h('input', { type: 'text', placeholder: 'Replace with', value: a.replace || '', oninput: (e) => { a.replace = e.target.value; commit(); } }),
        h('label', { class: 'check', style: { marginBottom: 0 } }, h('input', { type: 'checkbox', checked: !!a.regex, onchange: (e) => { a.regex = e.target.checked; commit(); } }), 'Regex'));
    } else if (a.type === 'url') {
      extra.push(
        h('input', { type: 'text', placeholder: 'Host (keep if empty)', value: a.host || '', oninput: (e) => { a.host = e.target.value; commit(); } }),
        h('input', { type: 'text', placeholder: 'Path', value: a.path || '', oninput: (e) => { a.path = e.target.value; commit(); } }),
        h('input', { type: 'text', placeholder: 'Query (e.g. a=1&b=2)', value: a.query || '', oninput: (e) => { a.query = e.target.value; commit(); } }));
    } else if (a.type === 'method') {
      extra.push(h('select', { onchange: (e) => { a.value = e.target.value; commit(); } },
        METHODS.slice(1).map((m) => h('option', { value: m, selected: a.value === m }, m))));
    }
    return h('div', { class: 'action-row' }, phaseSel, typeSel, ...extra, h('span', { class: 'grow' }),
      h('button', { class: 'btn danger small', onclick: () => { rule.actions.splice(i, 1); draw(); commit(); } }, 'Remove'));
  }
  draw();
  return h('div', { class: 'field', style: { flex: 1 } },
    h('label', null, 'Actions'),
    list,
    h('button', { class: 'btn', style: { alignSelf: 'flex-start' }, onclick: () => { rule.actions.push(newAction()); draw(); commit(); } }, '＋ Add Action'));
}

function fieldEl(f, rule, onChange) {
  if (Array.isArray(f)) return h('div', { class: f.length === 3 ? 'row3' : 'row2' }, f.map((x) => fieldEl(x, rule, onChange)));
  if (f.type === 'actions') return actionsField(rule, onChange);
  const val = rule[f.key];
  if (f.type === 'check') {
    return h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: !!val, onchange: (e) => onChange(f.key, e.target.checked) }), f.label);
  }
  let input;
  if (f.type === 'select') {
    input = h('select', { onchange: (e) => onChange(f.key, e.target.value) }, f.options.map(([v, l]) => h('option', { value: v, selected: (val ?? f.options[0][0]) === v }, l)));
  } else if (f.type === 'textarea' || f.type === 'code') {
    input = codeArea({ class: f.tall ? 'code' : '', value: val ?? '', oninput: (e) => onChange(f.key, e.target.value) });
    if (f.type === 'code' && !f.tall) input.style.minHeight = '200px';
  } else if (f.type === 'file') {
    const txt = h('input', { type: 'text', value: val || '', placeholder: 'None — use body below', oninput: (e) => onChange(f.key, e.target.value) });
    input = h('div', { style: { display: 'flex', gap: '6px' } }, txt,
      h('button', { class: 'btn', onclick: async () => { const p = await rae.invoke('mapLocal:pickFile'); if (p) { txt.value = p; onChange(f.key, p); } } }, 'Choose…'),
      h('button', { class: 'btn', onclick: () => { txt.value = ''; onChange(f.key, ''); } }, 'Clear'));
  } else {
    input = h('input', { type: f.type === 'number' ? 'number' : 'text', value: val ?? '', placeholder: f.placeholder || '', spellcheck: false, oninput: (e) => onChange(f.key, f.type === 'number' ? Number(e.target.value) : e.target.value) });
  }
  return h('div', { class: 'field', style: f.tall ? { flex: 1 } : null }, h('label', null, f.label), input, f.hint ? h('div', { class: 'hint' }, f.hint) : null);
}

function newRule(key, prefill) {
  const def = RULE_TOOLS[key];
  const defaults = typeof def.defaults === 'function' ? def.defaults() : def.defaults;
  return { id: uid(), enabled: true, name: '', pattern: '', matchType: 'wildcard', method: 'ANY', ...structuredClone(defaults), ...(prefill || {}) };
}

function renderRuleTool(container, key, prefill) {
  const def = RULE_TOOLS[key];
  const tool = structuredClone(S.config[key]);
  let selId = tool.rules[0]?.id;
  if (prefill) {
    const r = newRule(key, prefill);
    tool.rules.push(r);
    tool.enabled = true;
    selId = r.id;
  }
  const persist = debounce(() => saveConfig({ [key]: tool }).then(() => toolsModal?.drawNav()), 250);
  if (prefill) persist();

  const list = h('div', { class: 'rule-items' });
  const editor = h('div', { class: 'rule-editor' + (key === 'scripting' || key === 'rewrite' ? ' full' : '') });

  const renderList = () => {
    list.replaceChildren(...tool.rules.map((r) => h('div', { class: 'rule-item' + (r.id === selId ? ' sel' : ''), onclick: () => { selId = r.id; renderList(); renderEditor(); } },
      h('input', { type: 'checkbox', checked: r.enabled !== false, onclick: (e) => e.stopPropagation(), onchange: (e) => { r.enabled = e.target.checked; persist(); } }),
      h('div', { class: 'ri-text' },
        h('div', { class: 'ri-name' }, r.name || r.pattern || 'Untitled'),
        h('div', { class: 'ri-sub' }, [r.method && r.method !== 'ANY' ? r.method : '', r.pattern || '—', def.sub ? def.sub(r) : ''].filter(Boolean).join('  '))))));
    if (!tool.rules.length) list.append(h('div', { class: 'note' }, 'No rules yet. Click “Add Rule”, or right-click any request → Tools.'));
  };
  const renderEditor = () => {
    const r = tool.rules.find((x) => x.id === selId);
    if (!r) return editor.replaceChildren(h('div', { class: 'pane-empty' }, 'Select or add a rule'));
    editor.replaceChildren(...def.fields.map((f) => fieldEl(f, r, (k, v) => { r[k] = v; persist(); renderList(); })));
  };

  container.append(
    toolHead(def.title, def.desc, tool.enabled, (on) => { tool.enabled = on; persist(); }),
    h('div', { class: 'tools-content' },
      h('div', { class: 'rule-list' }, list, h('div', { class: 'rule-actions' },
        h('button', { class: 'btn', onclick: () => { const r = newRule(key); tool.rules.push(r); selId = r.id; persist(); renderList(); renderEditor(); } }, '＋ Add Rule'),
        h('button', { class: 'btn', onclick: () => { const r = tool.rules.find((x) => x.id === selId); if (!r) return; const c = { ...structuredClone(r), id: uid(), name: (r.name || 'Rule') + ' copy' }; tool.rules.push(c); selId = c.id; persist(); renderList(); renderEditor(); } }, 'Duplicate'),
        h('span', { class: 'grow' }),
        h('button', { class: 'btn danger', onclick: () => { tool.rules = tool.rules.filter((x) => x.id !== selId); selId = tool.rules[0]?.id; persist(); renderList(); renderEditor(); } }, 'Delete'))),
      editor));
  renderList();
  renderEditor();
}

function listEditor(label, values, onChange, hint) {
  return h('div', { class: 'field list-editor' }, h('label', null, label),
    codeArea({ value: (values || []).join('\n'), oninput: debounce((e) => onChange(e.target.value.split('\n').map((s) => s.trim()).filter(Boolean)), 300) }),
    hint ? h('div', { class: 'hint' }, hint) : null);
}

function renderSSL(container) {
  const ssl = structuredClone(S.config.ssl);
  const save = () => saveConfig({ ssl });
  container.append(
    toolHead('SSL Proxying', 'Decrypt HTTPS traffic for matching hosts. Requires the Rae Proxy root certificate to be trusted by the client. Apps that use certificate pinning will fail — add them to the exclude list.'),
    h('div', { class: 'rule-editor' },
      h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: ssl.interceptAll, onchange: (e) => { ssl.interceptAll = e.target.checked; save(); } }), h('b', null, 'Enable SSL Proxying for all domains'), h('span', { style: { color: 'var(--fg-dim)' } }, ' (except the exclude list)')),
      h('div', { class: 'row2' },
        listEditor('Include list (used when “all domains” is off)', ssl.include, (v) => { ssl.include = v; save(); }, 'One host per line. Wildcards OK: *.example.com'),
        listEditor('Exclude list (never decrypted)', ssl.exclude, (v) => { ssl.exclude = v; save(); }, 'Apple services pin certificates and are excluded by default.'))));
}

const THROTTLE_PRESETS = {
  Custom: null,
  '100% Loss': { latency: 30000, downloadKbps: 1 },
  'Very Bad Network': { latency: 1500, downloadKbps: 50 },
  EDGE: { latency: 850, downloadKbps: 240 },
  '3G': { latency: 300, downloadKbps: 780 },
  'DSL': { latency: 50, downloadKbps: 2000 },
  LTE: { latency: 65, downloadKbps: 12000 },
  'Wi-Fi': { latency: 2, downloadKbps: 30000 },
};

function renderThrottle(container) {
  const t = structuredClone(S.config.throttle);
  const save = () => saveConfig({ throttle: t });
  const lat = h('input', { type: 'number', value: t.latency, oninput: (e) => { t.latency = Number(e.target.value); t.preset = 'Custom'; sel.value = 'Custom'; save(); } });
  const dl = h('input', { type: 'number', value: t.downloadKbps, oninput: (e) => { t.downloadKbps = Number(e.target.value); t.preset = 'Custom'; sel.value = 'Custom'; save(); } });
  const sel = h('select', { onchange: (e) => { t.preset = e.target.value; const p = THROTTLE_PRESETS[t.preset]; if (p) { Object.assign(t, p); lat.value = p.latency; dl.value = p.downloadKbps; } save(); } },
    Object.keys(THROTTLE_PRESETS).map((k) => h('option', { value: k, selected: t.preset === k }, k)));
  container.append(
    toolHead('Network Conditions', 'Simulate slow or lossy networks for every request passing through the proxy.', t.enabled, (on) => { t.enabled = on; save(); }),
    h('div', { class: 'rule-editor' },
      h('div', { class: 'field' }, h('label', null, 'Preset'), sel),
      h('div', { class: 'row2' },
        h('div', { class: 'field' }, h('label', null, 'Added latency (ms)'), lat),
        h('div', { class: 'field' }, h('label', null, 'Download bandwidth (kbps, 0 = unlimited)'), dl))));
}

function renderReverse(container) {
  const list = structuredClone(S.config.reverseProxies || []);
  const save = debounce(() => saveConfig({ reverseProxies: list }), 400);
  const body = h('div');
  const draw = () => body.replaceChildren(
    ...list.map((r, i) => h('div', { class: 'card', style: { display: 'grid', gridTemplateColumns: '30px 110px 1fr 100px 90px 70px', gap: '10px', alignItems: 'end' } },
      h('input', { type: 'checkbox', checked: r.enabled !== false, style: { marginBottom: '8px' }, onchange: (e) => { r.enabled = e.target.checked; save(); } }),
      h('div', { class: 'field', style: { margin: 0 } }, h('label', null, 'Local port'), h('input', { type: 'number', value: r.localPort, oninput: (e) => { r.localPort = Number(e.target.value); save(); } })),
      h('div', { class: 'field', style: { margin: 0 } }, h('label', null, 'Remote host'), h('input', { type: 'text', value: r.remoteHost, oninput: (e) => { r.remoteHost = e.target.value; save(); } })),
      h('div', { class: 'field', style: { margin: 0 } }, h('label', null, 'Remote port'), h('input', { type: 'number', value: r.remotePort, oninput: (e) => { r.remotePort = Number(e.target.value); save(); } })),
      h('label', { class: 'check', style: { marginBottom: '8px' } }, h('input', { type: 'checkbox', checked: !!r.secure, onchange: (e) => { r.secure = e.target.checked; save(); } }), 'HTTPS'),
      h('button', { class: 'btn danger', style: { marginBottom: '2px' }, onclick: () => { list.splice(i, 1); save(); draw(); } }, 'Remove'))),
    h('button', { class: 'btn', onclick: () => { list.push({ id: uid(), enabled: true, localPort: 8080 + list.length, remoteHost: 'api.example.com', remotePort: 443, secure: true }); save(); draw(); } }, '＋ Add Reverse Proxy'));
  container.append(
    toolHead('Reverse Proxy', 'Listen on a local port and forward everything to a remote server — useful for clients that can’t be configured to use a proxy. Point them at http://localhost:<local port>.'),
    h('div', { class: 'rule-editor' }, body));
  draw();
}

function renderGeneral(container) {
  const c = S.config;
  const port = h('input', { type: 'number', value: c.port });
  container.append(
    toolHead('Settings', 'Proxy listener and capture options.'),
    h('div', { class: 'rule-editor' },
      h('div', { class: 'row2' },
        h('div', { class: 'field' }, h('label', null, 'Proxy port'), h('div', { style: { display: 'flex', gap: '6px' } }, port, h('button', { class: 'btn', onclick: async () => { await saveConfig({ port: Number(port.value) }); await refreshState(); toast(S.proxy.running ? `Listening on ${S.proxy.port}` : S.proxy.error); } }, 'Apply'))),
        h('div', { class: 'field' }, h('label', null, 'Max recorded requests'), h('input', { type: 'number', value: c.maxFlows, oninput: debounce((e) => saveConfig({ maxFlows: Number(e.target.value) }), 400) }))),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: c.listenAll, onchange: (e) => saveConfig({ listenAll: e.target.checked }) }), 'Allow connections from other devices on the network (iOS, Android, other computers)'),
      h('div', { class: 'hint', style: { margin: '-4px 0 12px 22px', color: 'var(--fg-faint)', fontSize: '11px' } }, 'Each new device is refused until you approve it. You’ll be asked the first time it connects.'),
      h('div', { class: 'row2' },
        listEditor('Allowed devices', c.allowedClients, (v) => saveConfig({ allowedClients: v }), 'One IP per line. Wildcards OK: 192.168.1.*'),
        listEditor('Denied devices', c.deniedClients, (v) => saveConfig({ deniedClients: v }), 'Refused silently, without asking.')),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: c.http2, onchange: (e) => saveConfig({ http2: e.target.checked }) }), 'Enable HTTP/2 — offer it to clients and use it with servers when the client does (needed for gRPC)'),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: c.verifyUpstreamTLS, onchange: (e) => saveConfig({ verifyUpstreamTLS: e.target.checked }) }), 'Verify upstream server TLS certificates (turn off for self-signed dev servers)'),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: c.noCache, onchange: (e) => saveConfig({ noCache: e.target.checked }) }), 'No Caching — strip conditional headers so every response is fresh'),
      h('div', { class: 'field', style: { maxWidth: '280px' } }, h('label', null, 'Max captured body size (MB)'), h('input', { type: 'number', value: Math.round(c.maxBodySize / 1048576), oninput: debounce((e) => saveConfig({ maxBodySize: Number(e.target.value) * 1048576 }), 400) })),
      h('div', { class: 'card' }, h('h4', null, 'License'), h('p', null, 'Rae Proxy is completely free. There are no plans, trials, request limits or locked features.'))));
}

function renderCertificate(container) {
  const body = h('div', { class: 'rule-editor' });
  const draw = () => {
    const ca = S.ca;
    const addrs = (S.proxy.addresses || []).map((a) => `${a.address}:${S.proxy.port}`);
    body.replaceChildren(
      h('div', { class: 'card' },
        h('h4', null, 'This Mac'),
        h('p', null, 'Root certificate: ', h('b', null, ca.commonName)),
        h('p', null, 'Status: ', ca.trusted ? h('span', { class: 'pill-ok' }, 'Installed & trusted') : h('span', { class: 'pill-bad' }, 'Not trusted — HTTPS cannot be decrypted')),
        h('div', { style: { display: 'flex', gap: '8px', marginTop: '10px', flexWrap: 'wrap' } },
          h('button', { class: 'btn primary', onclick: async () => { try { S.ca = await rae.invoke('ca:install'); toast(S.ca.trusted ? 'Certificate trusted' : 'Certificate added — mark it “Always Trust” in Keychain Access'); } catch (e) { toast('Install failed: ' + e.message); } draw(); updateChrome(); } }, ca.trusted ? 'Reinstall' : 'Install & Trust'),
          h('button', { class: 'btn', onclick: () => rae.invoke('ca:export') }, 'Export…'),
          h('button', { class: 'btn', onclick: async () => { S.ca = await rae.invoke('ca:info'); draw(); updateChrome(); } }, 'Check Again'),
          h('button', { class: 'btn danger', onclick: async () => { S.ca = await rae.invoke('ca:regenerate'); draw(); updateChrome(); } }, 'Regenerate…'))),
      h('div', { class: 'card' },
        h('h4', null, 'iOS / Android / other devices'),
        h('p', null, '1. Connect the device to the same Wi-Fi network. Set its HTTP proxy to Manual → ', h('b', { class: 'mono' }, addrs.join('  or  ') || `this Mac's IP:${S.proxy.port}`)),
        h('p', null, '2. On the device, open ', h('b', { class: 'mono' }, 'http://rae.proxy'), ' in the browser and download the certificate.'),
        h('p', null, '3. iOS: Settings → General → VPN & Device Management → install. Then Settings → General → About → Certificate Trust Settings → enable full trust.'),
        h('p', null, '4. Android: Settings → Security → Encryption & credentials → Install a certificate → CA certificate. Apps must opt in to user CAs (network_security_config) on Android 7+.'),
        !S.config.listenAll
          ? h('p', null, h('span', { class: 'pill-bad' }, 'Connections from other devices are off. '), h('span', { class: 'link', onclick: () => toolsModal.show('general') }, 'Turn them on in Settings'), ', then approve the device when Rae asks.')
          : h('p', null, 'The first time a device connects, Rae asks you to allow it. Approved devices are listed in Settings.')),
      h('div', { class: 'card' },
        h('h4', null, 'Simulators & command line'),
        h('p', null, 'iOS Simulator: drag the exported .pem onto the simulator, or run ', h('code', null, `xcrun simctl keychain booted add-root-cert "${ca.path}"`)),
        h('p', null, 'curl / scripts: ', h('code', null, `export https_proxy=http://127.0.0.1:${S.proxy.port} http_proxy=http://127.0.0.1:${S.proxy.port}`)),
        h('p', null, 'Node.js: ', h('code', null, `NODE_EXTRA_CA_CERTS="${ca.path}"`)),
        h('p', null, 'Python requests: ', h('code', null, `REQUESTS_CA_BUNDLE="${ca.path}"`))));
  };
  container.append(toolHead('Certificate', 'Install the Rae Proxy root certificate so HTTPS traffic can be decrypted.'), body);
  draw();
}

// ---------- Compose ----------
function openCompose(init = {}) {
  const method = h('select', null, METHODS.slice(1).map((m) => h('option', { selected: (init.method || 'GET') === m }, m)));
  const url = h('input', { type: 'text', value: init.url || 'https://httpbin.org/anything', spellcheck: false, style: { fontFamily: 'var(--mono)' } });
  const headers = codeArea({ value: headersToText(init.headers || [['Accept', '*/*'], ['User-Agent', 'RaeProxy/1.0']]) });
  const body = codeArea({ value: init.body || '', style: { minHeight: '180px' } });
  let m;
  const send = async () => {
    try {
      const id = await rae.invoke('compose:send', { method: method.value, url: url.value.trim(), headers: textToHeaders(headers.value), body: body.value });
      m.close();
      setTimeout(() => selectFlow(id, true), 150);
    } catch (e) {
      toast(e.message.replace(/^Error invoking remote method '[^']+': (Error: )?/, ''));
    }
  };
  m = openModal({
    title: 'Compose Request',
    body: h('div', null,
      h('div', { class: 'compose-grid field' }, method, url),
      h('div', { class: 'field' }, h('label', null, 'Headers (one per line)'), headers),
      h('div', { class: 'field' }, h('label', null, 'Body'), body)),
    foot: [h('span', { class: 'grow', style: { color: 'var(--fg-dim)' } }, '⌘↩ to send'), h('button', { class: 'btn', onclick: () => m.close() }, 'Cancel'), h('button', { class: 'btn primary', onclick: send }, 'Send')],
  });
  m.modal.addEventListener('keydown', (e) => { if (e.key === 'Enter' && e.metaKey) send(); });
  url.focus();
}

// ---------- Breakpoints ----------
const bpQueue = [];
let bpOpen = null;

function enqueueBreakpoint(bp) {
  bpQueue.push(bp);
  if (!bpOpen) showNextBreakpoint();
  else bpOpen.updateCount();
}

function showNextBreakpoint() {
  const bp = bpQueue.shift();
  if (!bp) { bpOpen = null; return; }
  const isReq = bp.phase === 'request';
  const fields = {};
  const rows = [];
  if (isReq) {
    fields.method = h('select', null, METHODS.slice(1).map((m) => h('option', { selected: bp.method === m }, m)));
    fields.url = h('input', { type: 'text', value: bp.url, spellcheck: false, style: { fontFamily: 'var(--mono)' } });
    rows.push(h('div', { class: 'compose-grid field' }, fields.method, fields.url));
  } else {
    fields.status = h('input', { type: 'number', value: bp.status });
    rows.push(h('div', { class: 'field', style: { maxWidth: '160px' } }, h('label', null, 'Status code'), fields.status));
  }
  fields.headers = codeArea({ value: headersToText(bp.headers), style: { minHeight: '140px' } });
  rows.push(h('div', { class: 'field' }, h('label', null, 'Headers'), fields.headers));
  if (bp.body.binary) rows.push(h('div', { class: 'note' }, `Binary body (${fmtBytes(bp.body.size)}) — will be sent unchanged.`));
  else {
    fields.body = codeArea({ value: bp.body.text, style: { minHeight: '220px' } });
    rows.push(h('div', { class: 'field' }, h('label', null, 'Body'), fields.body));
  }
  const countEl = h('span', { class: 'grow', style: { color: 'var(--fg-dim)' } });
  const finish = async (action) => {
    done = true;
    const data = action === 'execute' ? {
      method: fields.method?.value,
      url: fields.url?.value,
      status: fields.status ? Number(fields.status.value) : undefined,
      headers: textToHeaders(fields.headers.value),
      bodyText: fields.body ? fields.body.value : undefined,
    } : null;
    await rae.invoke('breakpoint:resolve', { id: bp.id, action, data });
    m.close();
  };
  let done = false;
  const m = openModal({
    title: `Breakpoint — ${isReq ? 'Request' : 'Response'}`,
    sub: `#${bp.flowId}`,
    closeOnOverlay: false,
    body: h('div', null, h('div', { class: 'bp-meta' }, `${bp.method || ''} ${bp.url || ''}`), rows),
    foot: [countEl,
      h('button', { class: 'btn danger', onclick: () => finish('abort') }, 'Abort'),
      h('button', { class: 'btn', onclick: () => finish('continue') }, 'Continue Unmodified'),
      h('button', { class: 'btn primary', onclick: () => finish('execute') }, 'Execute')],
    onClose: () => {
      if (!done) rae.invoke('breakpoint:resolve', { id: bp.id, action: 'continue' });
      setTimeout(showNextBreakpoint, 0);
    },
  });
  bpOpen = { updateCount: () => { countEl.textContent = bpQueue.length ? `${bpQueue.length} more paused` : ''; } };
  bpOpen.updateCount();
}

function prettyMaybe(text) {
  try { return JSON.stringify(JSON.parse(text), null, 2); } catch { return text; }
}

// ---------- device setup (shortcut) ----------
function openCertificate() { openTools('certificate'); }

// ---------- New device approval ----------
const clientPrompts = new Set();

function promptClient({ ip }) {
  if (clientPrompts.has(ip) || (S.config.allowedClients || []).includes(ip) || (S.config.deniedClients || []).includes(ip)) return;
  clientPrompts.add(ip);
  let m;
  const decide = async (key) => {
    if (key) await saveConfig({ [key]: [...new Set([...(S.config[key] || []), ip])] });
    m.close();
  };
  m = openModal({
    title: 'Allow this device?',
    cls: 'small',
    closeOnOverlay: false,
    body: h('div', null,
      h('p', { style: { marginTop: 0, lineHeight: 1.5 } }, h('b', { class: 'mono' }, ip), ' is trying to use Rae Proxy. Its connection was refused.'),
      h('p', { style: { color: 'var(--fg-dim)', lineHeight: 1.5 } }, 'Allow it only if it’s a device you’re debugging. Once allowed, it can send traffic through this Mac, and you can see that traffic. Reconnect from the device after allowing it.')),
    foot: [
      h('button', { class: 'btn', onclick: () => decide(null) }, 'Ask Later'),
      h('button', { class: 'btn danger', onclick: () => decide('deniedClients') }, 'Deny'),
      h('button', { class: 'btn primary', onclick: () => decide('allowedClients') }, 'Allow'),
    ],
    onClose: () => clientPrompts.delete(ip),
  });
}

// ---------- Upstream Proxy (Charles: External Proxy) ----------
function renderUpstream(container) {
  const up = structuredClone(S.config.upstreamProxy);
  // passwordEnc is owned by the main process (upstream:setPassword); never write back a stale copy.
  const save = debounce(() => { const { passwordEnc, ...rest } = up; saveConfig({ upstreamProxy: rest }); }, 300);
  const body = h('div', { class: 'rule-editor' });
  const input = (key, attrs = {}) => h('input', { type: 'text', value: up[key] ?? '', spellcheck: false, ...attrs, oninput: (e) => { up[key] = attrs.type === 'number' ? Number(e.target.value) || '' : e.target.value.trim(); save(); } });
  const field = (label, el, hint) => h('div', { class: 'field' }, h('label', null, label), el, hint ? h('div', { class: 'hint' }, hint) : null);

  const draw = () => {
    const pw = h('input', { type: 'password', placeholder: S.upstreamHasPassword ? '•••••••• (saved — type to replace)' : 'None', autocomplete: 'off' });
    const pwSave = async () => {
      S.upstreamHasPassword = await rae.invoke('upstream:setPassword', pw.value);
      pw.value = '';
      toast(S.upstreamHasPassword ? 'Password saved to the Keychain-encrypted store' : 'Password cleared');
      draw();
    };
    body.replaceChildren(...[
      h('div', { class: 'row2' },
        field('Proxy host', input('host', { placeholder: 'proxy.company.com' })),
        field('Port', input('port', { type: 'number', placeholder: '8080' }))),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: up.sameForHttps !== false, onchange: (e) => { up.sameForHttps = e.target.checked; save(); draw(); } }), 'Use the same proxy for HTTPS'),
      up.sameForHttps === false ? h('div', { class: 'row2' },
        field('HTTPS proxy host', input('httpsHost', { placeholder: 'proxy.company.com' })),
        field('HTTPS port', input('httpsPort', { type: 'number', placeholder: '8080' }))) : null,
      h('div', { class: 'row2' },
        field('Username (optional)', input('username', { placeholder: 'None' }), 'Basic authentication. NTLM and Kerberos are not supported.'),
        field('Password', h('div', { style: { display: 'flex', gap: '6px' } }, pw,
          h('button', { class: 'btn', onclick: pwSave }, 'Save'),
          S.upstreamHasPassword ? h('button', { class: 'btn danger', onclick: () => { pw.value = ''; pwSave(); } }, 'Clear') : null),
          'Encrypted with your macOS Keychain; never written to disk in plain text.')),
      listEditor('Bypass — connect directly to these hosts', up.bypass, (v) => { up.bypass = v; save(); }, 'One host per line, wildcards OK (*.internal.company.com). localhost, 127.0.0.1 and *.local always go direct.'),
      h('div', { style: { display: 'flex', gap: '8px' } },
        h('button', { class: 'btn', onclick: async () => {
          const found = await rae.invoke('upstream:detect');
          if (!found) return toast('No proxy is configured in macOS Network settings');
          Object.assign(up, { host: found.host, port: found.port, sameForHttps: found.sameForHttps, httpsHost: found.httpsHost, httpsPort: found.httpsPort, bypass: [...new Set([...(up.bypass || []), ...found.bypass])] });
          save();
          draw();
          toast(`Imported ${found.host}:${found.port} from ${found.service}`);
        } }, 'Import from macOS Network Settings')),
    ].filter(Boolean));
  };
  container.append(
    toolHead('Upstream Proxy', 'Send Rae’s outgoing traffic through another HTTP proxy, for networks that require a company proxy. Applies to HTTP, HTTPS (via CONNECT), HTTP/2, WebSockets and SSL tunnels. Charles calls this “External Proxy”.', up.enabled, (on) => { up.enabled = on; save(); }),
    body);
  draw();
}
