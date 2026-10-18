# Rae Proxy

A free HTTP/HTTPS debugging proxy for macOS (Apple Silicon), inspired by Proxyman. It has no pricing, plans, trials, or locked features.

## Features

- **Capture** HTTP, HTTPS (MITM with a local root CA), and WebSocket traffic, including individual WebSocket messages
- **Inspector**: headers, query, body (JSON tree/pretty, form, XML/HTML, image preview, hex), cookies, Set-Cookie, raw, timing, summary
- **Filtering**: free text plus `method:POST`, `status:4xx`, `host:api`, and `tag:map-local`, with `-term` to exclude. There are also content-type and status chips, and the sidebar groups by domain and client and supports pinned domains.
- **SSL Proxying**: intercept all domains or use an include/exclude list. Hosts that aren't intercepted still appear as tunnels. Failed TLS handshakes (pinning, untrusted CA) are explained.
- **Breakpoints**: pause requests and/or responses, then edit the method, URL, status, headers, and body
- **Map Local**: serve a file or custom content. You can create a rule from any captured response.
- **Map Remote**: rewrite the scheme, host, port, path, or query
- **Scripting**: JavaScript `onRequest` / `onResponse` hooks, a shared state, and a script console
- **Block List / Allow List**
- **Network Conditions**: latency and bandwidth throttling, with presets
- **No Caching**, **Reverse Proxy**, **Compose / Repeat / Edit & Repeat**, **Copy as cURL**
- **HAR import/export** and session save/open (`.raesession`)
- **macOS System Proxy** toggle. It is restored when you quit, and cleaned up if the app crashed.
- **Device setup**: on iOS or Android, open `http://rae.proxy` to download the certificate

## Run

```bash
npm install
npm start          # dev
npm test           # headless engine tests
npm run dist       # builds dist/Rae Proxy-1.0.0-arm64.dmg and dist/mac-arm64/Rae Proxy.app
```

The default proxy port is `9090`. The root CA is stored in `~/Library/Application Support/Rae Proxy/certificates/`.

## Layout

```
src/main/main.js           Electron main: window, menus, IPC
src/main/proxy/engine.js   Proxy server, MITM, rule pipeline, WebSocket
src/main/proxy/ca.js       Root CA + per-host certificates
src/main/proxy/scripting.js, ws-frames.js, http-util.js
src/main/system.js         networksetup / security integration
src/main/har.js            HAR + session formats
src/renderer/              UI (vanilla JS, no build step)
```
