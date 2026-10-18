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

## Feature names: Rae Proxy vs Charles Proxy

If you're coming from Charles, this table shows where each feature lives in Rae Proxy. Each feature links to its section in [How to use each feature](#how-to-use-each-feature).

| Rae Proxy | Charles Proxy | Notes |
|---|---|---|
| [Recording](#recording) | Start / Stop Recording | Same idea: red dot in the toolbar, `⌘R` |
| [macOS System Proxy](#macos-system-proxy) | Proxy → macOS Proxy | `⇧⌘P` in both apps |
| [Request list & sidebar](#request-list--sidebar) | Sequence view / Structure view | The sidebar groups requests by domain and client; the table is the sequence |
| [Pinned domains](#pinned-domains) | Focus | Pinning keeps a host at the top of the sidebar |
| [Filter](#filter) | Filter (Sequence view) | Rae adds `method:`, `status:`, `host:`, `tag:` and `-term` exclusions |
| [Inspector (Request / Response panes)](#inspector) | Contents / Overview / Summary tabs | Header, Query, Body, Cookies, Raw, Summary, Set-Cookie, Timing |
| [WebSocket messages](#websocket-messages) | WebSocket view | Messages tab on the response pane |
| [SSL Proxying](#ssl-proxying) | Proxy → SSL Proxying Settings | Include and exclude lists; Rae can also intercept all domains |
| [Certificate](#certificate) | Help → SSL Proxying → Install Charles Root Certificate (…on a Mobile Device) | Device download page is `http://rae.proxy` (Charles: `chls.pro/ssl`) |
| [Breakpoints](#breakpoints) | Proxy → Breakpoint Settings | Edit and Execute / Abort like Charles |
| [Map Local](#map-local) | Tools → Map Local | Can also serve inline content, not just a file |
| [Map Remote](#map-remote) | Tools → Map Remote | |
| [Scripting](#scripting) | Tools → Rewrite | Rewrite uses rules; Scripting uses JavaScript and covers the same changes |
| [Block List](#block-list) | Tools → Block List (formerly Blacklist) | Return 403 or drop the connection |
| [Allow List](#allow-list) | Tools → Allow List (formerly Whitelist) | In Rae, unmatched traffic is still proxied, just not recorded |
| [Network Conditions](#network-conditions) | Proxy → Throttle Settings | `⌥⌘T` toggles it in Rae |
| [No Caching](#no-caching) | Tools → No Caching | |
| [Reverse Proxy](#reverse-proxy) | Proxy → Reverse Proxies | |
| [Compose](#compose) | Compose (toolbar pen icon) | `⌘N` |
| [Repeat / Edit and Repeat](#repeat--edit-and-repeat) | Repeat / Compose (from a request) | No equivalent of Charles's *Repeat Advanced* (repeat N times with concurrency) |
| [Copy as cURL](#copy-as-curl) | Copy cURL Request | |
| [Save / Open Session](#sessions-and-har) | File → Save / Open Session (`.chls`) | Rae uses `.raesession` and can't open `.chls` files |
| [Import / Export HAR](#sessions-and-har) | File → Import / Export (HAR) | Use HAR to move sessions between Charles and Rae |
| [Script Console](#scripting) | — | Shows `console.log` output from scripts |
| [Settings](#settings) | Proxy → Proxy Settings | Port, external access, upstream TLS checks, limits |

These Charles features have **no Rae Proxy equivalent**: DNS Spoofing (use [Map Remote](#map-remote) instead), External Proxy Settings, Mirror, Auto Save, Access Control, Repeat Advanced, and opening `.chls` files.

## How to use each feature

### Recording

1. Click the **red dot** at the left of the toolbar, or press `⌘R` (**Proxy → Recording**).
2. When recording is off, traffic still passes through the proxy, but new requests aren't added to the list.
3. To clear the list, click **⌫** next to the dot or press `⌘K` (**File → Clear Session**).

### macOS System Proxy

1. Click **System Proxy** in the toolbar, or press `⇧⌘P`.
2. macOS may ask for your password. Rae then routes HTTP and HTTPS for every enabled network service through `127.0.0.1:9090`.
3. Click it again to turn it off. Rae also turns it off when you quit and turns it back on at the next launch.

Rae saves each network service's proxy settings and bypass list before changing them, and puts them back exactly when you turn System Proxy off. An existing company proxy or custom bypass list survives. Services Rae didn't change are left alone.
4. If the app crashed while the system proxy was on, Rae restores your saved settings the next time it starts.

Apps that ignore the system proxy (many command-line tools) need it set directly:

```bash
export http_proxy=http://127.0.0.1:9090 https_proxy=http://127.0.0.1:9090
```

### Request list & sidebar

- Each row shows the ID, URL, method, status, type, time, duration, size and tags (such as `map-local`, `breakpoint`, `script`, `blocked`, `tunnel`).
- Click a column header to sort; click it again to reverse the order.
- Select one row with a click, several with `⌘`-click, or a range with `⇧`-click. Use `↑`/`↓` to move, `⌘A` to select all, and `⌫` to delete.
- The sidebar lists **Domains** (🔓 = decrypted HTTPS, 🔒 = encrypted tunnel, 🌐 = plain HTTP) and, when more than one device is connected, **Clients**. Click an entry to show only its requests; click **All Requests** to reset.
- Hide the sidebar with `⌘⌥S`. Switch the request/response panes between side-by-side and stacked with `⌘⌥D`. Drag the dividers to resize.

### Pinned domains

1. Right-click a domain in the sidebar (or a request in the list) and choose **Pin**.
2. The domain appears in a **Pinned** section at the top of the sidebar.
3. Right-click it again and choose **Unpin** to remove it.

### Filter

Press `⌘F` and type in the filter box. Plain words match the URL, method, status, tags and client address. Separate terms with spaces; every term must match.

| Example | Shows |
|---|---|
| `api users` | URLs containing both "api" and "users" |
| `method:post` | Only POST requests |
| `status:4` or `status:4xx` | 4xx responses |
| `host:github` | Hosts containing "github" |
| `tag:map-local` | Requests answered by Map Local |
| `-analytics` | Everything except URLs containing "analytics" |

The chips next to the box filter by protocol and content type (HTTP, HTTPS, WebSocket, JSON, GraphQL, Form, XML, HTML, JS, CSS, Image, Media, Font) and by status (1xx–5xx, Errors). Click an active chip again to clear it.

### Inspector

Select a request to see it in the two panes below the list.

- **Request tabs:** Header, Query, Body, Cookies, Raw, Summary. Summary shows the original URL if Map Remote changed it.
- **Response tabs:** Header, Body, Set-Cookie, Raw, Timing (plus Messages for WebSockets).
- On **Body**, choose a view at the right of the tab bar: **Tree** (collapsible JSON), **Pretty**, **Text**, **Form**, **Preview** (images and SVG) or **Hex**.
- Compressed bodies (gzip, deflate, brotli, zstd) are decompressed for display. The client still receives the original bytes.
- Right-click a request for **Copy URL**, **Copy Response Body** and **Save Response Body…**.

### WebSocket messages

1. WebSocket connections show `ws://` or `wss://` and the **WebSocket** type. For `wss://` the host needs [SSL Proxying](#ssl-proxying) enabled.
2. Select the connection and open the response pane's **Messages** tab.
3. Each message shows its direction (↑ sent, ↓ received), time, type and size. Up to 5,000 messages are kept per connection.

Rae removes WebSocket compression during the handshake so that the messages stay readable.

### SSL Proxying

By default Rae decrypts HTTPS for **all domains** except a few Apple domains that reject non-Apple certificates.

1. Open **Proxy → SSL Proxying List…** (`⌥⌘P`), or the **SSL Proxying** page in Tools (⚙︎).
2. **Enable SSL Proxying for all domains**: when on, everything except the exclude list is decrypted. When off, only hosts in the include list are decrypted.
3. Enter one host per line in **Include list** or **Exclude list**. Wildcards work: `*.example.com`.

Shortcut: right-click a request or domain and choose **Enable / Disable SSL Proxying for <host>**, then send the request again.

If an app pins its certificates, its requests show up as failed `CONNECT` rows with an explanation. Add that host to the exclude list.

You also need to [trust the certificate](#certificate) on the device sending the traffic.

### Certificate

**This Mac**

1. Open **Certificate → Install Certificate on this Mac…** (or click **Install Certificate…** in the yellow banner).
2. Click **Install & Trust** and enter your password in the macOS dialog.
3. Click **Check Again** if the status doesn't change to *Installed & trusted*.

**iPhone / iPad**

1. Put the device on the same Wi-Fi network as the Mac. In Rae, turn on **Settings → Allow connections from other devices** (it's off by default).
2. On the device: **Settings → Wi-Fi → (i) → Configure Proxy → Manual**. Enter the Mac's IP address (shown in the Rae toolbar) and port `9090`.
3. In Safari, open `http://rae.proxy`. The first attempt fails and Rae asks **Allow this device?** on the Mac. Click **Allow**, reload the page on the device, and tap **Download certificate**.
4. **Settings → General → VPN & Device Management** → install the profile.
5. **Settings → General → About → Certificate Trust Settings** → turn on full trust for *Rae Proxy CA*.

**Android**

Steps 1–3 as above, then **Settings → Security → Encryption & credentials → Install a certificate → CA certificate**. On Android 7+, an app only trusts user-installed certificates if its `network_security_config` allows it.

**iOS Simulator, Node.js, Python**

Copy the exact commands from **Certificate → Install Certificate on iOS / Android…**. They include the certificate path on your Mac:

```bash
xcrun simctl keychain booted add-root-cert "<path>/rae-proxy-ca.pem"
NODE_EXTRA_CA_CERTS="<path>/rae-proxy-ca.pem" node app.js
REQUESTS_CA_BUNDLE="<path>/rae-proxy-ca.pem" python app.py
```

Other actions in the **Certificate** menu: **Export Root Certificate…**, **Reveal Certificate in Finder**, and **Regenerate Root Certificate…** (after regenerating, every device must trust the new certificate).

### Breakpoints

1. Right-click a request → **Tools → Breakpoint…**. Or open **Tools → Breakpoints…** (`⌥⌘B`) and click **＋ Add Rule**.
2. Set **Matching URL** (for example `https://api.example.com/v1/*`), the **HTTP method**, and whether to **Pause on Request** and/or **Pause on Response**.
3. When a matching request arrives, Rae brings its window to the front and opens an editor:
   - **Request:** change the method, URL, headers and body.
   - **Response:** change the status code, headers and body.
4. Choose one:
   - **Execute** sends your edited version.
   - **Continue Unmodified** sends the original.
   - **Abort** closes the connection.
5. If several requests are paused, the editor shows how many are waiting and opens them one after another.

While a breakpoint has active rules, the **Breakpoints** toolbar button is highlighted. Turn the switch at the top of the tool off to disable every rule at once.

### Map Local

**Mock an existing response**

1. Right-click a captured request → **Tools → Map Local (use this response)…**.
2. The rule is pre-filled with that response's status, headers and body. Edit the body and the change applies straight away.

**Create one from scratch**

1. Open **Tools → Map Local…** (`⌥⌘L`) and click **＋ Add Rule**.
2. Set **Matching URL**, **Status code**, **Response headers** (one `Name: value` per line) and either:
   - **Response body**: inline content, or
   - **Local file**: click **Choose…**. The file overrides the inline body and is re-read on every request, so you can edit it in your own editor.

Matching requests never reach the server. They're tagged `map-local` in the list.

### Map Remote

1. Right-click a request → **Tools → Map Remote…**. Or open **Tools → Map Remote…** (`⌥⌘R`).
2. Set **Matching URL**, for example `https://api.example.com/*`.
3. Fill in only the parts you want to change: **To protocol**, **To host**, **To port**, **To path**, **To query**. Empty fields keep the original value.
4. Tick **Preserve original Host header** if the target server needs the original `Host` header.

Example: send production API calls to a local server by setting protocol `http`, host `localhost`, port `3000`.

The **Summary** tab of a remapped request shows both the original and the new URL.

### Scripting

1. Right-click a request → **Tools → Scripting…**, or open **Tools → Scripting…** (`⌥⌘I`) and click **＋ Add Rule**.
2. Set **Matching URL** and tick **Run onRequest** and/or **Run onResponse**.
3. Edit the script. The template already contains both functions:

```js
async function onRequest(context, url, request) {
  request.headers["X-Debug"] = "1";      // add or change headers
  request.queries["page"] = "2";         // change query parameters
  request.method = "POST";               // change method
  // request.url = "https://other.host/path";  // or replace the whole URL
  return request;
}

async function onResponse(context, url, request, response) {
  response.statusCode = 200;
  response.headers["Cache-Control"] = "no-store";
  if (typeof response.body === "object") response.body.injected = true; // JSON bodies arrive parsed
  // response.body = "plain text";        // strings are sent as-is, objects as JSON
  return response;
}
```

- JSON bodies are parsed into objects; other text bodies are strings; binary bodies are `null` (leave them alone to pass them through).
- `sharedState` keeps values between runs and is shared by every script.
- `console.log` / `warn` / `error` print to the **Script Console** (`⌥⌘C`, or **Console** in the status bar). The console opens automatically when a script throws.
- Each script has a 10-second time limit. If a script fails, the request continues unchanged.

Requests changed by a script are tagged `script`.

### Block List

1. Right-click a request → **Tools → Block List…**, or right-click a domain → **Block this domain…**. Or open **Tools → Block List…**.
2. Set **Matching URL** and choose an **Action**:
   - **Return 403 Forbidden**: the client gets an immediate 403.
   - **Drop connection**: the connection is closed with no response.

Blocked requests are tagged `blocked`.

### Allow List

1. Open **Tools → Allow List…** and switch the tool **on**.
2. Add one rule per URL pattern you want to see, for example `*://api.myapp.com/*`.
3. While the tool is on and has at least one active rule, **only matching requests are recorded**. All other traffic is still proxied, just not shown.

### Network Conditions

1. Click **Throttle** in the toolbar or press `⌥⌘T` to switch it on or off. When on, the button shows the active preset.
2. To change the settings, right-click **Throttle**, or open **Tools → Network Conditions…**.
3. Pick a **Preset** (100% Loss, Very Bad Network, EDGE, 3G, DSL, LTE, Wi-Fi), or enter your own **Added latency (ms)** and **Download bandwidth (kbps)** (`0` = unlimited).

Throttling applies to every response that goes through the proxy. Encrypted tunnels (hosts without SSL Proxying) are not throttled.

### No Caching

Turn it on with **Proxy → No Caching**, or under **Tools → Settings**. Rae removes `If-None-Match` and `If-Modified-Since` and sends `Cache-Control: no-cache` / `Pragma: no-cache`, so the server returns full responses instead of `304 Not Modified`.

### Reverse Proxy

Use this for clients that can't be configured to use a proxy.

1. Open **Proxy → Reverse Proxy…**.
2. Click **＋ Add Reverse Proxy**. Enter a **Local port**, **Remote host** and **Remote port**, and tick **HTTPS** if the remote server uses TLS.
3. Point the client at `http://localhost:<local port>`. Rae forwards each request to the remote server with the correct `Host` header and records it like any other request.

Reverse proxies listen on `127.0.0.1` only, so other devices can't reach them.

### Compose

1. Press `⌘N` (**File → New Request…**) or click **＋** in the toolbar.
2. Choose the method, enter the URL, headers (one `Name: value` per line) and body.
3. Press `⌘↩` or click **Send**. The result appears in the list, tagged `composed`, and is selected automatically.

Composed requests go through all your rules (Map Local, Breakpoints, Scripting, and so on). They're recorded even when recording is off.

### Repeat / Edit and Repeat

- **Repeat:** right-click one or more requests → **Repeat**. Each is sent again unchanged and appears as a new row.
- **Edit and Repeat:** double-click a request, or right-click → **Edit and Repeat…**. The Compose window opens pre-filled so you can change it before sending.

### Copy as cURL

Right-click a request → **Copy as cURL**. The command includes the method, URL, headers and body, and `--compressed` if the original accepted compressed responses. Paste it into a terminal to replay the request outside Rae.

### Sessions and HAR

| Action | Menu | Shortcut |
|---|---|---|
| Save every request as a Rae session (`.raesession`) | **File → Save Session…** | `⌘S` |
| Open a `.raesession` or `.har` file | **File → Open Session…** / **Import HAR…** | `⌘O` |
| Export every request as HAR | **File → Export All as HAR…** | `⇧⌘E` |
| Export only the selected requests as HAR | Right-click → **Export as HAR…** | |

Imported requests are added to the current list and tagged `imported`. To move a capture from Charles, export it there as HAR (**File → Export Session… → HTTP Archive**) and import it in Rae.

### Settings

Open **Rae Proxy → Settings…** (`⌘,`):

- **Proxy port**: enter a port and click **Apply**. If the system proxy is on, it switches to the new port automatically. If the port is already in use, a red banner offers **Change Port** and **Retry**.
- **Max recorded requests**: the oldest requests are dropped beyond this number (default 20,000).
- **Allow connections from other devices**: needed for phones, tablets and other computers. Off by default. Even when on, each new device is refused until you click **Allow** in the prompt that appears the first time it connects.
- **Allowed devices / Denied devices**: the approved and refused IP addresses, one per line. Wildcards like `192.168.1.*` work. Denied devices are refused without asking.
- **Verify upstream server TLS certificates**: turn this off to debug servers with self-signed certificates.
- **No Caching**: see [No Caching](#no-caching).
- **Max captured body size (MB)**: larger bodies are still forwarded in full but stored only up to this size.

Captured bodies larger than 8 KB are kept on disk in `session-bodies.bin` instead of in memory, so long sessions don't use gigabytes of RAM. The file is emptied by **Clear Session**, compacted automatically after many requests are deleted, and removed when you quit.

Settings and rules are saved in `~/Library/Application Support/Rae Proxy/config.json`.

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
