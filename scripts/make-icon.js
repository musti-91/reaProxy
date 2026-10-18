// Renders build/icon.png (1024x1024) from an inline SVG. Run: npx electron scripts/make-icon.js
const { app, BrowserWindow } = require('electron');
const fs = require('fs');
const path = require('path');
const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024">
<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#ff8a4c"/><stop offset="1" stop-color="#e5484d"/></linearGradient></defs>
<rect x="100" y="100" width="824" height="824" rx="185" fill="url(#g)"/>
<g fill="none" stroke="#fff" stroke-width="56" stroke-linecap="round" stroke-linejoin="round">
<path d="M300 380h330l-80-80M724 644H394l80 80"/></g>
<text x="512" y="560" text-anchor="middle" font-family="-apple-system,Helvetica" font-weight="800" font-size="120" fill="#fff" opacity=".95">RAE</text>
</svg>`;
app.whenReady().then(async () => {
  const win = new BrowserWindow({ width: 1024, height: 1024, show: false, frame: false, transparent: true, webPreferences: { offscreen: true } });
  await win.loadURL('data:text/html,' + encodeURIComponent(`<body style="margin:0;background:transparent">${svg}</body>`));
  await new Promise((r) => setTimeout(r, 300));
  const img = await win.webContents.capturePage({ x: 0, y: 0, width: 1024, height: 1024 });
  fs.writeFileSync(path.join(__dirname, '../build/icon.png'), img.resize({ width: 1024, height: 1024 }).toPNG());
  app.quit();
});
