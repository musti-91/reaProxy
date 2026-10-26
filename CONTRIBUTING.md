# Contributing to Rae Proxy

Thanks for taking a look. Rae Proxy is a small, macOS-only Electron app, so the
workflow is intentionally simple.

## Setup

```bash
npm install
npm start          # run the app
npm test           # headless engine tests (test/smoke.js, test/features.js)
npm run prettier:check
```

`npm test` runs against the proxy engine directly (no Electron window needed),
so it's fast enough to run on every change.

## Before opening a PR

- Run `npm test` and `npm run prettier:write` (or `prettier:check`) locally —
  CI runs both on macOS and will fail the PR otherwise.
- Keep PRs focused. If you're fixing a bug and notice something unrelated to
  clean up, open a separate PR for it.
- For a new feature, a short description of the use case in the PR (or a
  linked issue) helps review go faster — especially if it adds a new
  dependency or touches the proxy engine (`src/main/proxy/`).

## Reporting bugs / requesting features

Use the issue templates. Include macOS version, Rae Proxy version, and repro
steps for bugs — most issues here come down to a specific TLS/HTTP edge case,
and a repro saves a lot of back-and-forth.

## Scope

Rae Proxy intentionally doesn't aim to match every Charles Proxy feature (see
the README's comparison table). If you're proposing a large new feature,
opening an issue first to discuss it is a good idea before investing time in
a PR.
