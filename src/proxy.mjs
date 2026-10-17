// Reverse proxy: routes HTTP and WebSocket traffic to the user's loopback
// dsh instance, rewriting the server-rendered HTML it serves (insecure-context
// polyfill and the loopback transport hook) and bridging dsh's own 401.
import http from 'node:http';
import httpProxy from 'http-proxy';

import { TRUST_MODE } from './config.mjs';
import { bridgeDshBrowserSession, isIndexPath } from './browser-session.mjs';

// ---------------------------------------------------------------- proxy -----

// dsh's web UI calls the browser-global `crypto.randomUUID()` (e.g. provider
// catalog / draft attachments). Browsers only expose that API in SECURE
// contexts (https or localhost), so bare `http://<server-ip>:3080` breaks with
// "crypto.randomUUID is not a function". `crypto.getRandomValues` IS available
// in insecure contexts, so we inject a complete v4-UUID polyfill into every
// proxied HTML page — no dsh modification needed, upgrades keep working.
const RANDOM_UUID_POLYFILL = `<script>(function(){
if (typeof crypto!=='undefined'&&typeof crypto.randomUUID==='function')return;
function uuid4(){
  var b=crypto.getRandomValues(new Uint8Array(16));
  b[6]=(b[6]&15)|64;b[8]=(b[8]&63)|128;
  var s='';for(var i=0;i<16;i++)s+=b[i].toString(16).padStart(2,'0');
  return s.slice(0,8)+'-'+s.slice(8,12)+'-'+s.slice(12,16)+'-'+s.slice(16,20)+'-'+s.slice(20);
}
try{Object.defineProperty(crypto,'randomUUID',{value:uuid4,writable:true,configurable:true});}
catch(e){try{crypto.randomUUID=uuid4;}catch(e2){}}
})();</script>`;

// dsh's settings/credentials plane is browser-gated: the client computes
// connection.isLoopback from `location.hostname` (connection/src/client),
// so a page served from a LAN hostname reports "settings are unavailable in
// this browser" even though the hub's origin-rewrite already passes the
// server-side loopback fence. That flag also picks the settings mirror's
// persistence: `host` on loopback, `memory` elsewhere — and in `memory` mode
// the Models store never reads the provider catalog, which is exactly that
// error.
//
// The connection client honors a page-global transport hook before the hostname:
//   isLoopback: transport?.ownsHost === true || pageLocation === void 0 || isLoopbackHostname(...)
// Declaring `__DSH_TRANSPORT__` with `ownsHost: true` in the served index makes
// the page loopback-equivalent without touching dsh or rewriting cordis
// services. The hook carries no rpc/fetch/openStream, so the connection RPC
// caller falls back to the page's global fetch. Patching the served plugin
// bundle instead does not work here: the shell loads plugins through combo URLs
// (`/plugins/??<id>/client.js,...&rev=...`), not the `*.js?rev=` chunk URLs a
// text patch could target.
const DSH_TRANSPORT_HOOK =
  `<script>window.__DSH_TRANSPORT__=Object.assign({},window.__DSH_TRANSPORT__,{ownsHost:true});</script>`;

// Marks a page as hub-served. The hub is the only entry to the backend, so a
// browser plugin that only makes sense under the hub (dsh-hub-utils) checks this
// marker and stays out of a bare `dsh web`. The version keeps a later marker
// change detectable.
const DSH_HUB_HOOK = '<script>window.__DSH_HUB__={version:1};</script>';

export const proxy = httpProxy.createProxyServer({
  ws: true,
  // trusted-host mode keeps the browser's real Host so dsh's own fence (fed by
  // --trusted-host at spawn) makes the decision. origin-rewrite mode masquerades
  // as a loopback same-origin client instead.
  changeOrigin: TRUST_MODE === 'origin-rewrite',
  proxyTimeout: 120_000,
  selfHandleResponse: true, // we own the response so we can rewrite HTML
});

proxy.on('proxyRes', (proxyRes, req, res) => {
  const ct = String(proxyRes.headers['content-type'] ?? '');
  const url = String(req.url ?? '');
  const reqPath = new URL(url, 'http://x').pathname;
  const be = req.hubBackend;
  // A response that keeps streaming (long poll / SSE) is live use too, so the
  // idle culler counts its bytes as activity, not just the request that opened it.
  if (be) proxyRes.on('data', () => { be.lastActivity = Date.now(); });
  // dsh refused the index with 401: the browser either has no dsh cookie yet or
  // holds a stale one. Re-mint it from the launch token and redirect, instead of
  // surfacing "reopen the URL printed by dsh web". The throttle stops a redirect
  // loop if the freshly minted cookie is itself refused.
  if (be && proxyRes.statusCode === 401 && req.method === 'GET'
    && isIndexPath(reqPath) && Date.now() - be.bridgeAttemptAt > 5000) {
    be.bridgeAttemptAt = Date.now();
    proxyRes.resume(); // discard dsh's 401 body; this handler owns the response
    bridgeDshBrowserSession(req, res, be, { force: true })
      .then((handled) => {
        if (handled || res.headersSent || res.writableEnded) return;
        res.writeHead(401, { 'cache-control': 'no-store', 'content-type': 'text/plain; charset=utf-8' });
        res.end('dsh web authentication required; reopen the URL printed by dsh web.\n');
      })
      .catch((err) => {
        console.error('[hub] browser-session bridge failed:', err.message);
        if (!res.headersSent) { res.writeHead(502); res.end('dsh-hub: browser-session bridge failed\n'); }
      });
    return;
  }
  if (!/text\/html/i.test(ct)) {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
    return;
  }
  const chunks = [];
  proxyRes.on('data', (c) => chunks.push(c));
  proxyRes.on('error', () => res.destroy());
  proxyRes.on('end', () => {
    const headers = { ...proxyRes.headers };
    delete headers['content-length'];
    delete headers['content-encoding'];
    res.writeHead(proxyRes.statusCode, headers);
    const html = Buffer.concat(chunks).toString('utf-8');
    const injection = DSH_HUB_HOOK + DSH_TRANSPORT_HOOK + RANDOM_UUID_POLYFILL;
    const injected = /<head[^>]*>/i.test(html)
      ? html.replace(/<head[^>]*>/i, (m) => m + injection)
      : injection + html;
    res.end(Buffer.from(injected, 'utf-8'));
  });
});

proxy.on('error', (err, req, res) => {
  console.error('[hub] proxy error:', err.message);
  if (res instanceof http.ServerResponse) {
    if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' });
    res.end('dsh-hub: backend unavailable\n');
  } else if (res?.destroy) {
    res.destroy();
  }
});
