// Reverse proxy for dsh's HTTP and WebSocket traffic: origin rewriting, the
// insecure-context page hooks, and the bridge that spends dsh's one-shot
// launch token on behalf of an already-authenticated browser.
import crypto from 'node:crypto';
import http from 'node:http';
import httpProxy from 'http-proxy';

import { TRUST_MODE } from './config.mjs';
import { localeFromRequest, pageHeaders, sendHtml, startingPage, t } from './web.mjs';

// A proxy connection error is treated as a startup transient only until the
// instance has served its first response and for a short grace after readiness.
const STARTUP_GRACE_MS = 10_000;

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
// this browser" even though the proxy's origin-rewrite already passes the
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

// Marks a page as hub-served. Both entry points are the only way to the
// backend, so a browser plugin that only makes sense under dsh-hub
// (dsh-hub-utils) checks this marker and stays out of a bare `dsh web`.
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

/**
 * Append a hub session-refresh Set-Cookie (already set on `res` by the caller)
 * to a proxied response. dsh sets its own cookies on some routes, so both must
 * survive; the hub's cookie is the distinct `dshhub_session` name.
 */
function mergeSetCookie(headers, res) {
  const ours = res.getHeader('set-cookie');
  if (ours === undefined) return headers;
  const list = Array.isArray(ours) ? [...ours] : [ours];
  const theirs = headers['set-cookie'];
  if (theirs !== undefined) {
    if (Array.isArray(theirs)) list.push(...theirs);
    else list.push(theirs);
  }
  return { ...headers, 'set-cookie': list };
}

proxy.on('proxyRes', (proxyRes, req, res) => {  const ct = String(proxyRes.headers['content-type'] ?? '');
  const url = String(req.url ?? '');
  const reqPath = new URL(url, 'http://x').pathname;
  const be = req.hubBackend;
  // A response that keeps streaming (long poll / SSE) is live use too, so the
  // idle culler counts its bytes as activity, not just the request that opened it.
  if (be) {
    be.healthy = true; // dsh's HTTP layer answered; later errors are not startup
    proxyRes.on('data', () => be.touch());
  }
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
        if (handled || res.headersSent || res.writableEnded || res.destroyed) return;
        res.writeHead(401, { 'cache-control': 'no-store', 'content-type': 'text/plain; charset=utf-8' });
        res.end('dsh web authentication required; reopen the URL printed by dsh web.\n');
      })
      .catch((err) => {
        console.error('[hub] browser-session bridge failed:', err.message);
        if (!res.headersSent && !res.destroyed && !res.writableEnded) {
          res.writeHead(502);
          res.end('dsh-hub: browser-session bridge failed\n');
        }
      });
    return;
  }
  if (!/text\/html/i.test(ct)) {
    if (res.destroyed || res.writableEnded) { proxyRes.resume(); return; }
    res.writeHead(proxyRes.statusCode, mergeSetCookie(proxyRes.headers, res));
    proxyRes.pipe(res);
    return;
  }
  const chunks = [];
  proxyRes.on('data', (c) => chunks.push(c));
  proxyRes.on('error', () => res.destroy());
  proxyRes.on('end', () => {
    if (res.destroyed || res.writableEnded) return;
    const headers = mergeSetCookie(proxyRes.headers, res);
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
  // WebSocket upgrades have no ServerResponse; let the client reconnect.
  if (!(res instanceof http.ServerResponse)) {
    if (res?.destroy) res.destroy();
    return;
  }
  if (res.headersSent || res.writableEnded) {
    try { res.end(); } catch { /* already gone */ }
    return;
  }
  if (res.destroyed) return;
  if (req === undefined) {
    res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('dsh-hub: backend unavailable\n');
    return;
  }
  const be = req.hubBackend;
  const starting = be !== undefined && (
    be.starting === true
    || (be.healthy !== true && Date.now() - (be.startedAt ?? 0) < STARTUP_GRACE_MS)
  );
  const pathname = new URL(String(req?.url ?? '/'), 'http://x').pathname;
  const index = req?.method === 'GET' && isIndexPath(pathname);
  const locale = localeFromRequest(req);
  // The index during startup gets the same loading page as the router's cold
  // start; anything else must stay a retryable non-HTML response.
  if (starting && index) {
    sendHtml(res, 200, startingPage(locale), pageHeaders(req, locale));
    return;
  }
  if (starting) {
    res.writeHead(503, { 'content-type': 'text/plain; charset=utf-8', 'retry-after': '3' });
    res.end(`${t(locale, 'error.starting')}\n`);
    return;
  }
  res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
  res.end('dsh-hub: backend unavailable\n');
});

// --------------------------------------------- dsh browser-session bridge ----
// dsh gates its index (and every /api channel) on its own `dsh-auth-*` cookie,
// which is minted ONLY by a request carrying the per-process `?token=` value
// printed once at startup. The hub's session cookie means nothing to dsh, so an
// authenticated hub session used to land on `401 dsh web authentication
// required; reopen the URL printed by dsh web.`
//
// We capture that token from the instance's stdout and perform the exchange
// ourselves: one loopback `GET /?token=<token>` using the authority the proxied
// browser request will present, then relay dsh's Set-Cookie to the browser and
// redirect to the clean index. The token never reaches the browser, the URL bar
// stays clean, and dsh is not modified.

/** dsh's deterministic browser-session cookie name for one request authority. */
function dshCookieName(authority) {
  return 'dsh-auth-' + crypto.createHash('sha256').update(authority).digest('base64url');
}

/** The authority dsh sees on a proxied browser request (it binds its cookie to it). */
function backendAuthority(be, req) {
  return TRUST_MODE === 'origin-rewrite'
    ? `127.0.0.1:${be.port}`
    : String(req.headers.host ?? `127.0.0.1:${be.port}`);
}

function hasRequestCookie(req, name) {
  const prefix = `${name}=`;
  for (const part of String(req.headers.cookie ?? '').split(';')) {
    if (part.trim().startsWith(prefix)) return true;
  }
  return false;
}

/** True for the dsh index paths that can mint a browser session. */
export function isIndexPath(pathname) {
  return pathname === '/' || pathname === '/index.html';
}

/**
 * Spend the instance's launch token and return the Set-Cookie value dsh minted
 * for `authority`, or null when no cookie came back.
 */
function mintDshSessionCookie(be, authority) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (value) => { if (!settled) { settled = true; resolve(value); } };
    const req = http.request({
      host: '127.0.0.1',
      port: be.port,
      method: 'GET',
      path: `/?token=${encodeURIComponent(be.launchToken)}`,
      setHost: false,
      headers: { host: authority, connection: 'close' },
    }, (res) => {
      res.resume(); // only the Set-Cookie header matters
      res.on('end', () => done(res.headers['set-cookie'] ?? null));
      res.on('error', () => done(null));
    });
    req.on('error', () => done(null));
    req.setTimeout(10_000, () => { req.destroy(); done(null); });
    req.end();
  });
}

/**
 * Ensure the browser holds dsh's own session cookie, minting and relaying it
 * through the instance's launch token when absent (or when `force` re-mints
 * after dsh rejected a stale one).
 * @returns true when this wrote the 303 carrying dsh's Set-Cookie.
 */
export async function bridgeDshBrowserSession(req, res, be, { force = false } = {}) {
  const authority = backendAuthority(be, req);
  if (!force && hasRequestCookie(req, dshCookieName(authority))) return false;
  if (!await be.waitLaunchToken(5000)) return false;
  const setCookie = await mintDshSessionCookie(be, authority);
  if (!setCookie) return false;
  if (res.destroyed || res.writableEnded) return false;
  const merged = mergeSetCookie({ 'set-cookie': setCookie }, res);
  res.writeHead(303, {
    'cache-control': 'no-store',
    'referrer-policy': 'no-referrer',
    location: '/',
    'set-cookie': merged['set-cookie'],
  });
  res.end();
  return true;
}

/**
 * Cookie header authenticating internal /api calls. dsh's browser fence applies
 * to loopback requests too, so prewarm/revalidate must present the same
 * `dsh-auth-*` cookie a browser would; we mint our own from the instance's
 * launch token and reuse it for that instance's lifetime.
 * @returns the `name=value` pair, or null when no token/cookie is available.
 */
export async function hubDshCookieHeader(be) {
  if (be.internalCookie) return be.internalCookie;
  if (!await be.waitLaunchToken(5000)) return null;
  const setCookie = await mintDshSessionCookie(be, `127.0.0.1:${be.port}`);
  if (!setCookie) return null;
  const raw = Array.isArray(setCookie) ? setCookie[0] : setCookie;
  if (typeof raw !== 'string' || raw === '') return null;
  be.internalCookie = raw.split(';')[0];
  return be.internalCookie;
}
