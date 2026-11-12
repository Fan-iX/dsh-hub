// Multi-user HTTP entry: authentication gate, cold-start page, session-list
// cache interception, per-user forwarding, and the WebSocket upgrade path.
import http from 'node:http';

import { AUTH_LOG_FILE, CFG, TRUST_MODE } from './config.mjs';
import { createLogin } from '../backend/auth.mjs';
import {
  bridgeDshBrowserSession, hubDshCookieHeader, isIndexPath, proxy,
} from '../backend/dsh-proxy.mjs';
import {
  handleKeepAlive, localeFromRequest, loginErrorMessage, loginPage, pageHeaders, readRequestBody, sendHtml,
  sendJson, startingPage, t, wantsDocument,
} from '../backend/web.mjs';
import { keyFor, lookupUser, verify } from './accounts.mjs';
import { backends, getOrCreateBackend } from './instances.mjs';
import {
  SESSION_LIST_PATH, forwardSessionList, isCacheableSessionList, isStandardSessionList,
  loadDiskEntry, maybeRevalidateSessionList, memoryLookup, requestRpcId,
  serveCachedSessionList, storeSessionList,
} from './session-list-cache.mjs';

const { handleLogin, handleLogout, sessionInfo, sessionUser, maybeRefreshSession } = createLogin({
  verify, keyFor, auditPath: AUTH_LOG_FILE, cfg: CFG,
});

// Spawns running in the background, and the last spawn failure per user. A
// request that needs a cold backend starts the spawn here and answers at once
// (loading page or 503), instead of holding the navigation open for up to
// SPAWN_TIMEOUT_MS.
const spawnInflight = new Set();
const spawnFailures = new Map();

/** Start (or join) a backend spawn without blocking the request that needs it. */
function startBackendInBackground(user) {
  if (spawnInflight.has(user)) return;
  spawnInflight.add(user);
  void getOrCreateBackend(user)
    .catch((err) => {
      console.error(`[hub] spawn failed for ${user}:`, err.message);
      spawnFailures.set(user, err.message);
    })
    .finally(() => spawnInflight.delete(user));
}

export async function route(req, res) {
  const url = new URL(req.url, 'http://x');

  if (url.pathname === '/hub/login' && req.method === 'GET') {
    const locale = localeFromRequest(req);
    const error = url.searchParams.get('error');
    sendHtml(res, 200,
      loginPage(locale, loginErrorMessage(locale, error, url.searchParams.get('wait')), error !== null),
      pageHeaders(req, locale));
    return;
  }
  if (url.pathname === '/hub/login' && req.method === 'POST') {
    await handleLogin(req, res);
    return;
  }
  if (url.pathname === '/hub/logout') {
    handleLogout(req, res);
    return;
  }

  const session = sessionInfo(req);
  if (session === null) {
    // A navigation goes to the login page; a fetch gets a machine-readable 401
    // so a hub-aware page can redirect without depending on dsh's UI.
    if (wantsDocument(req)) {
      res.writeHead(303, { location: '/hub/login' });
      res.end();
    } else {
      sendJson(res, 401, { error: 'unauthenticated' }, { 'x-dsh-hub-login': '/hub/login' });
    }
    return;
  }
  const user = session.user;
  if (!await lookupUser(user)) {  // account deleted since login
    handleLogout(req, res);
    return;
  }
  if (url.pathname === '/hub/api/session') {
    // A near-expiry session is extended here; the probe response reports the
    // post-refresh TTL so dsh-hub-utils can re-arm its expiry timer.
    const effectiveExp = maybeRefreshSession(res, session) ?? session.exp;
    sendJson(res, 200, {
      authenticated: true,
      user,
      expiresInSec: Math.max(0, Math.floor((effectiveExp - Date.now()) / 1000)),
    });
    return;
  }
  if (url.pathname === '/hub/api/keepalive') {
    await handleKeepAlive(req, res, backends.get(user));
    return;
  }

  // Session-list RPC cache: hot memory for a live instance, optional per-user
  // disk for a respawn. Only the standard `session.list({})` shape is cached.
  if (req.method === 'POST' && url.pathname === SESSION_LIST_PATH) {
    let body;
    try {
      body = await readRequestBody(req);
    } catch (err) {
      sendJson(res, err.message === 'body too large' ? 413 : 408, { error: err.message }, { 'retry-after': '2' });
      return;
    }
    const rpcId = requestRpcId(body);
    const standard = rpcId !== undefined && isStandardSessionList(body);
    let be = backends.get(user);
    const running = be !== undefined && be.child !== null && be.child.exitCode === null && !be.starting;

    if (standard && running) {
      const entry = memoryLookup(user);
      if (entry !== null) {
        be.touch(); // a cache hit is browser activity too
        if (await serveCachedSessionList(res, entry, rpcId)) {
          maybeRevalidateSessionList(user, be, body);
          return;
        }
        if (res.destroyed || res.writableEnded) return;
      }
      // Memory miss on a live instance: forward for freshness. The disk tier is
      // for a stopped/respawning instance, not for an alive one.
    } else if (standard && !running) {
      let entry = null;
      try {
        entry = await loadDiskEntry(user);
      } catch (err) {
        console.warn(`[hub] session.list disk cache read failed for ${user}:`, err.message);
      }
      if (entry !== null) {
        try {
          if (await serveCachedSessionList(res, entry, rpcId)) return;
          if (res.destroyed || res.writableEnded) return;
        } catch (err) {
          console.warn(`[hub] session.list disk cache serve failed for ${user}:`, err.message);
          if (res.headersSent) { res.destroy(); return; }
          // The prefix read failed before headers: fall through to a live forward.
        }
      }
      // No usable disk snapshot: spawn/forward.
    }

    if (!running) {
      try {
        be = await getOrCreateBackend(user);
      } catch (err) {
        console.error(`[hub] spawn failed for ${user}:`, err.message);
        sendHtml(res, 503, `<pre>dsh-hub: fail to launch\n${err.message}</pre>`);
        return;
      }
    }
    be.touch();
    req.headers.origin = `http://127.0.0.1:${be.port}`;
    req.headers['accept-encoding'] = 'identity';
    // Present the hub's own cookie for this backend, not the browser's: after a
    // respawn the browser still carries the old port's cookie name and dsh would
    // refuse it, while the hub always mints for the current authority.
    const internalCookie = await hubDshCookieHeader(be);
    if (internalCookie) req.headers.cookie = internalCookie;
    let captured;
    // The browser's session.list request and the hub's internal forward are
    // independent; abort the forward when the client goes away so a slow store
    // does not keep working (and holding a 12 MB response) for nobody.
    const abort = new AbortController();
    const onClientClose = () => { if (!res.writableEnded) abort.abort(); };
    res.once('close', onClientClose);
    try {
      captured = await forwardSessionList(be, req.headers, body, abort.signal);
    } catch (err) {
      // The request body is already consumed, so the generic proxy fallback
      // would forward an empty RPC; answer a retryable failure instead.
      console.error(`[hub] session.list forward failed for ${user}:`, err.message);
      sendJson(res, 503, { error: 'session list unavailable' }, { 'retry-after': '5' });
      return;
    } finally {
      res.removeListener('close', onClientClose);
    }
    if (standard && isCacheableSessionList(captured)) storeSessionList(user, captured);
    if (res.destroyed || res.writableEnded) return;
    res.writeHead(captured.status, {
      'content-type': captured.headers['content-type'] ?? 'application/json',
      'content-length': captured.body.length,
    });
    res.end(captured.body);
    return;
  }

  // Never block on a cold backend: start (or join) the spawn in the background
  // and answer immediately. The index navigation gets the static loading page,
  // whose meta refresh retries this URL; anything else gets a retryable 503 so
  // an API call cannot hang for the whole spawn either.
  let be = backends.get(user);
  if (!be || !be.child || be.child.exitCode !== null || be.starting) {
    const locale = localeFromRequest(req);
    const failure = spawnFailures.get(user);
    if (failure !== undefined) {
      spawnFailures.delete(user);
      sendHtml(res, 503, `<pre>${t(locale, 'error.spawnFailed')}\n${failure}</pre>`,
        pageHeaders(req, locale));
      return;
    }
    startBackendInBackground(user);
    if (req.method === 'GET' && isIndexPath(url.pathname)) {
      sendHtml(res, 200, startingPage(locale), pageHeaders(req, locale));
    } else {
      res.writeHead(503, { 'content-type': 'text/plain; charset=utf-8', 'retry-after': '3' });
      res.end(`${t(locale, 'error.starting')}\n`);
    }
    return;
  }
  spawnFailures.delete(user);
  be.touch();
  req.hubBackend = be; // lets the proxy 401 handler re-mint dsh's session cookie
  // First navigation of an authenticated session: mint dsh's own browser-session
  // cookie before touching the backend, so the index never answers 401.
  if (req.method === 'GET' && isIndexPath(url.pathname)) {
    try {
      if (await bridgeDshBrowserSession(req, res, be)) return;
    } catch (err) {
      console.error(`[hub] browser-session bridge failed for ${user}:`, err.message);
    }
  }
  if (TRUST_MODE === 'origin-rewrite') {
    // Legacy fallback: align Origin with the loopback Host changeOrigin sends;
    // cross-site protection is carried by the hub's SameSite cookie instead.
    // Also inject Origin when the browser omitted it entirely (service-worker
    // or extension re-fetches drop Origin/Sec-Fetch-* headers): plugin guards
    // like task-board's browser-marker check need one of the two, and this
    // request already passed the session cookie authentication.
    req.headers.origin = `http://127.0.0.1:${be.port}`;
  }
  // Force identity encoding so the HTML rewrite sees plain text.
  req.headers['accept-encoding'] = 'identity';
  // Sending a message is a strong activity signal; refresh the session cookie
  // on the prompt response (dsh-proxy merges it with dsh's own Set-Cookie). The
  // session-list RPC is deliberately not a refresh source: it can be driven by
  // background WebSocket events.
  if (url.pathname === '/api/session/prompt') {
    maybeRefreshSession(res, session);
  }
  proxy.web(req, res, { target: `http://127.0.0.1:${be.port}` });
}

/**
 * Create the multi-user HTTP server with its request and upgrade handlers.
 * @returns the listening-ready server (caller owns `listen`).
 */
export function createHubServer() {
  const server = http.createServer((req, res) => {
    // Client resets are normal on flaky networks; never let them surface as an
    // unhandled socket error. The route's promise settles separately.
    req.on('error', () => { /* client gone */ });
    res.on('error', () => { /* client gone */ });
    route(req, res).catch((err) => {
      console.error('[hub] handler error:', err);
      if (res.destroyed || res.writableEnded) return;
      if (!res.headersSent) res.writeHead(500);
      res.end('dsh-hub: internal error');
    });
  });
  // Bound slow headers (slowloris); request bodies carry their own deadline.
  server.headersTimeout = 30_000;

  // WebSocket upgrade (dsh event streams) — routed by the same session cookie.
  server.on('upgrade', (req, socket, head) => {
    const user = sessionUser(req);
    if (!user) {
      socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      socket.destroy();
      return;
    }
    const be = backends.get(user);
    if (!be || !be.child || be.child.exitCode !== null || be.starting) {
      socket.write('HTTP/1.1 503 Service Unavailable\r\n\r\n');
      socket.destroy();
      return;
    }
    be.touch();
    // An attached event stream is live use: count it so the idle culler never
    // reaps a backend whose browser is still watching (a long agent turn or a
    // background job can run for hours without a single HTTP request). dsh
    // heartbeats the stream every 2s and the client answers, so `data` keeps
    // arriving; the count alone is the stronger guard.
    be.wsClients += 1;
    let detached = false;
    const detach = () => {
      if (detached) return;
      detached = true;
      be.wsClients = Math.max(0, be.wsClients - 1);
      be.touch(); // the idle window starts when the stream detaches
    };
    socket.on('data', () => be.touch());
    socket.on('close', detach);
    // A reset before the upstream upgrade would otherwise be an unhandled
    // 'error' on the raw socket.
    socket.on('error', () => { detach(); socket.destroy(); });
    if (TRUST_MODE === 'origin-rewrite') {
      req.headers.origin = `http://127.0.0.1:${be.port}`;
    }
    try {
      proxy.ws(req, socket, head, { target: `http://127.0.0.1:${be.port}` });
    } catch {
      detach();
      socket.destroy();
    }
  });

  return server;
}
