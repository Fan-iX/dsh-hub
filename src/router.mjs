// HTTP router: authentication gate, cold-start loading page, session-list
// cache interception, and forwarding to the backend through the proxy.
import { TRUST_MODE } from './config.mjs';
import { backends, getOrCreateBackend } from './backends.mjs';
import { proxy } from './proxy.mjs';
import { bridgeDshBrowserSession, isIndexPath } from './browser-session.mjs';
import { sendHtml, readRequestBody } from './http.mjs';
import { STARTING_PAGE, loginPage } from './pages.mjs';
import { lookupUser } from './users.mjs';
import { handleLogin, handleLogout, sessionUser } from './auth.mjs';
import {
  SESSION_LIST_PATH, deferSessionList, forwardSessionList, isCacheableSessionList,
  requestRpcId, revalidateSessionList, rpcCache, serveCachedSessionList,
  sessionListCacheKey, storeSessionList,
} from './session-list-cache.mjs';

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
    sendHtml(res, 200, loginPage(''));
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

  const user = sessionUser(req);
  if (!user) {
    res.writeHead(303, { location: '/hub/login' });
    res.end();
    return;
  }
  if (!lookupUser(user)) {  // account deleted since login
    handleLogout(req, res);
    return;
  }

  // Session-list RPC cache: serve the last known snapshot forever (serve-stale),
  // refresh it in the background on a throttle (see block above).
  if (req.method === 'POST' && url.pathname === SESSION_LIST_PATH) {
    const body = await readRequestBody(req);
    const key = sessionListCacheKey(user, body);
    const entry = rpcCache.get(key);
    const now = Date.now();
    if (entry) {
      serveCachedSessionList(res, entry, requestRpcId(body));
      if (now >= entry.nextRevalidateAt && !entry.inflight) {
        entry.inflight = true;
        const be = backends.get(user);
        if (be?.port) {
          revalidateSessionList(user, be, body, key).catch((err) =>
            console.error(`[hub] session.list revalidate failed for ${user}:`, err.message));
        } else {
          deferSessionList(entry);
        }
      }
      return;
    }
    // No snapshot yet: forward (capturing), cache 200s, respond.
    let be;
    try {
      be = await getOrCreateBackend(user);
    } catch (err) {
      console.error(`[hub] spawn failed for ${user}:`, err.message);
      sendHtml(res, 503, `<pre>dsh-hub: fail to launch\n${err.message}</pre>`);
      return;
    }
    be.lastActivity = Date.now();
    req.headers.origin = `http://127.0.0.1:${be.port}`;
    req.headers['accept-encoding'] = 'identity';
    // Present the hub's own cookie for this backend, not the browser's: after a
    // respawn the browser still carries the old port's cookie name and dsh would
    // refuse it, while the hub always mints for the current authority.
    const internalCookie = await hubDshCookieHeader(be);
    if (internalCookie) req.headers.cookie = internalCookie;
    let captured;
    try {
      captured = await forwardSessionList(be, req.headers, body);
    } catch (err) {
      // Backend died between spawn and forward (cull/restart race): fall back
      // to the streaming proxy, which re-triggers the spawn-on-demand path.
      console.error(`[hub] session.list forward failed for ${user}:`, err.message);
      proxy.web(req, res, { target: `http://127.0.0.1:${be.port}` });
      return;
    }
    if (isCacheableSessionList(captured)) storeSessionList(key, captured);
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
    const failure = spawnFailures.get(user);
    if (failure !== undefined) {
      spawnFailures.delete(user);
      sendHtml(res, 503, `<pre>dsh-hub: fail to launch\n${failure}</pre>`);
      return;
    }
    startBackendInBackground(user);
    if (req.method === 'GET' && isIndexPath(url.pathname)) {
      sendHtml(res, 200, STARTING_PAGE);
    } else {
      res.writeHead(503, { 'retry-after': '3', 'content-type': 'text/plain; charset=utf-8' });
      res.end('dsh-hub: dsh instance is starting\n');
    }
    return;
  }
  spawnFailures.delete(user);
  be.lastActivity = Date.now();
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
    // request already passed the hub's PAM cookie authentication.
    req.headers.origin = `http://127.0.0.1:${be.port}`;
  }
  // Force identity encoding so the HTML rewrite below sees plain text.
  req.headers['accept-encoding'] = 'identity';
  proxy.web(req, res, { target: `http://127.0.0.1:${be.port}` });
}
