// dsh-hub — a JupyterHub-style front for DeepSeek Harness (dsh).
//
// Architecture (mirrors JupyterHub):
//   Authenticator  — PAM (system accounts), login page, HMAC-signed session cookie
//   Spawner        — on first authenticated request, spawn `dsh web --port <N>`
//                    as that OS user (uid/gid), with DSH_HOME isolated per user,
//                    plus an iptables loopback owner-guard so OTHER local users
//                    cannot reach the unauthenticated dsh port.
//   Proxy          — routes HTTP + WebSocket by session cookie to the user's backend
//                    (single shared hostname; no path rewriting needed).
//   Culler         — stops idle backends after IDLE_CULL_MS and removes guards.
//
// dsh itself is NOT modified — it stays on 127.0.0.1, single-user, untouched,
// so upstream upgrades and plugin installs keep working.
//
// Run as root (systemd) for PAM + setuid + iptables. Non-root runs in degraded
// dev mode (no setuid spawn, no iptables guard, PAM may fail without shadow access).

import http from 'node:http';
import fs from 'node:fs';

import {
  AUTH_LOG_FILE, CACHE_DIR, CFG, IPTABLES, IS_ROOT, SECRET_PATH, TRUSTED_HOSTS, TRUST_MODE,
} from './config.mjs';
import { handleLogin, handleLogout, sessionUser } from './auth.mjs';
import { lookupUser } from './users.mjs';
import { sendHtml } from './http.mjs';
import { STARTING_PAGE, loginPage } from './pages.mjs';
import { bridgeDshBrowserSession, isIndexPath } from './browser-session.mjs';
import { proxy } from './proxy.mjs';
import { backends, getOrCreateBackend, removeGuard } from './backends.mjs';
import {
  SESSION_LIST_PATH, deferSessionList, forwardSessionList, isCacheableSessionList, loadPersistedCache,
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

async function route(req, res) {
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

loadPersistedCache(); // restore session-list cache entries across hub restarts

const server = http.createServer((req, res) => {
  route(req, res).catch((err) => {
    console.error('[hub] handler error:', err);
    if (!res.headersSent) res.writeHead(500);
    res.end('dsh-hub: internal error');
  });
});

// WebSocket upgrade (dsh event streams) — routed by the same session cookie.
server.on('upgrade', (req, socket, head) => {
  const user = sessionUser(req);
  if (!user) {
    socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
    socket.destroy();
    return;
  }
  const be = backends.get(user);
  if (!be || !be.child || be.child.exitCode !== null) {
    socket.write('HTTP/1.1 503 Service Unavailable\r\n\r\n');
    socket.destroy();
    return;
  }
  be.lastActivity = Date.now();
  if (TRUST_MODE === 'origin-rewrite') {
    req.headers.origin = `http://127.0.0.1:${be.port}`;
  }
  proxy.ws(req, socket, head, { target: `http://127.0.0.1:${be.port}` });
});

// -------------------------------------------------------------- shutdown -----
// An external stop (SIGTERM/SIGINT/SIGHUP) tears down everything this hub owns:
// every spawned dsh instance (its whole process group, SIGTERM then SIGKILL),
// their loopback guards, the persisted session-list cache, and the cookie-signing
// secret. Cleanup is best-effort and bounded, so one wedged backend can never
// keep the hub alive. HUB_CLEAN_ON_STOP=0 leaves the cache and secret in place.
let shuttingDown = false;

/** Signal one backend's whole process group, falling back to the direct child. */
function killBackendTree(be, signal) {
  if (!be?.child || be.child.exitCode !== null) return;
  try {
    process.kill(-be.child.pid, signal); // detached spawn ⇒ negative pid = its group
  } catch {
    try { be.child.kill(signal); } catch { /* already gone */ }
  }
}

/** SIGKILL every live backend and release its loopback guard. */
function forceKillBackends() {
  for (const be of backends.values()) {
    killBackendTree(be, 'SIGKILL');
    removeGuard(be.port, be.info.uid);
  }
}

/** Delete the persisted cache and the cookie secret unless cleanup is disabled. */
function removeRuntimeState() {
  if (!CFG.cleanOnStop) {
    console.log('[hub] HUB_CLEAN_ON_STOP=0: keeping cache and cookie secret');
    return;
  }
  for (const [what, target, options] of [
    ['cache', CACHE_DIR, { recursive: true, force: true }],
    ['cookie secret', SECRET_PATH, { force: true }],
  ]) {
    try {
      fs.rmSync(target, options);
      console.log(`[hub] removed ${what} ${target}`);
    } catch (err) {
      console.error(`[hub] ${what} cleanup failed:`, err.message);
    }
  }
}

/** Stop instances, remove runtime state, and exit; a second signal forces it. */
function shutdown(reason) {
  if (shuttingDown) {
    console.warn(`[hub] ${reason} again during shutdown — forcing exit`);
    forceKillBackends();
    removeRuntimeState();
    process.exit(0);
  }
  shuttingDown = true;
  console.log(`[hub] ${reason} received: stopping ${backends.size} dsh instance(s)`);
  try { server.close(); } catch { /* already closing */ }

  const pending = [...backends.values()].filter((be) => be.child && be.child.exitCode === null);
  for (const be of pending) killBackendTree(be, 'SIGTERM');

  const deadline = Date.now() + CFG.shutdownGraceMs;
  let finished = false;
  let timer;
  const finish = () => {
    if (finished) return;
    finished = true;
    clearInterval(timer);
    forceKillBackends(); // the child exit handler normally removed guards; this is the backstop
    removeRuntimeState();
    console.log('[hub] shutdown complete');
    process.exit(0);
  };
  timer = setInterval(() => {
    if (!pending.some((be) => be.child.exitCode === null)) { finish(); return; }
    if (Date.now() >= deadline) finish();
  }, 100);
  // Hard ceiling: never let a wedged backend hold the process open.
  setTimeout(finish, CFG.shutdownGraceMs + 3000);
}

for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) {
  process.on(signal, () => shutdown(signal));
}

// ------------------------------------------------------------------ boot ----

try { fs.mkdirSync(CFG.logDir, { recursive: true }); } catch { /* non-root dev run */ }
server.listen(CFG.hubPort, CFG.hubHost, () => {
  console.log(`[hub] dsh-hub listening on ${CFG.hubHost}:${CFG.hubPort}`);
  console.log(`[hub] dsh binary: ${CFG.dshBin}`);
  console.log(`[hub] trust mode: ${TRUST_MODE}` +
    (TRUST_MODE === 'trusted-host' ? ` (authorities: ${TRUSTED_HOSTS.join(', ') || 'none detected — set TRUSTED_HOSTS'})` : ''));
  console.log(`[hub] running as ${IS_ROOT ? 'root (full isolation mode)' : `uid ${process.getuid?.()} (dev mode — no setuid/iptables)`}`);
  if (!IPTABLES) console.warn('[hub] WARNING: iptables unavailable — loopback ports of user instances are NOT guarded against other local users');
  if (CFG.allowUsers.length) console.log(`[hub] allow-list: ${CFG.allowUsers.join(', ')}`);
  console.log(`[hub] login guard: ${CFG.authMaxFailures} failures / `
    + (CFG.authWindowMs >= 60_000 ? `${Math.round(CFG.authWindowMs / 60_000)} min` : `${Math.round(CFG.authWindowMs / 1000)} s`)
    + ' per IP'
    + (CFG.trustedProxies.length ? `, trusting X-Forwarded-For from ${CFG.trustedProxies.join(', ')}` : ', using the TCP peer address only'));
  console.log(`[hub] auth audit log: ${AUTH_LOG_FILE}`);
  console.log(CFG.cleanOnStop
    ? `[hub] on SIGTERM/SIGINT/SIGHUP: stop instances and remove ${CACHE_DIR} + ${SECRET_PATH}`
    : '[hub] on stop: instances stopped, cache and cookie secret kept (HUB_CLEAN_ON_STOP=0)');
  console.log(CFG.idleCullMs === 0
    ? '[hub] idle culling DISABLED — backends run until stopped'
    : `[hub] idle cull after ${Math.round(CFG.idleCullMs / 60000)} min`);
});
