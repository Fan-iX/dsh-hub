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
import { sessionUser } from './auth.mjs';
import { proxy } from './proxy.mjs';
import { route } from './router.mjs';
import { backends, removeGuard } from './backends.mjs';
import { loadPersistedCache } from './session-list-cache.mjs';

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
