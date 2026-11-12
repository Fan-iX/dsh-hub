// Single-user HTTP entry: the same login page/session contract as the
// multi-user hub, a lazily spawned single dsh instance, and HTTP/WebSocket
// forwarding with the same page hooks and dsh browser-session bridge.
import http from 'node:http';

import { CFG, TRUSTED_HOSTS, TRUST_MODE } from './config.mjs';
import { keyFor, lookupUser, verify } from './auth.mjs';
import { createLogin } from '../backend/auth.mjs';
import { DshInstance } from '../backend/instance.mjs';
import { bridgeDshBrowserSession, isIndexPath, proxy } from '../backend/dsh-proxy.mjs';
import {
  handleKeepAlive, localeFromRequest, loginErrorMessage, loginPage, pageHeaders, sendHtml, sendJson,
  startingPage, t, wantsDocument,
} from '../backend/web.mjs';

const { handleLogin, handleLogout, sessionInfo, sessionUser, maybeRefreshSession } = createLogin({
  verify, keyFor, auditPath: CFG.authLogPath, cfg: CFG,
});

let instance = null;
let spawnInflight = false;
let spawnFailure = null;

function spawnProxyInstance() {
  const inst = new DshInstance({
    user: CFG.serviceUser,
    cwd: CFG.workspace,
    env: {
      ...process.env,
      HOME: CFG.home,
      DSH_HOME: CFG.dshHome,
      // Marks the process as hub-spawned for host-side plugins (dsh-hub-utils
      // registers its quit route only under the hub).
      DSH_HUB: '1',
    },
    bin: CFG.dshBin,
    patches: [],
    trustMode: TRUST_MODE,
    trustedHosts: TRUSTED_HOSTS,
    logPath: CFG.logPath,
    spawnTimeoutMs: CFG.spawnTimeoutMs,
    onExit: (be) => {
      if (instance === be) instance = null;
    },
  });
  instance = inst;
  return inst;
}

/** Start (or join) the single instance's spawn without blocking the request. */
function startInstanceInBackground() {
  if (spawnInflight) return;
  if (instance !== null && instance.child && instance.child.exitCode === null) return;
  spawnInflight = true;
  const inst = spawnProxyInstance();
  inst.start()
    .then(() => {
      spawnFailure = null;
      console.log(`[hub] proxy dsh ready for ${CFG.serviceUser} on 127.0.0.1:${inst.port}`);
    })
    .catch((err) => {
      spawnFailure = err.message;
      console.error(`[hub] proxy dsh spawn failed for ${CFG.serviceUser}:`, err.message);
      if (instance === inst) instance = null;
    })
    .finally(() => { spawnInflight = false; });
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
  if (!await lookupUser(user)) { // service account deleted since login
    handleLogout(req, res);
    return;
  }
  if (url.pathname === '/hub/api/session') {
    const effectiveExp = maybeRefreshSession(res, session) ?? session.exp;
    sendJson(res, 200, {
      authenticated: true,
      user,
      expiresInSec: Math.max(0, Math.floor((effectiveExp - Date.now()) / 1000)),
    });
    return;
  }
  if (url.pathname === '/hub/api/keepalive') {
    await handleKeepAlive(req, res, instance);
    return;
  }

  // Never block on a cold instance: start (or join) the spawn in the background
  // and answer immediately. The index gets the static loading page; anything
  // else gets a retryable 503.
  let be = instance;
  if (!be || !be.child || be.child.exitCode !== null || be.starting) {
    const locale = localeFromRequest(req);
    if (spawnFailure !== null) {
      const failure = spawnFailure;
      spawnFailure = null;
      sendHtml(res, 503, `<pre>${t(locale, 'error.spawnFailed')}\n${failure}</pre>`,
        pageHeaders(req, locale));
      return;
    }
    startInstanceInBackground();
    if (req.method === 'GET' && isIndexPath(url.pathname)) {
      sendHtml(res, 200, startingPage(locale), pageHeaders(req, locale));
    } else {
      res.writeHead(503, { 'content-type': 'text/plain; charset=utf-8', 'retry-after': '3' });
      res.end(`${t(locale, 'error.starting')}\n`);
    }
    return;
  }
  be.touch();
  req.hubBackend = be; // lets the proxy 401 handler re-mint dsh's session cookie
  // First navigation of an authenticated session: mint dsh's own browser-session
  // cookie before touching the backend, so the index never answers 401.
  if (req.method === 'GET' && isIndexPath(url.pathname)) {
    try {
      if (await bridgeDshBrowserSession(req, res, be)) return;
    } catch (err) {
      console.error(`[hub] browser-session bridge failed for ${CFG.serviceUser}:`, err.message);
    }
  }
  if (TRUST_MODE === 'origin-rewrite') {
    req.headers.origin = `http://127.0.0.1:${be.port}`;
  }
  // Force identity encoding so the HTML rewrite sees plain text.
  req.headers['accept-encoding'] = 'identity';
  // Sending a message refreshes the sliding session cookie; see the hub route.
  if (url.pathname === '/api/session/prompt') {
    maybeRefreshSession(res, session);
  }
  proxy.web(req, res, { target: `http://127.0.0.1:${be.port}` });
}

/**
 * Create the single-user HTTP server.
 * @returns `{ server, getInstance }`; the caller owns `listen`/signals.
 */
export function createProxyServer() {
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

  server.on('upgrade', (req, socket, head) => {
    const user = sessionUser(req);
    if (!user) {
      socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      socket.destroy();
      return;
    }
    const be = instance;
    if (!be || !be.child || be.child.exitCode !== null || be.starting) {
      socket.write('HTTP/1.1 503 Service Unavailable\r\n\r\n');
      socket.destroy();
      return;
    }
    be.touch();
    be.wsClients += 1;
    let detached = false;
    const detach = () => {
      if (detached) return;
      detached = true;
      be.wsClients = Math.max(0, be.wsClients - 1);
      be.touch();
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

  return { server, getInstance: () => instance };
}
