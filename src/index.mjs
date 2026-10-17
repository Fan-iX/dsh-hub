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
//
// This file is the composition root: it wires the modules under src/ together
// (see the module map in README.md) and owns process startup.

import fs from 'node:fs';

import {
  AUTH_LOG_FILE, CACHE_DIR, CFG, IPTABLES, IS_ROOT, SECRET_PATH, TRUSTED_HOSTS, TRUST_MODE,
} from './config.mjs';
import { loadPersistedCache } from './session-list-cache.mjs';
import { createHubServer } from './server.mjs';
import { createShutdown, registerSignalHandlers } from './shutdown.mjs';
import { writeAccountUiPatch } from './dsh-patch.mjs';

// -------------------------------------------------------------------- wire ---
loadPersistedCache(); // restore session-list cache entries across hub restarts
const accountUiHidden = CFG.hideAccountUi && writeAccountUiPatch();
const server = createHubServer();
registerSignalHandlers(createShutdown(server));

// -------------------------------------------------------------------- boot ---
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
  console.log(accountUiHidden
    ? '[hub] account UI: hidden in spawned dsh instances (HIDE_ACCOUNT_UI=0 shows it)'
    : CFG.hideAccountUi
      ? '[hub] WARNING: account-UI patch missing — spawned instances keep the sign-in button'
      : '[hub] account UI: visible in spawned dsh instances (HIDE_ACCOUNT_UI=0)');
});
