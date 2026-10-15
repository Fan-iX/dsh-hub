// Environment-derived configuration, deployment paths, and host facts. Every
// value is read once at startup; the rest of the hub imports the resolved
// constants instead of touching process.env.

import fs from 'node:fs';
import path from 'node:path';
import { networkInterfaces } from 'node:os';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** Positive integer env value, or `dflt`. */
export function int(v, dflt) { const n = Number(v); return Number.isInteger(n) && n > 0 ? n : dflt; }
/** Non-negative integer env value, or `dflt`. */
export function intOrZero(v, dflt) { const n = Number(v); return Number.isInteger(n) && n >= 0 ? n : dflt; }

// Trust modes:
//  - 'origin-rewrite' (default): proxy rewrites Host (changeOrigin) and Origin
//    to loopback; CSRF protection is carried by the hub's SameSite=Lax cookie.
//    This is the ONLY mode that works behind a loopback-binding proxy: dsh's
//    RPC host empties trustedHosts for loopback-authority /api channels
//    (rpc-host.ts: `authority === 'loopback' ? [] : trustedHosts`), so
//    --trusted-host cannot grant non-loopback Hosts there.
//  - 'trusted-host': spawn dsh with its official `--trusted-host` flag and
//    forward Host/Origin untouched. Only works when the fence actually feeds
//    the flag to the channel (direct LAN binds), kept for future dsh support
//    of proxied deployments.
export const TRUST_MODE = process.env.TRUST_MODE === 'trusted-host' ? 'trusted-host' : 'origin-rewrite';

function lanIpv4s() {
  return Object.values(networkInterfaces()).flat()
    .filter((i) => i && i.family === 'IPv4' && !i.internal)
    .map((i) => i.address);
}

export const TRUSTED_HOSTS = [
  ...lanIpv4s(),
  ...(process.env.TRUSTED_HOSTS ?? '')
    .split(',').map((s) => s.trim()).filter(Boolean),
];

/** Absolute path of the dsh CLI entry to spawn, or a fatal exit. */
export function detectDshBin() {
  if (process.env.DSH_BIN) return process.env.DSH_BIN;
  const candidates = [
    // local installation with `npm install @deepseek-ai/dsh`
    path.resolve(__dirname, '../node_modules/.bin/dsh'),
    // system global installation with `npm install -g @deepseek-ai/dsh`
    '/usr/local/bin/dsh',
    '/usr/bin/dsh',
  ];
  for (const c of candidates) {
    try { fs.accessSync(c, fs.constants.X_OK); return c; } catch { /* next */ }
  }
  console.error(
    '[hub] FATAL: dsh binary not found. Set DSH_BIN to the dsh CLI entry\n' +
    '[hub] (a built checkout: <repo>/apps/cli/lib/bin.js). Detected candidates:\n' +
    candidates.map((c) => `        ${c}`).join('\n'));
  process.exit(1);
}

/** True when `name` is an executable found on the standard system paths. */
export function hasBin(name) {
  const { statSync } = fs;
  for (const dir of ['/usr/sbin', '/usr/bin', '/sbin', '/bin']) {
    try { statSync(`${dir}/${name}`); return true; } catch { /* keep looking */ }
  }
  return false;
}

export const CFG = {
  hubHost: process.env.HUB_HOST ?? '0.0.0.0',
  hubPort: int(process.env.HUB_PORT, 3080),
  dshBin: detectDshBin(),
  sessionTtlMs: int(process.env.SESSION_TTL_MS, 7 * 24 * 3600 * 1000),
  // 0 disables culling entirely — backends keep running with the browser
  // closed, JupyterHub/tmux-style. Pick a positive value to reap idle ones.
  idleCullMs: intOrZero(process.env.IDLE_CULL_MS, 4 * 3600 * 1000),
  spawnTimeoutMs: int(process.env.SPAWN_TIMEOUT_MS, 60_000),
  cookieName: 'dshhub_session',
  // Optional comma-separated allow-list of usernames. Empty = all system users.
  allowUsers: (process.env.ALLOW_USERS ?? '')
    .split(',').map((s) => s.trim()).filter(Boolean),
  logDir: process.env.HUB_LOG_DIR ?? '/var/log/dsh-hub',
  // On SIGTERM/SIGINT/SIGHUP: stop every spawned instance, then delete the
  // persisted session-list cache and the cookie-signing secret. Set
  // HUB_CLEAN_ON_STOP=0 to keep them (a plain restart should not log every
  // browser out). The grace period bounds how long a backend may take to exit
  // before it is SIGKILLed.
  cleanOnStop: process.env.HUB_CLEAN_ON_STOP !== '0',
  shutdownGraceMs: int(process.env.SHUTDOWN_GRACE_MS, 5000),
  // Login guard: failures are counted per client IP inside a sliding window.
  // Reaching AUTH_MAX_FAILURES within AUTH_WINDOW_MS answers 429 until the
  // oldest counted failure ages out of the window.
  authWindowMs: int(process.env.AUTH_WINDOW_MS, 10 * 60 * 1000),
  authMaxFailures: int(process.env.AUTH_MAX_FAILURES, 5),
  // Comma-separated IPs/CIDRs whose X-Forwarded-For / X-Real-IP may be trusted.
  // Empty (the default) always uses the TCP peer address and ignores both.
  trustedProxies: (process.env.TRUSTED_PROXIES ?? '')
    .split(',').map((s) => s.trim()).filter(Boolean),
};

// Append-only authentication audit log: one stable line per login outcome,
// tagged with the resolved client IP, so an external log-driven banner can
// filter and ban without the hub keeping its own ban list.
export const AUTH_LOG_FILE = process.env.HUB_AUTH_LOG ?? path.join(CFG.logDir, 'auth.log');

export const IS_ROOT = process.getuid?.() === 0;
export const IPTABLES = IS_ROOT && hasBin('iptables');

// Runtime state (the signing secret and the session-list cache) lives in the
// launch directory — the service's WorkingDirectory — not in the checkout,
// which may be read-only or shared after deployment. Both paths are therefore
// resolved from the process working directory, not relative to this module.
export const RUNTIME_DIR = process.cwd();
export const SECRET_PATH = process.env.COOKIE_SECRET_FILE ?? path.join(RUNTIME_DIR, '.cookie-secret');
export const CACHE_DIR = path.join(RUNTIME_DIR, 'cache');
