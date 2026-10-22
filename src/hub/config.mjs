// Multi-user hub configuration: root-only settings layered over the shared
// backend configuration.
import path from 'node:path';

import {
  BASE, CACHE_DIR, IS_ROOT, TRUSTED_HOSTS, TRUST_MODE, hasBin, int,
} from '../backend/config.mjs';

export { CACHE_DIR, IS_ROOT, TRUSTED_HOSTS, TRUST_MODE };

export const IPTABLES = IS_ROOT && hasBin('iptables');

export const CFG = {
  ...BASE,
  // Admin-maintained global dsh overlays (`*.yml` drop-ins) applied to every
  // instance the hub spawns, in file-name order. Non-secret, world-readable.
  webConfigDir: process.env.HUB_WEB_CONFIG_DIR ?? '/etc/dsh-hub/web_config.d',
  // Optional comma-separated allow-list of usernames. Empty = all system users.
  allowUsers: (process.env.ALLOW_USERS ?? '')
    .split(',').map((s) => s.trim()).filter(Boolean),
  logDir: process.env.HUB_LOG_DIR ?? '/var/log/dsh-hub',
  // On SIGTERM/SIGINT/SIGHUP: stop every spawned instance, then delete the
  // persisted session-list cache. Set HUB_CLEAN_ON_STOP=0 to keep the cache.
  cleanOnStop: process.env.HUB_CLEAN_ON_STOP !== '0',
  // A shadow entry with no usable password is denied a session unless this is
  // set. Empty/locked hashes (`!`, `*`, `x`) count as no password.
  allowNoPassword: process.env.ALLOW_NOPASSWD === '1',
  // How long a derived per-user key is trusted before the shadow entry is
  // re-read (`/etc/shadow` mtime changes also force a refresh).
  fingerprintTtlMs: int(process.env.FINGERPRINT_TTL_MS, 60_000),
};

// Append-only authentication audit log: one stable line per login outcome,
// tagged with the resolved client IP, so an external log-driven banner can
// filter and ban without the hub keeping its own ban list.
export const AUTH_LOG_FILE = process.env.HUB_AUTH_LOG ?? path.join(CFG.logDir, 'auth.log');
