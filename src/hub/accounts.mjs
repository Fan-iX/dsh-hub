// Multi-user account policy: existence, PAM, the shadow fingerprint, the
// no-password/allow-list rules, and the per-user cookie key derived from the
// shadow entry.
import crypto from 'node:crypto';
import fs from 'node:fs';

import { CFG } from './config.mjs';
import { decoyUser, lookupUser, nssExec, pamAuthenticate } from '../backend/auth.mjs';

export { lookupUser };

// --------------------------------------------------- session credential -----
//
// A cookie is `user.exp.HMAC(key(user), user.exp)`, where `key(user)` comes from
// that user's shadow entry. A password change, lock, or forced change alters the
// entry and invalidates the user's cookies. The pepper lives only in this
// process: a shadow backup alone cannot forge a cookie, and no secret file is
// written. A restart therefore invalidates all sessions, matching the default
// clean-stop behavior.

const PEPPER = crypto.randomBytes(32);
const USERS_MAX = 10_000;
const USERS = new Map(); // user -> { key, hasPassword, checkedAt, mtime, lastUsed }

/** A shadow password field that can actually authenticate (not empty/locked). */
function hasUsablePassword(hash) {
  return hash !== ''
    && hash !== 'x'
    && hash !== '*'
    && hash !== '!'
    && !hash.startsWith('!')
    && !hash.startsWith('*');
}

/**
 * Read one user's shadow entry through NSS (`getent`). The whole line is the
 * fingerprint: the hash changes with the password, and the other fields change
 * on lock, expiry, or a forced change. No shadow file is parsed directly.
 * @returns `{ line, hasPassword }`, or null when no shadow entry is available.
 */
async function readShadow(user) {
  if (!/^[a-z_][a-z0-9_-]{0,31}$/i.test(user)) return null;
  const out = await nssExec(['shadow', user]);
  if (out === null) return null;
  const line = out.split('\n').find((row) => row.startsWith(`${user}:`));
  if (line === undefined) return null;
  const fields = line.split(':');
  if (fields.length < 2 || fields[0] !== user) return null;
  return { line, hasPassword: hasUsablePassword(fields[1]) };
}

/** mtime of the local shadow file, or 0 when NSS provides no such file. */
function shadowMtime() {
  try {
    return fs.statSync('/etc/shadow').mtimeMs;
  } catch {
    return 0;
  }
}

/** Store one freshly read shadow fingerprint as the user's key. */
function storeCredential(user, shadow, now) {
  const key = crypto.createHmac('sha256', PEPPER).update(`${user}\0${shadow.line}`).digest();
  const entry = {
    key,
    hasPassword: shadow.hasPassword,
    checkedAt: now,
    mtime: shadowMtime(),
    lastUsed: now,
  };
  USERS.delete(user);
  USERS.set(user, entry);
  if (USERS.size > USERS_MAX) {
    const oldest = USERS.keys().next().value;
    if (oldest !== undefined) USERS.delete(oldest);
  }
  return entry;
}

/**
 * Refresh one user's credential from NSS. Async so a slow `getent shadow`
 * cannot block the event loop.
 * @param keepExisting - on a failed read, keep the cached entry (and age it) so
 *   a transient NSS outage does not sign the user out.
 */
async function refreshCredential(user, keepExisting) {
  const shadow = await readShadow(user);
  if (shadow === null) {
    if (keepExisting) {
      const cached = USERS.get(user);
      if (cached !== undefined) cached.checkedAt = Date.now();
    } else {
      USERS.delete(user);
    }
    return null;
  }
  return storeCredential(user, shadow, Date.now());
}

const refreshing = new Set();

function scheduleRefresh(user) {
  if (refreshing.has(user)) return;
  refreshing.add(user);
  void refreshCredential(user, true)
    .catch((err) => console.error(`[hub] shadow refresh failed for ${user}:`, err.message))
    .finally(() => refreshing.delete(user));
}

/**
 * The cached key for a request. The cache stores only the derived key (never
 * the shadow line) and is bounded. A stale entry is returned while a background
 * refresh runs; a cookie for a user with no entry is rejected without an NSS
 * call, so forged cookies cannot force `getent` runs.
 * @returns the entry, or null when the user has no cached key.
 */
function cachedCredential(user) {
  const now = Date.now();
  const cached = USERS.get(user);
  if (cached === undefined) return null;
  const fresh = now - cached.checkedAt < CFG.fingerprintTtlMs && shadowMtime() <= cached.mtime;
  if (!fresh) scheduleRefresh(user);
  cached.lastUsed = now;
  USERS.delete(user);
  USERS.set(user, cached);
  return cached;
}

setInterval(() => {
  const cutoff = Date.now() - CFG.sessionTtlMs - CFG.fingerprintTtlMs;
  for (const [user, entry] of USERS) {
    if (entry.lastUsed < cutoff) USERS.delete(user);
  }
}, 60_000).unref();

// ------------------------------------------------------------ verification --

/**
 * Check one login for the multi-user hub.
 * @returns `{ ok, reason }`; the shared login flow audits the reason.
 */
export async function verify(username, password) {
  if (!await lookupUser(username, true)) {
    // Count the probe against the window and equalize timing with a real PAM
    // check against a decoy account. The outcome is ignored.
    const decoy = await decoyUser(CFG.authDecoyUser);
    if (decoy !== null) {
      try { await pamAuthenticate(decoy, password); } catch { /* outcome ignored */ }
    }
    return { ok: false, reason: 'unknown-user' };
  }
  const auth = await pamAuthenticate(username, password);
  if (!auth.ok) {
    // PAM_MAXTRIES (11) is a PAM-side lockout; surface it like our own guard.
    return { ok: false, reason: auth.code === 11 ? 'too-many' : 'auth-failed' };
  }
  const credential = await refreshCredential(username, false);
  if (credential === null) return { ok: false, reason: 'shadow-unavailable' };
  if (!credential.hasPassword && !CFG.allowNoPassword) return { ok: false, reason: 'no-password' };
  if (CFG.allowUsers.length && !CFG.allowUsers.includes(username)) {
    return { ok: false, reason: 'not-allowed' };
  }
  return { ok: true };
}

/**
 * The cookie key for `user`, or null when no session may be issued or kept.
 * With `force = false` a user that has not logged in since this process started
 * (no cache entry) is rejected without an NSS call. A stale entry is used while
 * a refresh runs in the background.
 */
export function keyFor(user, force = false) {
  if (!USERS.has(user)) return null;
  const credential = force ? USERS.get(user) : cachedCredential(user);
  if (credential === null) return null;
  if (!credential.hasPassword && !CFG.allowNoPassword) return null;
  return credential.key;
}
