// Multi-user account policy: existence, PAM, the shadow fingerprint, the
// no-password/allow-list rules, and the per-user cookie key derived from the
// shadow entry.
import crypto from 'node:crypto';
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';

import { CFG } from './config.mjs';
import { decoyUser, lookupUser, pamAuthenticate } from '../backend/auth.mjs';

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
function readShadow(user) {
  if (!/^[a-z_][a-z0-9_-]{0,31}$/i.test(user)) return null;
  let out;
  try {
    out = execFileSync('getent', ['shadow', user], {
      timeout: 3000,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
  } catch {
    return null;
  }
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

/**
 * The cached per-user key. The cache stores only the derived key (never the
 * shadow line) and is bounded. A cookie for a user with no cache entry is
 * rejected without an NSS call, so forged cookies cannot force `getent` runs.
 * @param force - refresh even when the cached entry is fresh (used at login).
 * @returns the entry, or null when the user has no shadow entry.
 */
function credentialFor(user, force = false) {
  const now = Date.now();
  const cached = USERS.get(user);
  if (!force && cached !== undefined) {
    const fresh = now - cached.checkedAt < CFG.fingerprintTtlMs && shadowMtime() <= cached.mtime;
    if (fresh) {
      cached.lastUsed = now;
      USERS.delete(user);
      USERS.set(user, cached);
      return cached;
    }
  }
  const shadow = readShadow(user);
  if (shadow === null) {
    USERS.delete(user);
    return null;
  }
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
  if (!lookupUser(username)) {
    // Count the probe against the window and equalize timing with a real PAM
    // check against a decoy account. The outcome is ignored.
    const decoy = decoyUser(CFG.authDecoyUser);
    if (decoy !== null) {
      try { await pamAuthenticate(decoy, password); } catch { /* outcome ignored */ }
    }
    return { ok: false, reason: 'unknown-user' };
  }
  if (!await pamAuthenticate(username, password)) return { ok: false, reason: 'auth-failed' };
  const credential = credentialFor(username, true);
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
 * (no cache entry) is rejected without an NSS call.
 */
export function keyFor(user, force = false) {
  if (!force && !USERS.has(user)) return null;
  const credential = credentialFor(user, force);
  if (credential === null) return null;
  if (!credential.hasPassword && !CFG.allowNoPassword) return null;
  return credential.key;
}
