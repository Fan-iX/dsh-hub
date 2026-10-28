// Single-user authentication: the only accepted username is the account running
// the proxy, and its password is checked through PAM (native first, `su <self>`
// as the fallback), so the login page keeps the same username/password contract
// as the multi-user hub. The session key is an in-memory pepper — there is no
// shadow access and no secret file; a proxy restart logs the browser out.
import crypto from 'node:crypto';

import { CFG } from './config.mjs';
import { decoyUser, lookupUser, pamAuthenticate } from '../backend/auth.mjs';

export { lookupUser };

const PEPPER = crypto.randomBytes(32);
const SERVICE = CFG.serviceUser;

/**
 * Check one login. Any username other than the service account is rejected
 * after the same decoy PAM path used by the hub, so unknown usernames do not
 * reveal themselves by timing.
 * @returns `{ ok, reason }`.
 */
export async function verify(username, password) {
  if (username !== SERVICE) {
    const decoy = await decoyUser(CFG.authDecoyUser);
    if (decoy !== null) {
      try { await pamAuthenticate(decoy, password); } catch { /* outcome ignored */ }
    }
    return { ok: false, reason: 'unknown-user' };
  }
  const ok = await pamAuthenticate(username, password);
  return ok ? { ok: true } : { ok: false, reason: 'auth-failed' };
}

/**
 * The cookie key for the service account. No per-session or per-user state is
 * needed in single-user mode; a restart invalidates cookies with the pepper.
 */
export function keyFor(user, _force = false) {
  if (user !== SERVICE) return null;
  return crypto.createHmac('sha256', PEPPER).update(user).digest();
}
