// System account lookup via getent, cached per username.
import { execFileSync } from 'node:child_process';

const passwdCache = new Map(); // user -> {uid, gid, home, shell} | null

export function lookupUser(user) {
  if (!/^[a-z_][a-z0-9_-]{0,31}$/i.test(user)) return null;
  if (passwdCache.has(user)) return passwdCache.get(user);
  let info = null;
  try {
    const out = execFileSync('getent', ['passwd', user], { timeout: 3000 }).toString();
    const [name, , uid, gid, , home, shell] = out.trim().split(':');
    if (name === user) info = { uid: +uid, gid: +gid, home, shell };
  } catch { /* unknown user */ }
  passwdCache.set(user, info);
  return info;
}
