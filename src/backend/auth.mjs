// Shared authentication flow: login page/guard/audit, the signed session
// cookie, PAM verification, and system account lookup. The two entry points
// supply only `verify` (how a password is checked) and `keyFor` (which HMAC key
// signs that user's cookie).
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';

import { IS_ROOT } from './config.mjs';
import {
  localeFromRequest, loginPage, pageHeaders, readBody, sendHtml, t, urlencoded,
} from './web.mjs';

const execFileAsync = promisify(execFile);

// ------------------------------------------------------- system accounts ----
//
// NSS (`getent`) can block for seconds when a network backend (SSSD/LDAP/
// winbind) is unreachable, so it must never run synchronously on the request
// path. Every lookup is an async child with a hard SIGKILL timeout; Node reaps
// the async child, and a hung query only delays the lookup that asked for it,
// not the whole hub. Results are cached with a TTL and single-flight per user;
// a stale entry is served while a refresh runs in the background.

const NSS_OPTS = {
  timeout: 3000,
  killSignal: 'SIGKILL',
  encoding: 'utf8',
  maxBuffer: 1 << 20,
};
const PASSWD_TTL_MS = 60_000;

const passwdCache = new Map(); // user -> { info, checkedAt }
const passwdInflight = new Map(); // user -> Promise

/**
 * Run `getent` with a hard timeout.
 * @returns stdout, or null when the lookup failed or timed out.
 */
export async function nssExec(args) {
  try {
    const { stdout } = await execFileAsync('getent', args, NSS_OPTS);
    return stdout;
  } catch {
    return null;
  }
}

async function fetchPasswd(user) {
  const out = await nssExec(['passwd', user]);
  if (out === null) return null;
  const [name, , uid, gid, , home, shell] = out.trim().split(':');
  if (name !== user) return null;
  return { uid: +uid, gid: +gid, home, shell };
}

function refreshPasswd(user) {
  const inflight = passwdInflight.get(user);
  if (inflight !== undefined) return inflight;
  const run = fetchPasswd(user)
    .then((info) => {
      passwdCache.set(user, { info, checkedAt: Date.now() });
      return info;
    })
    .finally(() => { passwdInflight.delete(user); });
  passwdInflight.set(user, run);
  return run;
}

/**
 * Resolve one system account through NSS.
 * @param user - account name.
 * @param force - await a fresh read (login/spawn); otherwise a cached answer is
 *   returned and a stale one is refreshed in the background.
 * @returns the account info, or null when it does not exist.
 */
export async function lookupUser(user, force = false) {
  if (!/^[a-z_][a-z0-9_-]{0,31}$/i.test(user)) return null;
  const cached = passwdCache.get(user);
  if (cached !== undefined && !force) {
    if (Date.now() - cached.checkedAt >= PASSWD_TTL_MS) void refreshPasswd(user);
    return cached.info;
  }
  return refreshPasswd(user);
}

// ----------------------------------------------------------------- PAM ------
// Three password paths, most capable first:
//  1. native `node-linux-pam` (optionalDependency; needs libpam to build)
//  2. `su` under a PTY via `node-pty` (optionalDependency): several
//     distributions only let `su` read the password from a terminal. The child
//     runs as `nobody` so `su` prompts for the TARGET user's password instead of
//     letting root bypass the check.
//  3. legacy `su` with the password on stdin: works where `su` reads stdin
//     (e.g. Arch), kept for installs without node-pty.
let pamNative = null;
try { pamNative = (await import('node-linux-pam')).default; } catch { /* optional */ }
// The package's ESM interop yields the module object; a broken/incompatible
// build must fall through to the su path rather than throw per login.
if (pamNative !== null && typeof pamNative.pamAuthenticate !== 'function') pamNative = null;

let ptySpawn = null;
try {
  const pty = await import('node-pty');
  ptySpawn = (pty.default ?? pty).spawn;
} catch { /* optional */ }

const SU_TIMEOUT_MS = 10_000;

// PAM codes that mean "this context could not perform the check", not "the
// password is wrong". A real rejection (`PAM_AUTH_ERR`) must never fall through
// to `su`: a permissive su/PAM stack could turn it into a login.
const PAM_UNVERIFIABLE = new Set([
  1,  // PAM_OPEN_ERR
  2,  // PAM_SYMBOL_ERR
  3,  // PAM_SERVICE_ERR
  4,  // PAM_SYSTEM_ERR
  5,  // PAM_BUF_ERR
  8,  // PAM_CRED_INSUFFICIENT
  9,  // PAM_AUTHINFO_UNAVAIL
  19, // PAM_CONV_ERR
  26, // PAM_ABORT
  28, // PAM_MODULE_UNKNOWN
  -1, // the addon threw or returned no code
]);

let warnedSuFallback = false;

if (ptySpawn === null && pamNative === null) {
  console.warn('[hub] auth: neither node-linux-pam nor node-pty is available — '
    + 'password checks use the su stdin fallback, which fails where su needs a terminal');
}

/**
 * Ask the native PAM module for one verdict.
 * @returns `{ ok, code }`; `code` is the PAM return value when it failed.
 */
function nativePam(username, password) {
  return new Promise((resolve) => {
    try {
      pamNative.pamAuthenticate({ username, password }, (err, code) => {
        resolve({ ok: !err, code: Number.isInteger(code) ? code : -1 });
      });
    } catch {
      resolve({ ok: false, code: -1 });
    }
  });
}

/** Verify `username`'s password. The caller maps false to a generic failure. */
export async function pamAuthenticate(username, password) {
  // Prefer native PAM in both modes: the root hub can verify any account, and
  // the non-root proxy verifies its own service account in-process.
  if (pamNative !== null) {
    const verdict = await nativePam(username, password);
    if (verdict.ok) return true;
    if (!PAM_UNVERIFIABLE.has(verdict.code)) return false;
    // The PAM stack could not check here (e.g. unix_chkpwd restrictions for a
    // non-root caller); fall back to su.
    if (ptySpawn === null && !warnedSuFallback) {
      warnedSuFallback = true;
      console.warn('[hub] auth: native PAM could not verify; using the su stdin fallback');
    }
  }
  if (ptySpawn !== null) return suViaPty(username, password);
  return suViaStdin(username, password);
}

/**
 * Run `su` on a pseudo-terminal and feed it the password. Some distributions
 * only let `su` read from a terminal, which the stdin fallback cannot satisfy.
 */
function suViaPty(username, password) {
  return new Promise((resolve) => {
    let term;
    try {
      term = ptySpawn('su', [username, '-c', 'exit 0'], {
        name: 'xterm-256color',
        cols: 80,
        rows: 24,
        cwd: '/',
        // Root must not let `su` bypass the check: as nobody it asks for the
        // target user's password.
        ...(IS_ROOT ? { uid: 65534, gid: 65534 } : {}),
        env: { PATH: '/usr/local/bin:/usr/bin:/bin', TERM: 'xterm-256color', LANG: 'C' },
      });
    } catch {
      resolve(false);
      return;
    }
    let done = false;
    let wrote = false;
    let timer;
    let fallback;
    const finish = (ok) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      clearTimeout(fallback);
      resolve(ok);
    };
    const writePassword = () => {
      if (wrote) return;
      wrote = true;
      try { term.write(`${password}\r`); } catch { /* the exit handler settles */ }
    };
    timer = setTimeout(() => {
      try { term.kill(); } catch { /* already gone */ }
      finish(false);
    }, SU_TIMEOUT_MS);
    // `su` disables echo before printing its prompt, so writing on the first
    // output keeps the password out of the echo window. The short fallback
    // covers a `su` that refuses before prompting; the exit status decides.
    term.onData(writePassword);
    fallback = setTimeout(writePassword, 500);
    term.onExit(({ exitCode }) => finish(exitCode === 0));
  });
}

/** Legacy fallback: `su` with the password on stdin (needs a stdin-reading su). */
function suViaStdin(username, password) {
  return new Promise((resolve) => {
    const opts = { stdio: ['pipe', 'ignore', 'ignore'] };
    if (IS_ROOT) { opts.uid = 65534; opts.gid = 65534; } // nobody: non-root su prompts via PAM
    const child = spawn('su', [username, '-c', 'exit 0'], opts);
    let done = false;
    const finish = (ok) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(ok);
    };
    const timer = setTimeout(() => { child.kill('SIGKILL'); finish(false); }, SU_TIMEOUT_MS);
    child.on('error', () => finish(false));
    child.on('exit', (code) => finish(code === 0));
    // `su` may exit before reading the password (no tty, bad account state); an
    // unhandled EPIPE on stdin would otherwise take the whole process down.
    child.stdin.on('error', () => { /* the exit handler settles the attempt */ });
    try {
      child.stdin.write(`${password}\n`);
      child.stdin.end();
    } catch { /* the exit handler settles the attempt */ }
  });
}

// Unknown usernames still run one PAM check against a decoy account, so a wrong
// password takes the same time whether or not the account exists. The result is
// ignored and the login always fails. A locked system account works as a decoy.
let decoyName; // undefined = not resolved yet, null = unavailable
/** Resolve (once) the account used to equalize unknown-username timing. */
export async function decoyUser(name) {
  if (decoyName !== undefined) return decoyName;
  const candidate = name;
  decoyName = candidate && await lookupUser(candidate, true) ? candidate : null;
  if (decoyName === null) {
    console.warn(`[hub] AUTH_DECOY_USER=${JSON.stringify(candidate)} is not an existing account; `
      + 'unknown-usernames are answered faster than wrong passwords');
  }
  return decoyName;
}

// ------------------------------------------------------- audit logging ------
// One stable line per outcome, e.g.
//   2026-10-05T08:00:00.000Z [auth] login failed user=testuser ip=10.0.0.5
// The client IP is always last so an `ip=<HOST>` filter (fail2ban-style) cannot
// capture anything else. Falls back to stdout/journald when unavailable.
function createAudit(auditPath) {
  let stream = null; // WriteStream, or false once unavailable
  return function audit(line) {
    if (stream === null) {
      try {
        fs.mkdirSync(path.dirname(auditPath), { recursive: true });
        stream = fs.createWriteStream(auditPath, { flags: 'a', mode: 0o600 });
        stream.on('error', (err) => console.error('[hub] audit log write failed:', err.message));
      } catch (err) {
        console.error('[hub] audit log unavailable, falling back to console:', err.message);
        stream = false;
      }
    }
    const text = `${new Date().toISOString()} [auth] ${line}\n`;
    if (stream) stream.write(text);
    else process.stdout.write(text);
  };
}

/** One log-safe token: no whitespace, control characters, equals, or quotes. */
function logToken(value) {
  return String(value ?? '').replace(/[^\x21-\x7e]/g, '_').replace(/[="\\]/g, '_').slice(0, 64);
}

// ------------------------------------------------------------ client IP -----
// Rate-limited keys must be stable: strip zone ids / brackets / ports, unmap
// IPv4-mapped IPv6, and canonicalize IPv6 so two spellings of one address share
// a bucket.

/** Canonicalize one address; unknown input is lowercased and returned as-is. */
function normalizeIp(raw) {
  if (typeof raw !== 'string') return '?';
  let s = raw.trim();
  if (s.startsWith('[')) {
    const end = s.indexOf(']');
    if (end !== -1) s = s.slice(1, end);
  }
  const zone = s.indexOf('%');
  if (zone !== -1) s = s.slice(0, zone);
  let mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(s);
  if (mapped) s = mapped[1];
  else {
    mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(s);
    if (mapped) {
      const hi = parseInt(mapped[1], 16), lo = parseInt(mapped[2], 16);
      s = `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
    }
  }
  if (net.isIPv4(s)) return s;
  if (net.isIPv6(s)) {
    try { return new URL(`http://[${s}]/`).hostname.slice(1, -1); } catch { return s.toLowerCase(); }
  }
  const hostPort = /^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/.exec(s);
  return hostPort ? hostPort[1] : s.toLowerCase();
}

/** Expand a canonical address to its 4- or 16-byte form, or null. */
function ipToBytes(ip) {
  if (net.isIPv4(ip)) return ip.split('.').map((n) => Number(n) & 255);
  if (!net.isIPv6(ip)) return null;
  const parts = ip.split('::');
  const left = parts[0] === '' ? [] : parts[0].split(':');
  const right = parts.length > 1 && parts[1] !== '' ? parts[1].split(':') : [];
  const groups = [...left, ...Array(Math.max(0, 8 - left.length - right.length)).fill('0'), ...right];
  const bytes = [];
  for (const g of groups) { const v = parseInt(g, 16); bytes.push((v >> 8) & 255, v & 255); }
  return bytes.length === 16 ? bytes : null;
}

/** Whether `ip` falls inside an exact address or `addr/prefix` CIDR. */
function ipInCidr(ip, cidr) {
  const slash = cidr.indexOf('/');
  const base = normalizeIp(slash === -1 ? cidr : cidr.slice(0, slash));
  const bits = slash === -1 ? null : Number(cidr.slice(slash + 1));
  const ipBytes = ipToBytes(ip);
  const baseBytes = ipToBytes(base);
  if (ipBytes === null || baseBytes === null || ipBytes.length !== baseBytes.length) return false;
  if (bits === null) return ipBytes.every((b, i) => b === baseBytes[i]);
  if (!Number.isInteger(bits) || bits < 0 || bits > ipBytes.length * 8) return false;
  const whole = Math.floor(bits / 8);
  for (let i = 0; i < whole; i++) if (ipBytes[i] !== baseBytes[i]) return false;
  const rest = bits % 8;
  if (rest === 0) return true;
  const mask = (0xff << (8 - rest)) & 0xff;
  return (ipBytes[whole] & mask) === (baseBytes[whole] & mask);
}

/**
 * Resolve the client address for rate limiting and audit lines. Without a
 * configured trusted proxy the TCP peer is authoritative; with one, the
 * rightmost untrusted hop in X-Forwarded-For wins (falling back to X-Real-IP),
 * so a client-supplied header cannot move the limit to another address.
 */
function clientIp(req, peer, trustedProxies) {
  const isTrusted = (ip) => trustedProxies.some((entry) => ipInCidr(ip, entry));
  if (trustedProxies.length === 0 || !isTrusted(peer)) return peer;
  const header = req.headers['x-forwarded-for'];
  const raw = Array.isArray(header) ? header.join(',') : String(header ?? '');
  const chain = raw.split(',').map((part) => normalizeIp(part.split(';')[0])).filter((ip) => ip !== '' && ip !== '?');
  for (let i = chain.length - 1; i >= 0; i--) {
    if (!isTrusted(chain[i])) return chain[i];
  }
  if (chain.length > 0) return chain[0];
  const real = req.headers['x-real-ip'];
  if (typeof real === 'string' && real.trim() !== '') return normalizeIp(real);
  return peer;
}

// --------------------------------------------------------- login flow ------

/**
 * Build the login/logout/session handlers for one entry point.
 *
 * `verify(username, password)` resolves to `{ ok, reason }`; it owns account
 * lookup, the decoy check for unknown users, and any mode-specific policy.
 * `keyFor(user, force)` returns the HMAC key for that user's cookie, or null
 * when the user may not hold a session. At login it is called with
 * `force = true`; on every subsequent request with `force = false`.
 */
export function createLogin({ verify, keyFor, auditPath, cfg }) {
  const audit = createAudit(auditPath);

  // Sliding-window login guard: one ascending array of failure timestamps per
  // client IP. Memory stays bounded because each array keeps at most
  // authMaxFailures entries and a sweep drops IPs whose window has fully aged out.
  const LOGIN_ATTEMPTS = new Map(); // ip -> ascending failure timestamps
  const LOGIN_PENDING = new Map(); // ip -> attempts currently in flight
  const AUTH_TRACKED_MAX = 100_000;

  function pruneFailures(list, now) {
    const cutoff = now - cfg.authWindowMs;
    let drop = 0;
    while (drop < list.length && list[drop] <= cutoff) drop++;
    if (drop > 0) list.splice(0, drop);
    return list;
  }

  function pendingAttempts(ip) {
    return LOGIN_PENDING.get(ip) ?? 0;
  }

  /**
   * Seconds this IP must wait before another attempt, or 0 when it may try now.
   * In-flight attempts count toward the limit: without that, a concurrent burst
   * would all pass the check before any failure was recorded.
   */
  function loginBlockSeconds(ip) {
    const now = Date.now();
    const list = LOGIN_ATTEMPTS.get(ip);
    if (list !== undefined) {
      pruneFailures(list, now);
      if (list.length === 0) LOGIN_ATTEMPTS.delete(ip);
    }
    const failures = list?.length ?? 0;
    if (failures + pendingAttempts(ip) < cfg.authMaxFailures) return 0;
    if (failures === 0) return 1; // in-flight attempts fill the window; retry shortly
    return Math.max(1, Math.ceil((list[0] + cfg.authWindowMs - now) / 1000));
  }

  /** Reserve one slot before the async PAM call; false when the IP is full. */
  function reserveAttempt(ip) {
    if (loginBlockSeconds(ip) > 0) return false;
    LOGIN_PENDING.set(ip, pendingAttempts(ip) + 1);
    return true;
  }

  /** Release a reserved slot, recording a failed attempt when asked. */
  function releaseAttempt(ip, failed) {
    const pending = pendingAttempts(ip);
    if (pending > 0) {
      if (pending === 1) LOGIN_PENDING.delete(ip);
      else LOGIN_PENDING.set(ip, pending - 1);
    }
    if (failed) recordFailure(ip);
  }

  function recordFailure(ip) {
    const now = Date.now();
    const list = LOGIN_ATTEMPTS.get(ip) ?? [];
    pruneFailures(list, now);
    list.push(now);
    if (list.length > cfg.authMaxFailures) list.splice(0, list.length - cfg.authMaxFailures);
    LOGIN_ATTEMPTS.set(ip, list);
  }

  // Drop expired IPs so a distributed spray cannot grow the map without bound.
  setInterval(() => {
    const now = Date.now();
    for (const [ip, list] of LOGIN_ATTEMPTS) {
      pruneFailures(list, now);
      if (list.length === 0) LOGIN_ATTEMPTS.delete(ip);
    }
    while (LOGIN_ATTEMPTS.size > AUTH_TRACKED_MAX) {
      const oldest = LOGIN_ATTEMPTS.keys().next().value;
      if (oldest === undefined) break;
      LOGIN_ATTEMPTS.delete(oldest);
    }
  }, 60_000).unref();

  function sign(user, exp, iat, key) {
    return crypto.createHmac('sha256', key).update(`${user}.${exp}.${iat}`).digest('base64url');
  }

  function makeCookie(user, key, iat = Date.now()) {
    const exp = Math.min(iat + cfg.sessionTtlMs, iat + cfg.sessionMaxTtlMs);
    return { token: `${user}.${exp}.${iat}.${sign(user, exp, iat, key)}`, exp, iat };
  }

  /**
   * Extend a live session when it is near expiry. The effective threshold is
   * min(SESSION_REFRESH_THRESHOLD_MS, SESSION_TTL_MS / 2), so a refreshed cookie
   * is always far enough from expiry to avoid immediate re-triggering. Returns
   * null when no refresh is due or the absolute SESSION_MAX_TTL_MS cap is hit.
   */
  function refreshCookie(user, exp, iat, key) {
    const now = Date.now();
    const threshold = Math.min(cfg.sessionRefreshThresholdMs, Math.max(0, cfg.sessionTtlMs / 2));
    if (exp - now > threshold) return null;
    const maxExp = iat + cfg.sessionMaxTtlMs;
    const newExp = Math.min(now + cfg.sessionTtlMs, maxExp);
    if (newExp <= exp) return null; // no extension possible at the 7-day cap
    return { token: `${user}.${newExp}.${iat}.${sign(user, newExp, iat, key)}`, exp: newExp, iat };
  }

  function appendSetCookie(res, value) {
    const prev = res.getHeader('set-cookie');
    const list = prev === undefined ? [] : (Array.isArray(prev) ? prev : [prev]);
    res.setHeader('set-cookie', [...list, value]);
  }

  /**
   * Add a refreshed session cookie to `res` when due. The caller supplies the
   * sessionInfo result and gets the effective exp back (the old one when no
   * refresh happened), so /hub/api/session reports the post-refresh TTL.
   */
  function maybeRefreshSession(res, session) {
    if (session === null) return null;
    const key = keyFor(session.user, false);
    if (key === null) return null;
    const fresh = refreshCookie(session.user, session.exp, session.iat, key);
    if (fresh === null) return session.exp;
    const maxAge = Math.max(0, Math.floor((fresh.exp - Date.now()) / 1000));
    appendSetCookie(res,
      `${cfg.cookieName}=${fresh.token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`);
    return fresh.exp;
  }

  function parseCookie(req) {
    const raw = req.headers.cookie ?? '';
    for (const part of raw.split(';')) {
      const [k, ...rest] = part.trim().split('=');
      if (k === cfg.cookieName) return rest.join('=');
    }
    return null;
  }

  /** The authenticated session (user, signed expiry, issued-at), or null. */
  function sessionInfo(req) {
    const val = parseCookie(req);
    if (!val) return null;
    const m = /^(.+)\.(\d+)\.(\d+)\.(.+)$/.exec(val);
    if (!m) return null;
    const [, user, expStr, iatStr, sig] = m;
    const exp = Number(expStr);
    const iat = Number(iatStr);
    if (!Number.isFinite(exp) || !Number.isFinite(iat) || exp < Date.now()) return null;
    const key = keyFor(user, false);
    if (key === null) return null;
    const expect = sign(user, exp, iat, key);
    const a = Buffer.from(sig), b = Buffer.from(expect);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    return { user, exp, iat };
  }

  /** The authenticated username from the session cookie, or null. */
  function sessionUser(req) {
    const info = sessionInfo(req);
    return info === null ? null : info.user;
  }

  function sendBlocked(res, locale, headers, ip, wait) {
    audit(`login blocked ip=${logToken(ip)} retry_after=${wait}s`);
    const amount = t(locale, wait < 60 ? 'wait.seconds' : 'wait.minutes',
      { n: wait < 60 ? wait : Math.ceil(wait / 60) });
    sendHtml(res, 429, loginPage(locale, t(locale, 'error.tooManyAttempts', { wait: amount })),
      { ...headers, 'retry-after': String(wait) });
  }

  async function handleLogin(req, res) {
    const locale = localeFromRequest(req);
    const headers = pageHeaders(req, locale);
    const peer = normalizeIp(req.socket.remoteAddress);
    const ip = clientIp(req, peer, cfg.trustedProxies);
    const via = ip === peer ? '' : ` proxy=${logToken(peer)}`;
    const wait = loginBlockSeconds(ip);
    if (wait > 0) {
      sendBlocked(res, locale, headers, ip, wait);
      return;
    }
    const { username, password } = urlencoded(await readBody(req));
    if (!username || !password) {
      audit(`login rejected reason=missing-credentials ip=${logToken(ip)}${via}`);
      sendHtml(res, 401, loginPage(locale, t(locale, 'error.missingCredentials')), headers);
      return;
    }
    // Reserve before awaiting verification so a concurrent burst cannot exceed
    // the window.
    if (!reserveAttempt(ip)) {
      sendBlocked(res, locale, headers, ip, loginBlockSeconds(ip) || 1);
      return;
    }
    let result;
    try {
      result = await verify(username, password);
    } catch (err) {
      console.error('[hub] login verification failed:', err.message);
      result = { ok: false, reason: 'auth-error' };
    } finally {
      releaseAttempt(ip, result?.ok !== true);
    }
    if (result?.ok !== true) {
      const blocked = loginBlockSeconds(ip);
      audit(`login failed user=${logToken(username)} reason=${result?.reason ?? 'auth-error'} ip=${logToken(ip)}${via}`
        + (blocked > 0 ? ` blocked_for=${blocked}s` : ''));
      sendHtml(res, 401, loginPage(locale, t(locale, 'error.badCredentials')), headers);
      return;
    }
    const key = keyFor(username, true);
    if (key === null) {
      recordFailure(ip);
      const blocked = loginBlockSeconds(ip);
      audit(`login failed user=${logToken(username)} reason=key-unavailable ip=${logToken(ip)}${via}`
        + (blocked > 0 ? ` blocked_for=${blocked}s` : ''));
      sendHtml(res, 401, loginPage(locale, t(locale, 'error.badCredentials')), headers);
      return;
    }
    audit(`login ok user=${logToken(username)} ip=${logToken(ip)}${via}`);
    const { token, exp } = makeCookie(username, key);
    res.writeHead(303, {
      'set-cookie': `${cfg.cookieName}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.max(0, Math.floor((exp - Date.now()) / 1000))}`,
      location: '/',
    });
    res.end();
  }

  function handleLogout(req, res) {
    res.writeHead(303, {
      'set-cookie': `${cfg.cookieName}=; Path=/; HttpOnly; Max-Age=0`,
      location: '/hub/login',
    });
    res.end();
  }

  return { handleLogin, handleLogout, sessionInfo, sessionUser, maybeRefreshSession };
}
