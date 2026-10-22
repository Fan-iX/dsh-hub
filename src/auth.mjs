// Authentication and session: hub session cookies, client-IP resolution for the
// login guard, the sliding-window failure counter, the audit log, PAM
// verification, and the login/logout handlers.
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { spawn } from 'node:child_process';

import { AUTH_LOG_FILE, CFG, IS_ROOT, RUNTIME_DIR, SECRET_PATH } from './config.mjs';
import { readBody, sendHtml, urlencoded } from './http.mjs';
import { localeFromRequest, t } from './i18n.mjs';
import { loginPage } from './pages.mjs';
import { lookupUser } from './users.mjs';

// ----------------------------------------------------------- cookie secret --

const SECRET_BYTES = 32;

/** The secret must stay owner-only: any local reader can forge every session. */
function secureSecretFile() {
  try {
    fs.chmodSync(SECRET_PATH, 0o600);
  } catch (err) {
    console.warn(`[hub] cannot tighten ${SECRET_PATH} permissions:`, err.message);
  }
}

/**
 * Load the HMAC secret, or create one. A truncated or empty file is never used:
 * its HMAC is computable by anyone, which would let a cookie be forged without
 * a password. A too-short file is replaced.
 */
function loadOrCreateSecret() {
  let stat = null;
  try {
    stat = fs.lstatSync(SECRET_PATH);
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }
  // A symlink (or any non-file) could make the hub read/chmod/overwrite a file
  // chosen by a local user; refuse rather than follow it.
  if (stat !== null && !stat.isFile()) {
    console.error(`[hub] FATAL: ${SECRET_PATH} is not a regular file; refusing to use it`);
    process.exit(1);
  }
  let existing = null;
  if (stat !== null) {
    existing = fs.readFileSync(SECRET_PATH);
    const uid = process.getuid?.();
    if (uid !== undefined && stat.uid !== uid) {
      console.warn(`[hub] ${SECRET_PATH} is owned by uid ${stat.uid}, not the hub user`);
    }
  }
  if (existing !== null && existing.length >= SECRET_BYTES) {
    secureSecretFile();
    return existing;
  }
  if (existing !== null) {
    console.warn(`[hub] ${SECRET_PATH} is too short (${existing.length} bytes); regenerating it`);
  }
  const secret = crypto.randomBytes(SECRET_BYTES);
  try {
    if (existing === null) {
      fs.writeFileSync(SECRET_PATH, secret, { mode: 0o600, flag: 'wx' });
    } else {
      fs.writeFileSync(SECRET_PATH, secret, { mode: 0o600 });
    }
    secureSecretFile();
    return secret;
  } catch (err) {
    if (err.code === 'EEXIST') {
      // Lost a first-boot race: whatever the other process wrote is authoritative.
      // Re-check with lstat so a symlink planted in the race is never followed.
      if (!fs.lstatSync(SECRET_PATH).isFile()) {
        console.error(`[hub] FATAL: ${SECRET_PATH} is not a regular file; refusing to use it`);
        process.exit(1);
      }
      const raced = fs.readFileSync(SECRET_PATH);
      if (raced.length >= SECRET_BYTES) { secureSecretFile(); return raced; }
      console.warn(`[hub] ${SECRET_PATH} is still too short; using an in-memory secret`);
      return secret;
    }
    console.error(`[hub] cannot persist the cookie secret: ${err.message}; using an in-memory secret`);
    return secret;
  }
}

const SECRET = loadOrCreateSecret();

if (SECRET.length < SECRET_BYTES) {
  console.error(`[hub] FATAL: cookie secret is shorter than ${SECRET_BYTES} bytes`);
  process.exit(1);
}

try {
  if (fs.statSync(RUNTIME_DIR).mode & 0o022) {
    console.warn(`[hub] WARNING: ${RUNTIME_DIR} is group/other-writable; another local user could replace ${SECRET_PATH}`);
  }
} catch { /* the runtime directory is created/validated elsewhere */ }

function sign(user, exp) {
  return crypto.createHmac('sha256', SECRET).update(`${user}.${exp}`).digest('base64url');
}

function makeCookie(user) {
  const exp = Date.now() + CFG.sessionTtlMs;
  return `${user}.${exp}.${sign(user, exp)}`;
}

function parseCookie(req) {
  const raw = req.headers.cookie ?? '';
  for (const part of raw.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (k === CFG.cookieName) return rest.join('=');
  }
  return null;
}

export function sessionUser(req) {
  const val = parseCookie(req);
  if (!val) return null;
  const m = /^(.+)\.(\d+)\.(.+)$/.exec(val);
  if (!m) return null;
  const [, user, expStr, sig] = m;
  const exp = Number(expStr);
  if (!Number.isFinite(exp) || exp < Date.now()) return null;
  const expect = sign(user, exp);
  const a = Buffer.from(sig), b = Buffer.from(expect);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  return user;
}

// ----------------------------------------------------------------- PAM ------

// Sliding-window login guard: one ascending array of failure timestamps per
// client IP. Memory stays bounded because each array keeps at most
// AUTH_MAX_FAILURES entries (more is irrelevant once blocked) and a sweep drops
// IPs whose window has fully aged out.
const LOGIN_ATTEMPTS = new Map(); // ip -> ascending failure timestamps
const LOGIN_PENDING = new Map(); // ip -> attempts currently in flight
const AUTH_TRACKED_MAX = 100_000;

function pruneFailures(list, now) {
  const cutoff = now - CFG.authWindowMs;
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
  if (failures + pendingAttempts(ip) < CFG.authMaxFailures) return 0;
  if (failures === 0) return 1; // in-flight attempts fill the window; retry shortly
  return Math.max(1, Math.ceil((list[0] + CFG.authWindowMs - now) / 1000));
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
  if (list.length > CFG.authMaxFailures) list.splice(0, list.length - CFG.authMaxFailures);
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

// ------------------------------------------------------------- audit log ----
// One stable line per outcome, e.g.
//   2026-10-05T08:00:00.000Z [auth] login failed user=testuser ip=10.0.0.5
// The client IP is always last so an `ip=<HOST>` filter (fail2ban-style) cannot
// capture anything else. Falls back to stdout/journald when the file is
// unavailable.
let authLog = null; // WriteStream, or false once unavailable
function audit(line) {
  if (authLog === null) {
    try {
      fs.mkdirSync(path.dirname(AUTH_LOG_FILE), { recursive: true });
      authLog = fs.createWriteStream(AUTH_LOG_FILE, { flags: 'a', mode: 0o600 });
      authLog.on('error', (err) => console.error('[hub] audit log write failed:', err.message));
    } catch (err) {
      console.error('[hub] audit log unavailable, falling back to console:', err.message);
      authLog = false;
    }
  }
  const text = `${new Date().toISOString()} [auth] ${line}\n`;
  if (authLog) authLog.write(text);
  else process.stdout.write(text);
}

/** One log-safe token: no whitespace, control characters, equals, or quotes. */
function logToken(value) {
  return String(value ?? '').replace(/[^\x21-\x7e]/g, '_').replace(/[="\\]/g, '_').slice(0, 64);
}

// Two PAM paths:
//  1. native `node-linux-pam` (optionalDependency; needs libpam to build)
//  2. `su` fallback: spawn `su <user> -c 'exit 0'` as an unprivileged uid —
//     su then verifies the TARGET user's password through PAM. Zero native
//     deps; failed attempts land in the normal auth log.
let pamNative = null;
try { pamNative = (await import('node-linux-pam')).default; } catch { /* optional */ }

function pamAuthenticate(username, password) {
  if (pamNative) {
    return new Promise((resolve) => {
      pamNative.pamAuthenticate({ username, password }, (err) => resolve(!err));
    });
  }
  return new Promise((resolve) => {
    const opts = { stdio: ['pipe', 'ignore', 'ignore'] };
    if (IS_ROOT) opts.uid = 65534; // nobody: non-root su prompts via PAM
    const child = spawn('su', [username, '-c', 'exit 0'], opts);
    let done = false;
    const finish = (ok) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(ok);
    };
    const timer = setTimeout(() => { child.kill('SIGKILL'); finish(false); }, 10_000);
    child.on('error', () => finish(false));
    child.on('exit', (code) => finish(code === 0));
    // `su` may exit before reading the password (no tty, bad account state); an
    // unhandled EPIPE on stdin would otherwise take the whole hub down.
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
function decoyUser() {
  if (decoyName !== undefined) return decoyName;
  const candidate = CFG.authDecoyUser;
  decoyName = candidate && lookupUser(candidate) ? candidate : null;
  if (decoyName === null) {
    console.warn(`[hub] AUTH_DECOY_USER=${JSON.stringify(candidate)} is not an existing account; `
      + 'unknown-usernames are answered faster than wrong passwords');
  }
  return decoyName;
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

function isTrustedProxy(ip) {
  return CFG.trustedProxies.some((entry) => ipInCidr(ip, entry));
}

/**
 * Resolve the client address for rate limiting and audit lines. Without a
 * configured trusted proxy the TCP peer is authoritative; with one, the
 * rightmost untrusted hop in X-Forwarded-For wins (falling back to X-Real-IP),
 * so a client-supplied header cannot move the limit to another address.
 */
function clientIp(req, peer = normalizeIp(req.socket.remoteAddress)) {
  if (CFG.trustedProxies.length === 0 || !isTrustedProxy(peer)) return peer;
  const header = req.headers['x-forwarded-for'];
  const raw = Array.isArray(header) ? header.join(',') : String(header ?? '');
  const chain = raw.split(',').map((part) => normalizeIp(part.split(';')[0])).filter((ip) => ip !== '' && ip !== '?');
  for (let i = chain.length - 1; i >= 0; i--) {
    if (!isTrustedProxy(chain[i])) return chain[i];
  }
  if (chain.length > 0) return chain[0];
  const real = req.headers['x-real-ip'];
  if (typeof real === 'string' && real.trim() !== '') return normalizeIp(real);
  return peer;
}

function sendBlocked(res, locale, pageHeaders, ip, wait) {
  audit(`login blocked ip=${logToken(ip)} retry_after=${wait}s`);
  const amount = t(locale, wait < 60 ? 'wait.seconds' : 'wait.minutes',
    { n: wait < 60 ? wait : Math.ceil(wait / 60) });
  sendHtml(res, 429, loginPage(locale, t(locale, 'error.tooManyAttempts', { wait: amount })),
    { ...pageHeaders, 'retry-after': String(wait) });
}

export async function handleLogin(req, res) {
  const locale = localeFromRequest(req);
  const pageHeaders = { 'content-language': locale, vary: 'Accept-Language' };
  const peer = normalizeIp(req.socket.remoteAddress);
  const ip = clientIp(req, peer);
  const via = ip === peer ? '' : ` proxy=${logToken(peer)}`;
  const wait = loginBlockSeconds(ip);
  if (wait > 0) {
    sendBlocked(res, locale, pageHeaders, ip, wait);
    return;
  }
  const { username, password } = urlencoded(await readBody(req));
  if (!username || !password) {
    audit(`login rejected reason=missing-credentials ip=${logToken(ip)}${via}`);
    sendHtml(res, 401, loginPage(locale, t(locale, 'error.missingCredentials')), pageHeaders);
    return;
  }
  const info = lookupUser(username);
  if (!info) {
    // Count the probe against the window even though the account does not exist.
    if (!reserveAttempt(ip)) {
      sendBlocked(res, locale, pageHeaders, ip, loginBlockSeconds(ip) || 1);
      return;
    }
    try {
      // Equalize the response time with a wrong password: run the same PAM path
      // against a decoy account. Its outcome is ignored; the login always fails.
      const decoy = decoyUser();
      if (decoy !== null) await pamAuthenticate(decoy, password);
    } catch { /* a decoy failure must not change the login outcome */ }
    finally {
      releaseAttempt(ip, true);
    }
    const blocked = loginBlockSeconds(ip);
    audit(`login failed user=${logToken(username)} reason=unknown-user ip=${logToken(ip)}${via}`
      + (blocked > 0 ? ` blocked_for=${blocked}s` : ''));
    sendHtml(res, 401, loginPage(locale, t(locale, 'error.badCredentials')), pageHeaders);
    return;
  }
  // Reserve before awaiting PAM so a concurrent burst cannot exceed the window.
  if (!reserveAttempt(ip)) {
    sendBlocked(res, locale, pageHeaders, ip, loginBlockSeconds(ip) || 1);
    return;
  }
  let pamOk = false;
  try {
    pamOk = await pamAuthenticate(username, password);
  } finally {
    releaseAttempt(ip, !pamOk);
  }
  let reason = '';
  if (!pamOk) reason = 'auth-failed';
  else if (CFG.allowUsers.length && !CFG.allowUsers.includes(username)) {
    recordFailure(ip);
    reason = 'not-allowed';
  }
  if (reason !== '') {
    const blocked = loginBlockSeconds(ip);
    audit(`login failed user=${logToken(username)} reason=${reason} ip=${logToken(ip)}${via}`
      + (blocked > 0 ? ` blocked_for=${blocked}s` : ''));
    sendHtml(res, 401, loginPage(locale, t(locale, 'error.badCredentials')), pageHeaders);
    return;
  }
  audit(`login ok user=${logToken(username)} ip=${logToken(ip)}${via}`);
  const token = makeCookie(username);
  res.writeHead(303, {
    'set-cookie': `${CFG.cookieName}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(CFG.sessionTtlMs / 1000)}`,
    location: '/',
  });
  res.end();
}

export function handleLogout(req, res) {
  res.writeHead(303, {
    'set-cookie': `${CFG.cookieName}=; Path=/; HttpOnly; Max-Age=0`,
    location: '/hub/login',
  });
  res.end();
}
