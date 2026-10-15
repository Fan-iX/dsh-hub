// Authentication and session: hub session cookies, client-IP resolution for the
// login guard, the sliding-window failure counter, the audit log, PAM
// verification, and the login/logout handlers.
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { spawn } from 'node:child_process';

import { AUTH_LOG_FILE, CFG, IS_ROOT, SECRET_PATH } from './config.mjs';
import { readBody, sendHtml, urlencoded } from './http.mjs';
import { loginPage } from './pages.mjs';
import { lookupUser } from './users.mjs';

// ----------------------------------------------------------- cookie secret --

let SECRET;
{
  try {
    SECRET = fs.readFileSync(SECRET_PATH);
  } catch {
    SECRET = crypto.randomBytes(32);
    fs.writeFileSync(SECRET_PATH, SECRET, { mode: 0o600 });
  }
}

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
const AUTH_TRACKED_MAX = 100_000;

function pruneFailures(list, now) {
  const cutoff = now - CFG.authWindowMs;
  let drop = 0;
  while (drop < list.length && list[drop] <= cutoff) drop++;
  if (drop > 0) list.splice(0, drop);
  return list;
}

/** Seconds this IP must wait before another attempt, or 0 when it may try now. */
function loginBlockSeconds(ip) {
  const now = Date.now();
  const list = LOGIN_ATTEMPTS.get(ip);
  if (list === undefined) return 0;
  pruneFailures(list, now);
  if (list.length === 0) { LOGIN_ATTEMPTS.delete(ip); return 0; }
  if (list.length < CFG.authMaxFailures) return 0;
  return Math.max(1, Math.ceil((list[0] + CFG.authWindowMs - now) / 1000));
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
    child.stdin.write(`${password}\n`);
    child.stdin.end();
  });
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

export async function handleLogin(req, res) {
  const peer = normalizeIp(req.socket.remoteAddress);
  const ip = clientIp(req, peer);
  const via = ip === peer ? '' : ` proxy=${logToken(peer)}`;
  const wait = loginBlockSeconds(ip);
  if (wait > 0) {
    audit(`login blocked ip=${logToken(ip)} retry_after=${wait}s`);
    const text = wait < 60 ? `${wait} 秒` : `${Math.ceil(wait / 60)} 分钟`;
    sendHtml(res, 429, loginPage(`尝试过多,请 ${text}后再试`), { 'retry-after': String(wait) });
    return;
  }
  const { username, password } = urlencoded(await readBody(req));
  if (!username || !password) {
    audit(`login rejected reason=missing-credentials ip=${logToken(ip)}${via}`);
    sendHtml(res, 401, loginPage('请输入用户名和密码'));
    return;
  }
  const info = lookupUser(username);
  let ok = false;
  let reason = 'auth-failed';
  if (!info) reason = 'unknown-user';
  else if (!await pamAuthenticate(username, password)) reason = 'auth-failed';
  else if (CFG.allowUsers.length && !CFG.allowUsers.includes(username)) reason = 'not-allowed';
  else ok = true;
  if (!ok) {
    recordFailure(ip);
    const blocked = loginBlockSeconds(ip);
    audit(`login failed user=${logToken(username)} reason=${reason} ip=${logToken(ip)}${via}`
      + (blocked > 0 ? ` blocked_for=${blocked}s` : ''));
    sendHtml(res, 401, loginPage('用户名或密码错误'));
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
