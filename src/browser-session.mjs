// Bridge between the hub PAM session and dsh's own browser-session cookie:
// capture the launch token dsh prints at startup, exchange it for the dsh-auth
// cookie on behalf of an authenticated browser, and mint an internal cookie for
// the hub's own loopback /api calls.
import crypto from 'node:crypto';
import http from 'node:http';

import { TRUST_MODE } from './config.mjs';

// --------------------------------------------- dsh browser-session bridge ----
// dsh gates its index (and every /api channel) on its own `dsh-auth-*` cookie,
// which is minted ONLY by a request carrying the per-process `?token=` value
// printed once at startup. The hub's PAM cookie means nothing to dsh, so an
// authenticated hub session used to land on `401 dsh web authentication
// required; reopen the URL printed by dsh web.`
//
// The hub captures that token from the backend's stdout and performs the
// exchange itself: one loopback `GET /?token=<token>` using the authority the
// proxied browser request will present, then it relays dsh's Set-Cookie to the
// browser and redirects to the clean index. The token never reaches the browser,
// the URL bar stays clean, and dsh is not modified — the hub only automates the
// step dsh already documents.

/** dsh's deterministic browser-session cookie name for one request authority. */
function dshCookieName(authority) {
  return 'dsh-auth-' + crypto.createHash('sha256').update(authority).digest('base64url');
}

/** The authority dsh sees on a proxied browser request (it binds its cookie to it). */
function backendAuthority(be, req) {
  return TRUST_MODE === 'origin-rewrite'
    ? `127.0.0.1:${be.port}`
    : String(req.headers.host ?? `127.0.0.1:${be.port}`);
}

function hasRequestCookie(req, name) {
  const prefix = `${name}=`;
  for (const part of String(req.headers.cookie ?? '').split(';')) {
    if (part.trim().startsWith(prefix)) return true;
  }
  return false;
}

export function isIndexPath(pathname) {
  return pathname === '/' || pathname === '/index.html';
}

/** Record a launch token parsed from a backend's stdout and wake any waiters. */
export function setLaunchToken(be, token) {
  be.launchToken = token;
  for (const resolve of be.launchTokenWaiters.splice(0)) resolve(true);
}

/** Resolve true once the backend has printed its launch token, false after timeoutMs. */
function waitLaunchToken(be, timeoutMs) {
  if (be.launchToken) return Promise.resolve(true);
  if (be.launchTokenUnavailable) return Promise.resolve(false);
  return new Promise((resolve) => {
    const waiter = (ok) => { clearTimeout(timer); resolve(ok); };
    const timer = setTimeout(() => {
      be.launchTokenUnavailable = true;
      be.launchTokenWaiters = be.launchTokenWaiters.filter((w) => w !== waiter);
      console.warn(`[hub] ${be.user}: dsh did not print its "dsh web: <url>?token=..." line; `
        + 'index requests cannot be bridged and dsh will refuse them');
      resolve(false);
    }, timeoutMs);
    be.launchTokenWaiters.push(waiter);
  });
}

/**
 * Spend the backend's launch token and return the Set-Cookie value dsh minted
 * for `authority`, or null when no cookie came back.
 */
function mintDshSessionCookie(be, authority) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (value) => { if (!settled) { settled = true; resolve(value); } };
    const req = http.request({
      host: '127.0.0.1',
      port: be.port,
      method: 'GET',
      path: `/?token=${encodeURIComponent(be.launchToken)}`,
      setHost: false,
      headers: { host: authority, connection: 'close' },
    }, (res) => {
      res.resume(); // only the Set-Cookie header matters
      res.on('end', () => done(res.headers['set-cookie'] ?? null));
      res.on('error', () => done(null));
    });
    req.on('error', () => done(null));
    req.setTimeout(10_000, () => { req.destroy(); done(null); });
    req.end();
  });
}

/**
 * Ensure the browser holds dsh's own session cookie, minting and relaying it
 * through the backend's launch token when absent (or when `force` re-mints after
 * dsh rejected a stale one).
 * @returns true when this wrote the 303 carrying dsh's Set-Cookie.
 */
export async function bridgeDshBrowserSession(req, res, be, { force = false } = {}) {
  const authority = backendAuthority(be, req);
  if (!force && hasRequestCookie(req, dshCookieName(authority))) return false;
  if (!await waitLaunchToken(be, 5000)) return false;
  const setCookie = await mintDshSessionCookie(be, authority);
  if (!setCookie) return false;
  res.writeHead(303, {
    'cache-control': 'no-store',
    'referrer-policy': 'no-referrer',
    location: '/',
    'set-cookie': setCookie,
  });
  res.end();
  return true;
}

/**
 * Cookie header authenticating hub-internal /api calls. dsh's browser fence
 * applies to loopback requests too, so prewarm/revalidate must present the same
 * `dsh-auth-*` cookie a browser would; the hub mints its own from the backend's
 * launch token and reuses it for that backend's lifetime.
 * @returns the `name=value` pair, or null when no token/cookie is available.
 */
export async function hubDshCookieHeader(be) {
  if (be.internalCookie) return be.internalCookie;
  if (!await waitLaunchToken(be, 5000)) return null;
  const setCookie = await mintDshSessionCookie(be, `127.0.0.1:${be.port}`);
  if (!setCookie) return null;
  const raw = Array.isArray(setCookie) ? setCookie[0] : setCookie;
  if (typeof raw !== 'string' || raw === '') return null;
  be.internalCookie = raw.split(';')[0];
  return be.internalCookie;
}
