// Serve-stale cache for the /api/session/list RPC, which can take tens of
// seconds on a cold store. See the section comment below for the full contract.
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';

import { CACHE_DIR } from './config.mjs';
import { hubDshCookieHeader } from '../backend/dsh-proxy.mjs';
import { sanitizeForwardHeaders } from '../backend/web.mjs';

// ------------------------------------------- /api/session/list response cache --
// dsh's session/list recomputes projections for every session (zstd-decode of
// large logs + projection apply); on this deployment it routinely takes
// 40-66s — far past the web client's 30s unary timeout, so the sidebar renders
// no history whenever the cache is cold. This cache makes the sidebar always
// instant: once a 200 response exists for a key it is served forever
// (serve-stale), with one throttled background revalidation refreshing it.
// A cached hit never spawns the backend, so idle culling keeps working.
// Revalidation failures keep the stale entry and back off, so a dead backend
// never empties the sidebar. Only 200 responses are cached; keys are per
// user + request-body hash so different payloads never mix.
//
// The wire endpoint is `session/list` (slash, not the old `session.list`) and
// its args travel as `payload.args._request`; a cached server-response is
// republished under the caller's rpcId because the client rejects a mismatched
// echo. Background refresh presents the same dsh browser cookie the hub mints.
export const SESSION_LIST_PATH = '/api/session/list';
const RPC_CACHE_REVALIDATE_MS = 60_000;   // min gap between background refreshes (12MB responses; keep the hub event loop free)
const RPC_CACHE_FAIL_BACKOFF_MS = 30_000; // pause after a failed refresh
const SESSION_LIST_TIMEOUT_MS = 120_000;  // a cold store can take 40-66s; never let a forward hang forever
export const rpcCache = new Map(); // key -> { status, headers, body, nextRevalidateAt, inflight }
const RPC_CACHE_MAX = 500;
const prewarmInflight = new Set();
// Cache survives hub restarts: entries persist under <cwd>/cache/session-list-<hash>.json.
const CACHE_PERSIST_GAP_MS = 300_000;     // throttle disk writes per key (16MB base64 files; async, off the hot path)
const STANDARD_SESSION_LIST_BODY = Buffer.from(JSON.stringify({
  type: 'client-request', rpcId: 'hub-prewarm', method: 'session/list',
  payload: { args: { _request: {} } },
}));

export function sessionListCacheKey(user, body) {
  // Hash only the payload (not rpcId), so hub prewarm and browser requests share a key.
  let payload = body;
  try {
    const parsed = JSON.parse(body.toString('utf8'));
    if (parsed !== null && typeof parsed === 'object' && 'payload' in parsed) {
      payload = Buffer.from(JSON.stringify(parsed.payload));
    }
  } catch {
    /* keep full-body hash */
  }
  const hash = crypto.createHash('sha256').update(payload).digest('hex').slice(0, 16);
  return `${user}:session/list:${hash}`;
}

function cacheFilePathFor(key) {
  return path.join(CACHE_DIR, `${crypto.createHash('sha256').update(key).digest('hex')}.json`);
}

function persistCacheEntry(key, entry) {
  const now = Date.now();
  if (entry.lastPersistAt !== undefined && now - entry.lastPersistAt < CACHE_PERSIST_GAP_MS) return;
  // Async write: a 16MB base64 payload must never block the event loop — the
  // hub proxies the browser's WebSocket event streams, and a sync disk write
  // here stalls them long enough to break the app's 3s readiness handshake.
  entry.lastPersistAt = now;
  fs.promises.mkdir(CACHE_DIR, { recursive: true })
    .then(() => fs.promises.writeFile(cacheFilePathFor(key), JSON.stringify({
      key,
      status: entry.status,
      contentType: entry.headers['content-type'] ?? 'application/json',
      bodyB64: entry.body.toString('base64'),
      nextRevalidateAt: entry.nextRevalidateAt,
    })))
    .catch((err) => console.error('[hub] session.list cache persist failed:', err.message));
}

export function loadPersistedCache() {
  try {
    const files = fs.readdirSync(CACHE_DIR).filter((f) => f.endsWith('.json'));
    files.sort((a, b) => {
      const sa = fs.statSync(path.join(CACHE_DIR, a)).mtimeMs;
      const sb = fs.statSync(path.join(CACHE_DIR, b)).mtimeMs;
      return sa - sb;
    });
    const keep = files.slice(-RPC_CACHE_MAX);
    for (const file of files) {
      if (!keep.includes(file)) {
        try { fs.unlinkSync(path.join(CACHE_DIR, file)); } catch { /* best-effort */ }
      }
    }
    for (const file of keep) {
      try {
        const raw = JSON.parse(fs.readFileSync(path.join(CACHE_DIR, file), 'utf8'));
        if (typeof raw.key !== 'string' || typeof raw.bodyB64 !== 'string' || raw.status !== 200) continue;
        rpcCache.set(raw.key, {
          status: raw.status,
          headers: { 'content-type': raw.contentType },
          body: Buffer.from(raw.bodyB64, 'base64'),
          nextRevalidateAt: raw.nextRevalidateAt ?? 0, // past → revalidate on first hit
          inflight: false,
        });
      } catch (err) {
        console.error('[hub] session.list cache load failed for', file, err.message);
      }
    }
  } catch (err) {
    if (err.code !== 'ENOENT') console.error('[hub] session.list cache dir read failed:', err.message);
  }
  if (rpcCache.size > 0) console.log(`[hub] loaded ${rpcCache.size} persisted session.list cache entries`);
}

export function forwardSessionList(be, headers, body, signal) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let timer;
    const cleanup = () => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
    };
    const done = (fn, value) => {
      if (settled) return;
      settled = true;
      cleanup();
      fn(value);
    };
    const onAbort = () => { req.destroy(new Error('session.list aborted')); };
    const req = http.request({
      host: '127.0.0.1',
      port: be.port,
      method: 'POST',
      path: SESSION_LIST_PATH,
      headers: { ...sanitizeForwardHeaders(headers, be.port), 'content-length': body.length, connection: 'close' },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => done(resolve, { status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      res.on('error', (err) => done(reject, err));
    });
    req.on('error', (err) => done(reject, err));
    timer = setTimeout(() => { req.destroy(new Error('session.list timed out')); }, SESSION_LIST_TIMEOUT_MS);
    if (signal !== undefined) {
      if (signal.aborted) { onAbort(); return; }
      signal.addEventListener('abort', onAbort, { once: true });
    }
    req.end(body);
  });
}

/** The rpcId a client-request envelope carries, when the body is one. */
export function requestRpcId(body) {
  try {
    const parsed = JSON.parse(body.toString('utf8'));
    return typeof parsed?.rpcId === 'string' ? parsed.rpcId : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Republish a cached server-response under the caller's rpcId (the client
 * rejects a mismatched echo). This runs on every cache hit with bodies up to
 * ~12 MB, so splice the first top-level `"rpcId"` value in the buffer instead of
 * JSON.parse + JSON.stringify over the whole payload, which blocks the event
 * loop long enough to stall the WebSocket event streams.
 */
function withRpcId(body, rpcId) {
  if (rpcId === undefined) return body;
  const key = body.indexOf('"rpcId"');
  if (key === -1) return body;
  const colon = body.indexOf(':', key + 7);
  if (colon === -1) return body;
  let start = colon + 1;
  while (start < body.length && (body[start] === 0x20 || body[start] === 0x09
    || body[start] === 0x0a || body[start] === 0x0d)) start++;
  if (body[start] !== 0x22) return body;
  let end = start + 1;
  for (; end < body.length; end++) {
    if (body[end] === 0x5c) { end++; continue; } // skip the escaped byte
    if (body[end] === 0x22) break;
  }
  if (end >= body.length) return body;
  return Buffer.concat([
    body.subarray(0, start),
    Buffer.from(JSON.stringify(rpcId)),
    body.subarray(end + 1),
  ]);
}

export function serveCachedSessionList(res, entry, rpcId) {
  if (res.destroyed || res.writableEnded) return;
  const body = withRpcId(entry.body, rpcId);
  try {
    res.writeHead(entry.status, {
      'content-type': entry.headers['content-type'] ?? 'application/json',
      'content-length': body.length,
    });
    res.end(body);
  } catch {
    /* client already gone — nothing to serve */
  }
}

/** A cacheable session.list payload: non-empty 200 whose envelope parses and carries an items array. */
export function isCacheableSessionList(captured) {
  if (captured.status !== 200 || captured.body.length === 0) return false;
  try {
    const parsed = JSON.parse(captured.body.toString('utf8'));
    return parsed?.result?.ok === true && Array.isArray(parsed.result.value?.items);
  } catch {
    return false;
  }
}

export async function revalidateSessionList(user, be, body, key) {
  const now = Date.now();
  try {
    const cookie = await hubDshCookieHeader(be);
    const headers = { accept: 'application/json', 'content-type': 'application/json' };
    if (cookie) headers.cookie = cookie;
    const captured = await forwardSessionList(be, headers, body);
    if (captured.status === 401) be.internalCookie = null; // rotated secret: re-mint on the next attempt
    if (isCacheableSessionList(captured)) {
      const entry = { ...captured, nextRevalidateAt: now + RPC_CACHE_REVALIDATE_MS, inflight: false };
      rpcCache.set(key, entry);
      persistCacheEntry(key, entry);
    } else {
      // Half-started backends answer 200 with an empty/partial body; never
      // let that clobber a good snapshot — keep the old entry and back off.
      const entry = rpcCache.get(key);
      if (entry) entry.nextRevalidateAt = now + RPC_CACHE_FAIL_BACKOFF_MS;
    }
  } catch (err) {
    console.error(`[hub] session.list revalidate failed for ${user}:`, err.message);
    // Keep serving the stale snapshot; back off so a dead backend is not hammered.
    const entry = rpcCache.get(key);
    if (entry) entry.nextRevalidateAt = now + RPC_CACHE_FAIL_BACKOFF_MS;
  } finally {
    const entry = rpcCache.get(key);
    if (entry) entry.inflight = false;
  }
}

/** Warm the session-list cache right after a backend spawn, without a browser request. */
export function prewarmSessionList(user, be) {
  const key = sessionListCacheKey(user, STANDARD_SESSION_LIST_BODY);
  if (rpcCache.has(key) || prewarmInflight.has(key)) return;
  prewarmInflight.add(key);
  revalidateSessionList(user, be, STANDARD_SESSION_LIST_BODY, key)
    .catch((err) => console.error(`[hub] session.list prewarm failed for ${user}:`, err.message))
    .finally(() => prewarmInflight.delete(key));
}

/** Release a cache entry that could not be refreshed (no live backend). */
export function deferSessionList(entry) {
  entry.inflight = false;
  entry.nextRevalidateAt = Date.now() + RPC_CACHE_FAIL_BACKOFF_MS;
}

/** Store one freshly captured 200 snapshot, evicting the oldest key at the cap. */
export function storeSessionList(key, captured) {
  if (rpcCache.size >= RPC_CACHE_MAX) {
    const oldest = rpcCache.keys().next().value;
    if (oldest !== undefined) rpcCache.delete(oldest);
  }
  const entry = {
    ...captured,
    nextRevalidateAt: Date.now() + RPC_CACHE_REVALIDATE_MS,
    inflight: false,
  };
  rpcCache.set(key, entry);
  persistCacheEntry(key, entry);
}
