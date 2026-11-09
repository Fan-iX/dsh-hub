// Serve-stale /api/session/list cache with two tiers:
//  - memory: one standard-payload entry per user, for browser page reconnects;
//  - disk: optional, one <user>.cache file per user, for respawning an instance
//    without a cold session-list projection.
//
// The cached body is canonical: the top-level rpcId value is replaced by "" and
// the value span is recorded, so the caller's rpcId can be written without
// parsing or copying the whole response. Disk files store the raw canonical
// body after a small binary header; no base64, no JSON round-trip.
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';

import { CACHE_DIR, CFG } from './config.mjs';
import { hubDshCookieHeader } from '../backend/dsh-proxy.mjs';
import { sanitizeForwardHeaders } from '../backend/web.mjs';

export const SESSION_LIST_PATH = '/api/session/list';
const REVALIDATE_MS = 60_000;
const MEM_TTL_MS = CFG.cacheMemTtlMs;
const MEM_MAX_BYTES = CFG.cacheMemoryMaxBytes;
const ENTRY_MAX_BYTES = CFG.cacheEntryMaxBytes;
const MEM_SWEEP_MS = 60_000;
const SESSION_LIST_TIMEOUT_MS = 120_000;
const DISK_MAGIC = Buffer.from('DSHC');
const DISK_VERSION = 1;
const HEADER_FIXED = 10; // magic(4) + version(u16) + headerLen(u32)

const STANDARD_SESSION_LIST_BODY = Buffer.from(JSON.stringify({
  type: 'client-request', rpcId: 'hub-prewarm', method: 'session/list',
  payload: { args: { _request: {} } },
}));

const memory = new Map(); // user -> { body, prefixEnd, suffixStart, bodyLen, hash, ... }
let memoryBytes = 0;
const revalidateAt = new Map(); // user -> timestamp
const prewarmInflight = new Set();
const diskQueue = new Map(); // user -> Promise (serialize writes per user)

// --------------------------------------------------------------- hashing ----

/** Change-detection hash; MD5 is the fastest built-in, SHA-256 is the FIPS fallback. */
function contentHash(buf) {
  try {
    if (typeof crypto.hash === 'function') return crypto.hash('md5', buf).toString('hex');
  } catch { /* MD5 unavailable (e.g. FIPS) */ }
  return crypto.createHash('sha256').update(buf).digest('hex');
}

// ------------------------------------------------------- canonical body -----

/**
 * Find the value span of the top-level `rpcId` key, without parsing the body.
 * Only a depth-1 object key counts, so `"rpcId"` inside a session title, a
 * nested object, or an escaped string is ignored.
 * @returns `{ start, end }` covering the JSON string value (both quotes), or null.
 */
function findTopLevelRpcId(body) {
  const n = body.length;
  let i = 0;
  const isWs = (c) => c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d;
  const skipWs = () => { while (i < n && isWs(body[i])) i++; };
  const skipString = () => {
    if (body[i] !== 0x22) return false;
    i++;
    while (i < n) {
      if (body[i] === 0x5c) { i += 2; continue; }
      if (body[i] === 0x22) { i++; return true; }
      i++;
    }
    return false;
  };
  const skipValue = () => {
    if (body[i] === 0x22) return skipString();
    if (body[i] === 0x7b || body[i] === 0x5b) {
      let depth = 0;
      while (i < n) {
        const c = body[i];
        if (c === 0x22) { if (!skipString()) return false; continue; }
        if (c === 0x7b || c === 0x5b) { depth++; i++; continue; }
        if (c === 0x7d || c === 0x5d) { depth--; i++; if (depth === 0) return true; continue; }
        i++;
      }
      return false;
    }
    while (i < n) {
      const c = body[i];
      if (c === 0x2c || c === 0x7d || c === 0x5d || isWs(c)) return true;
      i++;
    }
    return true;
  };

  skipWs();
  if (body[i] !== 0x7b) return null;
  i++;
  for (;;) {
    skipWs();
    if (i >= n || body[i] === 0x7d) return null;
    if (body[i] !== 0x22) return null;
    const keyStart = i + 1;
    if (!skipString()) return null;
    const key = body.toString('latin1', keyStart, i - 1);
    skipWs();
    if (body[i] !== 0x3a) return null;
    i++;
    skipWs();
    if (key === 'rpcId') {
      if (body[i] !== 0x22) return null;
      const start = i;
      if (!skipString()) return null;
      return { start, end: i };
    }
    if (!skipValue()) return null;
    skipWs();
    if (i < n && body[i] === 0x2c) { i++; continue; }
    // A top-level object without rpcId is not cacheable.
    return null;
  }
}

/**
 * Replace the top-level rpcId value with "" and record its span. The body stays
 * valid JSON; serving writes prefix + caller rpcId + suffix.
 * @returns `{ body, prefixEnd, suffixStart, bodyLen, hash }`, or null.
 */
function canonicalize(body) {
  const span = findTopLevelRpcId(body);
  if (span === null) return null;
  const canonical = Buffer.concat([
    body.subarray(0, span.start),
    Buffer.from('""'),
    body.subarray(span.end),
  ]);
  return {
    body: canonical,
    prefixEnd: span.start,
    suffixStart: span.start + 2,
    bodyLen: canonical.length,
    hash: contentHash(canonical),
  };
}

// --------------------------------------------------------------- memory -----

function memoryDelete(user) {
  const entry = memory.get(user);
  if (entry === undefined) return;
  memoryBytes -= entry.bytes;
  memory.delete(user);
}

function evictFor(bytes) {
  while (memoryBytes + bytes > MEM_MAX_BYTES && memory.size > 0) {
    let oldestUser;
    let oldest = Infinity;
    for (const [user, entry] of memory) {
      if (entry.lastUsed < oldest) { oldest = entry.lastUsed; oldestUser = user; }
    }
    if (oldestUser === undefined) break;
    memoryDelete(oldestUser);
  }
}

function memorySet(user, entry) {
  memoryDelete(user);
  if (entry.bytes > ENTRY_MAX_BYTES) return;
  evictFor(entry.bytes);
  if (memoryBytes + entry.bytes > MEM_MAX_BYTES) return;
  memory.set(user, entry);
  memoryBytes += entry.bytes;
}

/** The hot entry for `user`, or null when absent/expired. */
export function memoryLookup(user) {
  const entry = memory.get(user);
  if (entry === undefined) return null;
  if (Date.now() - entry.refreshedAt >= MEM_TTL_MS) { memoryDelete(user); return null; }
  entry.lastUsed = Date.now();
  return entry;
}

/** Drop the hot entry for a user; the disk file is intentionally kept. */
export function forgetUserCache(user) {
  memoryDelete(user);
  revalidateAt.delete(user);
}

setInterval(() => {
  const now = Date.now();
  for (const [user, entry] of memory) {
    if (now - entry.refreshedAt >= MEM_TTL_MS) memoryDelete(user);
  }
}, MEM_SWEEP_MS).unref();

// ----------------------------------------------------------------- disk -----

function diskPath(user) {
  if (!/^[a-z_][a-z0-9_-]{0,31}$/i.test(user)) return null;
  return path.join(CACHE_DIR, `${user}.cache`);
}

function headerFor(canonical, contentType, status, savedAt) {
  return Buffer.from(JSON.stringify({
    status,
    contentType,
    savedAt,
    bodyLen: canonical.bodyLen,
    prefixEnd: canonical.prefixEnd,
    suffixStart: canonical.suffixStart,
    hash: canonical.hash,
  }));
}

async function readDiskHeader(user) {
  if (CACHE_DIR === null) return null;
  const file = diskPath(user);
  if (file === null) return null;
  let handle;
  try {
    handle = await fs.promises.open(file, 'r');
    const fixed = Buffer.alloc(HEADER_FIXED);
    const got = await handle.read(fixed, 0, HEADER_FIXED, 0);
    if (got.bytesRead !== HEADER_FIXED) return null;
    if (!fixed.subarray(0, 4).equals(DISK_MAGIC)) return null;
    if (fixed.readUInt16LE(4) !== DISK_VERSION) return null;
    const headerLen = fixed.readUInt32LE(6);
    if (headerLen <= 0 || headerLen > 64 * 1024) return null;
    const headerBuf = Buffer.alloc(headerLen);
    const head = await handle.read(headerBuf, 0, headerLen, HEADER_FIXED);
    if (head.bytesRead !== headerLen) return null;
    const meta = JSON.parse(headerBuf.toString('utf8'));
    const stat = await handle.stat();
    const bodyOffset = HEADER_FIXED + headerLen;
    if (!Number.isInteger(meta.bodyLen) || meta.bodyLen < 0) return null;
    if (bodyOffset + meta.bodyLen > stat.size) return null;
    if (!Number.isInteger(meta.prefixEnd) || !Number.isInteger(meta.suffixStart)) return null;
    if (meta.prefixEnd < 0 || meta.suffixStart < meta.prefixEnd + 2) return null;
    if (meta.suffixStart > meta.bodyLen) return null;
    return { file, bodyOffset, ...meta };
  } catch {
    return null;
  } finally {
    if (handle !== undefined) await handle.close().catch(() => {});
  }
}

/** Load one user's disk entry metadata (no body read); null on miss/corruption. */
export async function loadDiskEntry(user) {
  const meta = await readDiskHeader(user);
  if (meta === null) return null;
  return {
    file: meta.file,
    bodyOffset: meta.bodyOffset,
    prefixEnd: meta.prefixEnd,
    suffixStart: meta.suffixStart,
    bodyLen: meta.bodyLen,
    hash: meta.hash,
    contentType: typeof meta.contentType === 'string' ? meta.contentType : 'application/json',
    status: Number.isInteger(meta.status) ? meta.status : 200,
    refreshedAt: Number.isFinite(meta.savedAt) ? meta.savedAt : Date.now(),
    lastUsed: Date.now(),
    bytes: meta.bodyLen,
  };
}

async function writeDisk(file, canonical, contentType, status) {
  await fs.promises.mkdir(CACHE_DIR, { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  const header = headerFor(canonical, contentType, status, Date.now());
  const fixed = Buffer.alloc(HEADER_FIXED);
  DISK_MAGIC.copy(fixed, 0);
  fixed.writeUInt16LE(DISK_VERSION, 4);
  fixed.writeUInt32LE(header.length, 6);
  const handle = await fs.promises.open(tmp, 'w', 0o600);
  try {
    await handle.write(fixed, 0, fixed.length, 0);
    await handle.write(header, 0, header.length, fixed.length);
    await handle.write(canonical.body, 0, canonical.body.length, fixed.length + header.length);
  } catch (err) {
    await handle.close().catch(() => {});
    await fs.promises.unlink(tmp).catch(() => {});
    throw err;
  }
  await handle.close();
  try {
    await fs.promises.rename(tmp, file);
  } catch (err) {
    await fs.promises.unlink(tmp).catch(() => {});
    throw err;
  }
}

async function persistDiskNow(user, canonical, contentType, status) {
  const meta = await readDiskHeader(user);
  if (meta !== null && meta.hash === canonical.hash) return; // content unchanged
  const file = diskPath(user);
  if (file === null) return;
  await writeDisk(file, canonical, contentType, status);
}

/** Queue a disk write; writes are serialized per user and only on content change. */
function persistDisk(user, canonical, contentType, status) {
  if (CACHE_DIR === null || diskPath(user) === null) return;
  const prev = diskQueue.get(user) ?? Promise.resolve();
  const next = prev
    .then(() => persistDiskNow(user, canonical, contentType, status))
    .catch((err) => console.error(`[hub] session.list disk cache write failed for ${user}:`, err.message))
    .finally(() => { if (diskQueue.get(user) === next) diskQueue.delete(user); });
  diskQueue.set(user, next);
}

// -------------------------------------------------------------- serving -----

/**
 * Write a cached entry under `rpcId`: prefix + escaped rpcId + suffix.
 * Memory entries are served from Buffer slices; disk entries stream the suffix
 * from the file without loading the whole body.
 * @returns true when a response was written.
 */
export async function serveCachedSessionList(res, entry, rpcId) {
  if (rpcId === undefined || res.destroyed || res.writableEnded) return false;
  const escaped = JSON.stringify(rpcId);
  const length = entry.prefixEnd + Buffer.byteLength(escaped) + (entry.bodyLen - entry.suffixStart);

  if (entry.body !== undefined) {
    res.writeHead(entry.status, {
      'content-type': entry.contentType ?? 'application/json',
      'content-length': length,
    });
    res.write(entry.body.subarray(0, entry.prefixEnd));
    res.write(escaped);
    res.write(entry.body.subarray(entry.suffixStart));
    res.end();
    return true;
  }

  // Disk: read the (normally tiny) prefix before committing the headers so a
  // missing/truncated file can still fall back to forwarding.
  const prefix = Buffer.alloc(entry.prefixEnd);
  if (entry.prefixEnd > 0) {
    const handle = await fs.promises.open(entry.file, 'r');
    try {
      const got = await handle.read(prefix, 0, entry.prefixEnd, entry.bodyOffset);
      if (got.bytesRead !== entry.prefixEnd) throw new Error('truncated cache prefix');
    } finally {
      await handle.close().catch(() => {});
    }
  }
  if (res.destroyed || res.writableEnded) return true;
  res.writeHead(entry.status, {
    'content-type': entry.contentType ?? 'application/json',
    'content-length': length,
  });
  res.write(prefix);
  res.write(escaped);
  if (entry.suffixStart >= entry.bodyLen) {
    res.end();
    return true;
  }
  await new Promise((resolve, reject) => {
    const stream = fs.createReadStream(entry.file, {
      start: entry.bodyOffset + entry.suffixStart,
      end: entry.bodyOffset + entry.bodyLen - 1,
    });
    let settled = false;
    const done = (err) => {
      if (settled) return;
      settled = true;
      stream.destroy();
      if (err) reject(err); else resolve();
    };
    stream.on('error', done);
    stream.on('end', () => done());
    res.on('close', () => done());
    stream.pipe(res);
  });
  return true;
}

// ------------------------------------------------------------- rewrite ------

/**
 * Store one fresh captured response. The memory entry expires after
 * CACHE_MEM_TTL_MS from the last content change; the disk is written only when
 * the canonical body (rpcId replaced by "") changed.
 */
export function storeSessionList(user, captured) {
  if (!isCacheableSessionList(captured)) return null;
  const canonical = canonicalize(captured.body);
  if (canonical === null) return null; // no top-level string rpcId: not servable
  const now = Date.now();
  const existing = memory.get(user);
  const changed = existing === undefined || existing.hash !== canonical.hash;
  const contentType = captured.headers['content-type'] ?? 'application/json';
  const entry = {
    body: canonical.body,
    prefixEnd: canonical.prefixEnd,
    suffixStart: canonical.suffixStart,
    bodyLen: canonical.bodyLen,
    hash: canonical.hash,
    contentType,
    status: captured.status,
    refreshedAt: changed ? now : existing.refreshedAt,
    lastUsed: now,
    bytes: canonical.bodyLen,
  };
  if (entry.bytes <= ENTRY_MAX_BYTES) memorySet(user, entry);
  else memoryDelete(user);
  persistDisk(user, canonical, contentType, captured.status);
  return entry;
}

// ------------------------------------------------------------ lifecycle -----

/** True when the body is `this.remote.session.list({})` (the standard payload). */
export function isStandardSessionList(body) {
  let parsed;
  try {
    parsed = JSON.parse(body.toString('utf8'));
  } catch {
    return false;
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return false;
  if (parsed.type !== 'client-request' || parsed.method !== 'session/list') return false;
  const payload = parsed.payload;
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) return false;
  if (Object.keys(payload).length !== 1) return false;
  const args = payload.args;
  if (args === null || typeof args !== 'object' || Array.isArray(args)) return false;
  if (Object.keys(args).length !== 1) return false;
  const request = args._request;
  return request !== null && typeof request === 'object'
    && !Array.isArray(request) && Object.keys(request).length === 0;
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

/** A cacheable session.list payload: non-empty 200 carrying an items array. */
export function isCacheableSessionList(captured) {
  if (captured.status !== 200 || captured.body.length === 0) return false;
  try {
    const parsed = JSON.parse(captured.body.toString('utf8'));
    return parsed?.result?.ok === true && Array.isArray(parsed.result.value?.items);
  } catch {
    return false;
  }
}

// ----------------------------------------------------------- forwarding -----

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

export async function revalidateSessionList(user, be, body) {
  revalidateAt.set(user, Date.now());
  const cookie = await hubDshCookieHeader(be);
  const headers = { accept: 'application/json', 'content-type': 'application/json' };
  if (cookie) headers.cookie = cookie;
  const captured = await forwardSessionList(be, headers, body);
  if (captured.status === 401) be.internalCookie = null; // rotated secret: re-mint next time
  storeSessionList(user, captured);
}

/** Refresh a hot entry at most once per REVALIDATE_MS. */
export function maybeRevalidateSessionList(user, be, body) {
  const now = Date.now();
  if (now - (revalidateAt.get(user) ?? 0) < REVALIDATE_MS) return;
  revalidateAt.set(user, now);
  void revalidateSessionList(user, be, body)
    .catch((err) => console.error(`[hub] session.list revalidate failed for ${user}:`, err.message));
}

/** Warm the cache after a backend spawn, without a browser request. */
export function prewarmSessionList(user, be) {
  if (prewarmInflight.has(user)) return;
  prewarmInflight.add(user);
  void revalidateSessionList(user, be, STANDARD_SESSION_LIST_BODY)
    .catch((err) => console.error(`[hub] session.list prewarm failed for ${user}:`, err.message))
    .finally(() => prewarmInflight.delete(user));
}
