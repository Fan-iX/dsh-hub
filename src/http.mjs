// Shared HTTP plumbing: response helpers and request-body readers used by the
// login handlers, the router, and the session-list cache.

/** Write a small HTML response. */
export function sendHtml(res, status, body, headers = {}) {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', ...headers });
  res.end(body);
}

/** Read a request body as UTF-8 text, rejecting anything over `limit` bytes. */
export function readBody(req, limit = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString()));
    req.on('error', reject);
  });
}

/** Parse an `application/x-www-form-urlencoded` login body. */
export function urlencoded(body) {
  const params = new URLSearchParams(body);
  return { username: params.get('username') ?? '', password: params.get('password') ?? '' };
}

/** Read a request body as a Buffer, with no size cap. */
export function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/** Copy headers for a hub-internal backend request, forcing a loopback Host. */
export function sanitizeForwardHeaders(headers, bePort) {
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    const key = k.toLowerCase();
    if (['connection', 'transfer-encoding', 'upgrade', 'keep-alive', 'proxy-connection', 'te', 'content-length', 'host'].includes(key)) continue;
    out[k] = v;
  }
  out.host = `127.0.0.1:${bePort}`;
  return out;
}
