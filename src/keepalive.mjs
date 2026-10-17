// Keep-alive control: the dsh web UI (through the dsh-hub-utils plugin) asks the
// hub to exempt this user's instance from idle culling, so closing the page no
// longer lets the culler reap it. The flag lives on the Backend, so it applies to
// that instance and resets when the instance is replaced.
import { backends } from './backends.mjs';
import { readBody } from './http.mjs';

/** Largest JSON body accepted here; the only field is one boolean. */
const MAX_BODY_BYTES = 1024;

/**
 * Answer one request on the keep-alive route.
 * @param req - the incoming request, already authenticated by the router.
 * @param res - the response this handler owns.
 * @param user - the authenticated hub user.
 */
export async function handleKeepAlive(req, res, user) {
  const be = backends.get(user);
  if (req.method === 'GET') {
    sendJson(res, 200, { keepAlive: be?.keepAlive === true, running: be !== undefined });
    return;
  }
  if (req.method !== 'POST') {
    res.writeHead(405, { allow: 'GET, POST', 'content-type': 'text/plain; charset=utf-8' });
    res.end('GET or POST only\n');
    return;
  }
  // CSRF: the hub session cookie is SameSite=Lax, and a cross-site form cannot
  // send application/json without a CORS preflight, so this pair is the guard.
  if (!/^application\/json\s*(;|$)/i.test(String(req.headers['content-type'] ?? ''))) {
    sendJson(res, 415, { error: 'content-type must be application/json' });
    return;
  }
  let raw;
  try {
    raw = await readBody(req, MAX_BODY_BYTES);
  } catch (err) {
    sendJson(res, err.message === 'body too large' ? 413 : 400, { error: err.message });
    return;
  }
  let payload;
  try {
    payload = JSON.parse(raw);
  } catch {
    sendJson(res, 400, { error: 'invalid JSON body' });
    return;
  }
  if (typeof payload?.keepAlive !== 'boolean') {
    sendJson(res, 400, { error: 'keepAlive must be a boolean' });
    return;
  }
  if (be === undefined) {
    sendJson(res, 409, { error: 'no running instance' });
    return;
  }
  if (be.keepAlive !== payload.keepAlive) {
    be.keepAlive = payload.keepAlive;
    console.log(`[hub] keep-alive ${be.keepAlive ? 'enabled' : 'disabled'} for ${user}`);
  }
  be.lastActivity = Date.now(); // the toggle is a browser interaction
  sendJson(res, 200, { keepAlive: be.keepAlive, running: true });
}

/** Write one JSON response. */
function sendJson(res, status, value) {
  const body = JSON.stringify(value);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
  });
  res.end(body);
}
