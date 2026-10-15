// The hub's HTTP entry: request handling through the router, plus the
// WebSocket upgrade path that carries dsh's event streams.
import http from 'node:http';

import { TRUST_MODE } from './config.mjs';
import { sessionUser } from './auth.mjs';
import { backends } from './backends.mjs';
import { proxy } from './proxy.mjs';
import { route } from './router.mjs';

/**
 * Create the hub HTTP server with its request and upgrade handlers attached.
 * @returns the listening-ready server (caller owns `listen`).
 */
export function createHubServer() {
  const server = http.createServer((req, res) => {
    route(req, res).catch((err) => {
      console.error('[hub] handler error:', err);
      if (!res.headersSent) res.writeHead(500);
      res.end('dsh-hub: internal error');
    });
  });

  // WebSocket upgrade (dsh event streams) — routed by the same session cookie.
  server.on('upgrade', (req, socket, head) => {
    const user = sessionUser(req);
    if (!user) {
      socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      socket.destroy();
      return;
    }
    const be = backends.get(user);
    if (!be || !be.child || be.child.exitCode !== null) {
      socket.write('HTTP/1.1 503 Service Unavailable\r\n\r\n');
      socket.destroy();
      return;
    }
    be.lastActivity = Date.now();
    // An attached event stream is live use: count it so the idle culler never
    // reaps a backend whose browser is still watching (a long agent turn or a
    // background job can run for hours without a single HTTP request). dsh
    // heartbeats the stream every 2s and the client answers, so `data` keeps
    // arriving; the count alone is the stronger guard.
    be.wsClients += 1;
    socket.on('data', () => { be.lastActivity = Date.now(); });
    socket.on('close', () => {
      be.wsClients = Math.max(0, be.wsClients - 1);
      be.lastActivity = Date.now(); // the idle window starts when the stream detaches
    });
    if (TRUST_MODE === 'origin-rewrite') {
      req.headers.origin = `http://127.0.0.1:${be.port}`;
    }
    proxy.ws(req, socket, head, { target: `http://127.0.0.1:${be.port}` });
  });

  return server;
}
