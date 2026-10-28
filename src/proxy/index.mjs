// dsh-hub single-user proxy entry — a non-root front for one local dsh web.
//
// It gives dsh, which has no authentication and binds to loopback only, an
// authenticated HTTP/WebSocket listener on the LAN. The login page is the same
// username/password form as the multi-user hub; the only accepted account is
// the one running the proxy, verified through PAM. The proxy lazily spawns one
// dsh web process as that user, manages its lifecycle (cull, keep-alive, quit),
// and forwards the browser-session bridge exactly like the multi-user hub.
//
// No setuid, no iptables guard, no per-user isolation: run it on a single-user
// host or a host where other local users are trusted.

import { CFG, TRUSTED_HOSTS, TRUST_MODE } from './config.mjs';
import { lookupUser } from './auth.mjs';
import { createProxyServer } from './server.mjs';
import { startCuller } from '../backend/instance.mjs';

if (!await lookupUser(CFG.serviceUser, true)) {
  console.error(`[hub] FATAL: service account ${JSON.stringify(CFG.serviceUser)} does not exist`);
  process.exit(1);
}

const { server, getInstance } = createProxyServer();
startCuller(() => {
  const be = getInstance();
  return be ? [be] : [];
}, CFG);

let shuttingDown = false;
function shutdown(reason) {
  if (shuttingDown) {
    console.warn(`[hub] ${reason} again during shutdown — forcing exit`);
    process.exit(0);
  }
  shuttingDown = true;
  console.log(`[hub] ${reason} received: stopping the single-user proxy`);
  try { server.close(); } catch { /* already closing */ }
  getInstance()?.stop();
  // Keep the process alive through the child's grace period, then exit.
  setTimeout(() => process.exit(0), CFG.shutdownGraceMs + 1000);
}
for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) {
  process.on(signal, () => shutdown(signal));
}

server.listen(CFG.hubPort, CFG.hubHost, () => {
  console.log(`[hub] dsh-hub (single-user proxy) listening on ${CFG.hubHost}:${CFG.hubPort}`);
  console.log(`[hub] service account: ${CFG.serviceUser}`);
  console.log(`[hub] dsh binary: ${CFG.dshBin}`);
  console.log(`[hub] DSH_HOME: ${CFG.dshHome}`);
  console.log(`[hub] workspace: ${CFG.workspace}`);
  console.log(`[hub] trust mode: ${TRUST_MODE}` +
    (TRUST_MODE === 'trusted-host' ? ` (authorities: ${TRUSTED_HOSTS.join(', ') || 'none detected — set TRUSTED_HOSTS'})` : ''));
  console.log(`[hub] auth audit log: ${CFG.authLogPath}`);
  console.log(`[hub] dsh log: ${CFG.logPath}`);
  console.log(CFG.idleCullMs === 0
    ? '[hub] idle culling DISABLED — the instance runs until stopped'
    : `[hub] idle cull after ${Math.round(CFG.idleCullMs / 60000)} min`);
});
