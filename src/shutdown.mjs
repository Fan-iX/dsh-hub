// Graceful stop for the whole hub: kill every spawned instance's process group,
// release its loopback guard, delete the persisted cache and cookie secret, and
// exit. Cleanup is best-effort and bounded so a wedged backend can never keep
// the process alive.
import fs from 'node:fs';

import { CACHE_DIR, CFG, SECRET_PATH } from './config.mjs';
import { backends, removeGuard } from './backends.mjs';

let shuttingDown = false;

/** Signal one backend's whole process group, falling back to the direct child. */
function killBackendTree(be, signal) {
  if (!be?.child || be.child.exitCode !== null) return;
  try {
    process.kill(-be.child.pid, signal); // detached spawn ⇒ negative pid = its group
  } catch {
    try { be.child.kill(signal); } catch { /* already gone */ }
  }
}

/** SIGKILL every live backend and release its loopback guard. */
function forceKillBackends() {
  for (const be of backends.values()) {
    killBackendTree(be, 'SIGKILL');
    removeGuard(be.port, be.info.uid);
  }
}

/** Delete the persisted cache and the cookie secret unless cleanup is disabled. */
function removeRuntimeState() {
  if (!CFG.cleanOnStop) {
    console.log('[hub] HUB_CLEAN_ON_STOP=0: keeping cache and cookie secret');
    return;
  }
  for (const [what, target, options] of [
    ['cache', CACHE_DIR, { recursive: true, force: true }],
    ['cookie secret', SECRET_PATH, { force: true }],
  ]) {
    try {
      fs.rmSync(target, options);
      console.log(`[hub] removed ${what} ${target}`);
    } catch (err) {
      console.error(`[hub] ${what} cleanup failed:`, err.message);
    }
  }
}

/**
 * Build the shutdown handler for one HTTP server.
 * @param server - the hub server to stop accepting connections on.
 * @returns a function that tears the hub down and exits the process.
 */
export function createShutdown(server) {
  return function shutdown(reason) {
    if (shuttingDown) {
      console.warn(`[hub] ${reason} again during shutdown — forcing exit`);
      forceKillBackends();
      removeRuntimeState();
      process.exit(0);
    }
    shuttingDown = true;
    console.log(`[hub] ${reason} received: stopping ${backends.size} dsh instance(s)`);
    try { server.close(); } catch { /* already closing */ }

    const pending = [...backends.values()].filter((be) => be.child && be.child.exitCode === null);
    for (const be of pending) killBackendTree(be, 'SIGTERM');

    const deadline = Date.now() + CFG.shutdownGraceMs;
    let finished = false;
    let timer;
    const finish = () => {
      if (finished) return;
      finished = true;
      clearInterval(timer);
      forceKillBackends(); // the child exit handler normally removed guards; this is the backstop
      removeRuntimeState();
      console.log('[hub] shutdown complete');
      process.exit(0);
    };
    timer = setInterval(() => {
      if (!pending.some((be) => be.child.exitCode === null)) { finish(); return; }
      if (Date.now() >= deadline) finish();
    }, 100);
    // Hard ceiling: never let a wedged backend hold the process open.
    setTimeout(finish, CFG.shutdownGraceMs + 3000);
  };
}

/** Run `shutdown` on the external stop signals. */
export function registerSignalHandlers(shutdown) {
  for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) {
    process.on(signal, () => shutdown(signal));
  }
}
