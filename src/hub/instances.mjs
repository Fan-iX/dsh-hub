// Multi-user instance registry: one dsh process per authenticated user, with
// uid/gid isolation, loopback owner guards, per-user logs, and the idle culler.
import fs from 'node:fs';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

import { CFG, IPTABLES, IS_ROOT, TRUSTED_HOSTS, TRUST_MODE } from './config.mjs';
import { lookupUser } from '../backend/auth.mjs';
import { DshInstance, startCuller } from '../backend/instance.mjs';
import { webConfigPatches } from './web-config.mjs';
import { forgetUserCache, prewarmSessionList } from './session-list-cache.mjs';

const execFileAsync = promisify(execFile);

/** @type {Map<string, DshInstance>} */
export const backends = new Map();

// iptables loopback owner-guard: only the backend's own uid (and root) may
// connect to the backend port on lo. Other local users get DROPped. This closes
// the "dsh has no auth and loopback is shared" hole on multi-user machines.
//
// Async with a hard SIGKILL timeout: iptables can block on the xtables lock for
// seconds, and a sync call here froze the whole hub (including the event streams
// it proxies) on every spawn and instance exit.
async function addGuard(port, uid) {
  if (!IPTABLES) return;
  // Insert in reverse so final order is: ACCEPT(root), ACCEPT(uid), DROP.
  await runIptables(['-I', 'OUTPUT', '1', '-o', 'lo', '-p', 'tcp', '--dport', String(port),
    '-j', 'DROP']);
  await runIptables(['-I', 'OUTPUT', '1', '-o', 'lo', '-p', 'tcp', '--dport', String(port),
    '-m', 'owner', '--uid-owner', String(uid), '-j', 'ACCEPT']);
  await runIptables(['-I', 'OUTPUT', '1', '-o', 'lo', '-p', 'tcp', '--dport', String(port),
    '-m', 'owner', '--uid-owner', '0', '-j', 'ACCEPT']);
}

/** Remove the loopback owner guard for one closed backend. */
export async function removeGuard(port, uid) {
  if (!IPTABLES) return;
  for (const args of [
    ['-o', 'lo', '-p', 'tcp', '--dport', String(port), '-m', 'owner', '--uid-owner', '0', '-j', 'ACCEPT'],
    ['-o', 'lo', '-p', 'tcp', '--dport', String(port), '-m', 'owner', '--uid-owner', String(uid), '-j', 'ACCEPT'],
    ['-o', 'lo', '-p', 'tcp', '--dport', String(port), '-j', 'DROP'],
  ]) {
    await runIptables(['-D', 'OUTPUT', ...args], true);
  }
}

async function runIptables(args, tolerate = false) {
  const bin = fs.existsSync('/usr/sbin/iptables') ? '/usr/sbin/iptables' : '/usr/bin/iptables';
  try {
    await execFileAsync(bin, args, { timeout: 5000, killSignal: 'SIGKILL', maxBuffer: 64 * 1024 });
  } catch (err) {
    if (!tolerate) console.error('[hub] iptables failed:', args.join(' '), err.message);
  }
}

/**
 * Return this user's running instance, spawning one on first use.
 * @throws when the account is unknown or not on the allow-list.
 */
export async function getOrCreateBackend(user) {
  let be = backends.get(user);
  // Join an in-flight spawn instead of returning a not-yet-ready instance; the
  // session-list cache path awaits this and must not forward too early.
  if (be?.starting) return be.start();
  if (be && be.child && be.child.exitCode === null) return be;

  const info = await lookupUser(user, true);
  if (!info) throw new Error(`unknown system user: ${user}`);
  if (CFG.allowUsers.length && !CFG.allowUsers.includes(user)) {
    throw new Error(`user ${user} is not on the allow-list`);
  }

  const home = info.home;
  const env = {
    HOME: home,
    DSH_HOME: path.join(home, '.dsh'),   // per-user data root: sessions, keys, settings
    // Marks the process as hub-spawned for host-side plugins (dsh-hub-utils
    // registers its quit route only under the hub).
    DSH_HUB: '1',
    PATH: '/usr/local/bin:/usr/bin:/bin',
    LANG: process.env.LANG ?? 'en_US.UTF-8',
    TERM: 'xterm-256color',
  };

  // Per-user default workspace: if ~/.dsh/hub-default-workspace names an
  // existing directory, spawn the backend there instead of home. The dsh web
  // sidebar is workspace-scoped, so landing in the user's data workspace makes
  // their sessions visible immediately (no directory-picker navigation, which
  // cannot traverse home symlinks).
  let cwd = home;
  try {
    const dflt = fs.readFileSync(path.join(home, '.dsh', 'hub-default-workspace'), 'utf8').trim();
    if (dflt && fs.statSync(dflt).isDirectory()) cwd = dflt;
  } catch { /* no default workspace configured — keep home */ }

  const instance = new DshInstance({
    user,
    cwd,
    env,
    bin: CFG.dshBin,
    patches: webConfigPatches(),
    trustMode: TRUST_MODE,
    trustedHosts: TRUSTED_HOSTS,
    uid: IS_ROOT ? info.uid : undefined,
    gid: IS_ROOT ? info.gid : undefined,
    logPath: path.join(CFG.logDir, `${user}.log`),
    spawnTimeoutMs: CFG.spawnTimeoutMs,
    onSpawn: (be) => addGuard(be.port, info.uid),
    onExit: (be) => {
      void removeGuard(be.port, info.uid);
      forgetUserCache(user); // hot memory follows the instance; the disk survives
      if (backends.get(user) === be) backends.delete(user);
    },
  });
  instance.info = info; // shutdown needs the guarded uid
  backends.set(user, instance);
  try {
    await instance.start();
  } catch (err) {
    if (instance.child) instance.stop();
    if (backends.get(user) === instance) backends.delete(user);
    throw err;
  }
  prewarmSessionList(user, instance); // warm the session-list cache before the browser asks
  return instance;
}

// Idle culler. 0 = never cull (JupyterHub-style always-on backends; the
// browser-closed conversation keeps running indefinitely, tmux-style).
//
// Idleness is measured from `lastActivity`, which every proxied HTTP request and
// every frame of a proxied event stream refreshes. A backend that still has an
// attached stream is never reaped even if no frame arrived inside the window:
// dsh heartbeats the stream every 2s, so an attached browser would otherwise
// keep it active anyway — the guard just makes a stalled reader explicit. This
// is what keeps a long server-side turn (say, an agent blocked on a background
// job) alive while the user watches it.
startCuller(() => backends.values(), CFG);
