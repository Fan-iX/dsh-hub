// Spawned dsh instances: per-user process lifecycle, loopback port guards,
// per-user backend logs, and the idle culler.
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { execFileSync, spawn } from 'node:child_process';

import { CFG, IPTABLES, IS_ROOT, TRUSTED_HOSTS, TRUST_MODE } from './config.mjs';
import { setLaunchToken } from './browser-session.mjs';
import { ACCOUNT_UI_PATCH_PATH } from './dsh-patch.mjs';
import { prewarmSessionList } from './session-list-cache.mjs';
import { lookupUser } from './users.mjs';

// -------------------------------------------------------------- backends ----

/** @type {Map<string, Backend>} */
export const backends = new Map();

class Backend {
  constructor(user, info, port) {
    this.user = user;
    this.info = info;
    this.port = port;
    this.child = null;
    this.ready = null;      // promise resolved when TCP accepts
    this.lastActivity = Date.now();
    this.starting = false;
    this.launchToken = null;          // dsh's one-shot browser-session launch token, parsed from stdout
    this.launchTokenUnavailable = false;
    this.launchTokenWaiters = [];
    this.internalCookie = null;       // hub-minted dsh cookie for its own /api calls (prewarm/revalidate)
    this.bridgeAttemptAt = 0;         // throttles 401-triggered re-mints
    this.wsClients = 0;               // attached event streams; a backend with one is never culled
    this.keepAlive = false;           // user opted out of idle culling (dsh-hub-utils toggle)
  }
}

function randomFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

function waitTcp(port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    (function tryOnce() {
      const sock = net.connect(port, '127.0.0.1');
      sock.once('connect', () => { sock.destroy(); resolve(); });
      sock.once('error', () => {
        sock.destroy();
        if (Date.now() > deadline) reject(new Error(`backend did not come up within ${timeoutMs}ms`));
        else setTimeout(tryOnce, 300);
      });
    })();
  });
}

// iptables loopback owner-guard: only the backend's own uid (and root) may
// connect to the backend port on lo. Other local users get DROPped. This closes
// the "dsh has no auth and loopback is shared" hole on multi-user machines.
function addGuard(port, uid) {
  if (!IPTABLES) return;
  // Insert in reverse so final order is: ACCEPT(root), ACCEPT(uid), DROP.
  runIptables(['-I', 'OUTPUT', '1', '-o', 'lo', '-p', 'tcp', '--dport', String(port),
    '-j', 'DROP']);
  runIptables(['-I', 'OUTPUT', '1', '-o', 'lo', '-p', 'tcp', '--dport', String(port),
    '-m', 'owner', '--uid-owner', String(uid), '-j', 'ACCEPT']);
  runIptables(['-I', 'OUTPUT', '1', '-o', 'lo', '-p', 'tcp', '--dport', String(port),
    '-m', 'owner', '--uid-owner', '0', '-j', 'ACCEPT']);
}
export function removeGuard(port, uid) {
  if (!IPTABLES) return;
  for (const args of [
    ['-o', 'lo', '-p', 'tcp', '--dport', String(port), '-m', 'owner', '--uid-owner', '0', '-j', 'ACCEPT'],
    ['-o', 'lo', '-p', 'tcp', '--dport', String(port), '-m', 'owner', '--uid-owner', String(uid), '-j', 'ACCEPT'],
    ['-o', 'lo', '-p', 'tcp', '--dport', String(port), '-j', 'DROP'],
  ]) {
    try {
      const bin = fs.existsSync('/usr/sbin/iptables') ? '/usr/sbin/iptables' : '/usr/bin/iptables';
      execFileSync(bin, ['-D', 'OUTPUT', ...args], { stdio: 'ignore', timeout: 5000 });
    } catch { /* already gone */ }
  }
}
function runIptables(args, tolerate = false) {
  const bin = '/usr/sbin/iptables';
  try {
    execFileSync(fs.existsSync(bin) ? bin : '/usr/bin/iptables', args, { stdio: 'ignore', timeout: 5000 });
  } catch (err) {
    if (!tolerate) console.error('[hub] iptables failed:', args.join(' '), err.message);
  }
}

function logStreamFor(user) {
  try {
    fs.mkdirSync(CFG.logDir, { recursive: true });
    fs.accessSync(CFG.logDir, fs.constants.W_OK);
    const stream = fs.createWriteStream(path.join(CFG.logDir, `${user}.log`), { flags: 'a' });
    stream.on('error', (e) => console.error(`[hub] backend log for ${user} unavailable:`, e.message));
    return stream;
  } catch {
    return 'ignore';
  }
}

export async function getOrCreateBackend(user) {
  let be = backends.get(user);
  if (be && be.child && be.child.exitCode === null) return be;
  if (be?.starting) return be;

  const info = lookupUser(user);
  if (!info) throw new Error(`unknown system user: ${user}`);
  if (CFG.allowUsers.length && !CFG.allowUsers.includes(user)) {
    throw new Error(`user ${user} is not on the allow-list`);
  }

  const port = await randomFreePort();
  be = new Backend(user, info, port);
  be.starting = true;
  backends.set(user, be);

  const home = info.home;
  const env = {
    HOME: home,
    DSH_HOME: path.join(home, '.dsh'),   // per-user data root: sessions, keys, settings
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

  const opts = {
    cwd,
    env,
    // Own process group: the shutdown handler can then signal the whole dsh tree
    // (terminals, subagents), not only the direct child.
    detached: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  };
  if (IS_ROOT) { opts.uid = info.uid; opts.gid = info.gid; }
  else console.warn('[hub] non-root: spawning dsh as hub user (dev mode, no isolation)');

  console.log(`[hub] spawning dsh for ${user} (uid ${info.uid}) on 127.0.0.1:${port}, DSH_HOME=${env.DSH_HOME}`);
  // `--profile web` (rather than the `web` abbreviation) is required once the
  // launcher-level `--patch` overlay is in play. The overlay hides the
  // loopback-only account UI; the user's own cordis.patch.yml is never touched.
  const args = [CFG.dshBin, '--profile', 'web'];
  if (CFG.hideAccountUi && fs.existsSync(ACCOUNT_UI_PATCH_PATH)) {
    args.push('--patch', ACCOUNT_UI_PATCH_PATH);
  }
  args.push('--port', String(port), '--no-open');
  if (TRUST_MODE === 'trusted-host') {
    for (const authority of TRUSTED_HOSTS) args.push('--trusted-host', authority);
  }
  const child = spawn(process.execPath, args, opts);
  be.child = child;
  // dsh prints, once at readiness, the only URL that can mint its browser-session
  // cookie: `dsh web: http://127.0.0.1:<port>/?token=<token>`. Capture that token
  // in flight so the hub can spend it on behalf of PAM-authenticated browsers.
  let stdoutTail = '';
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    if (be.launchToken) return;
    stdoutTail = (stdoutTail + chunk).slice(-8192);
    const line = /dsh web:\s+(\S+)/.exec(stdoutTail);
    if (!line) return;
    try {
      const token = new URL(line[1]).searchParams.get('token');
      if (token) setLaunchToken(be, token);
    } catch { /* URL not fully written yet — keep buffering */ }
  });
  const log = logStreamFor(user);
  if (log !== 'ignore') {
    child.stdout.pipe(log, { end: false });
    child.stderr.pipe(log, { end: false });
  } else {
    child.stdout.resume(); child.stderr.resume();
  }

  addGuard(port, info.uid);

  child.once('exit', (code, signal) => {
    console.log(`[hub] dsh for ${user} exited (code=${code} signal=${signal})`);
    removeGuard(port, info.uid);
    if (backends.get(user) === be) backends.delete(user);
  });

  be.ready = waitTcp(port, CFG.spawnTimeoutMs).finally(() => {
    be.starting = false;
    be.lastActivity = Date.now(); // the idle window starts at readiness, not at fork
  });
  await be.ready;
  prewarmSessionList(user, be); // warm the session-list cache before the browser asks
  return be;
}

async function stopBackend(user) {
  const be = backends.get(user);
  if (!be) return;
  console.log(`[hub] culling dsh for ${user} (port ${be.port})`);
  be.child?.kill('SIGTERM');
  setTimeout(() => be.child?.kill('SIGKILL'), 5000).unref();
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
if (CFG.idleCullMs > 0) {
  setInterval(() => {
    const now = Date.now();
    for (const [user, be] of backends) {
      if (be.starting) continue;        // a spawn in flight is work, not idleness
      if (be.wsClients > 0) continue;   // a live event stream keeps the instance
      if (be.keepAlive) continue;       // the user pinned this instance from the web UI
      if (now - be.lastActivity > CFG.idleCullMs) stopBackend(user);
    }
  }, CFG.cullIntervalMs).unref();
}
