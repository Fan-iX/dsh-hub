// One spawned dsh web instance: process lifecycle, launch-token capture, the
// per-instance activity/WebSocket/keep-alive state, and the idle culler. Both
// entry points use this class; the multi-user hub keeps a Map of them, the
// single-user proxy keeps exactly one.
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { spawn } from 'node:child_process';

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

/** Open an owner-only dsh log, or null when the path is unusable. */
function openLog(logPath) {
  if (!logPath) return null;
  try {
    fs.mkdirSync(path.dirname(logPath), { recursive: true });
    const stream = fs.createWriteStream(logPath, { flags: 'a', mode: 0o600 });
    stream.on('open', () => { try { fs.chmodSync(logPath, 0o600); } catch { /* best effort */ } });
    stream.on('error', (err) => console.error(`[hub] dsh log ${logPath} unavailable:`, err.message));
    return stream;
  } catch (err) {
    console.error(`[hub] dsh log ${logPath} unavailable:`, err.message);
    return null;
  }
}

/** One running (or starting) dsh web process. */
export class DshInstance {
  constructor(opts) {
    this.user = opts.user;
    this.opts = opts;
    this.port = opts.port ?? null;
    this.child = null;
    this.ready = null;          // promise resolved when TCP accepts
    this.starting = false;
    this.lastActivity = Date.now();
    this.launchToken = null;    // one-shot browser-session token, parsed from stdout
    this.launchTokenUnavailable = false;
    this.launchTokenWaiters = [];
    this.internalCookie = null; // hub-minted dsh cookie for internal /api calls
    this.bridgeAttemptAt = 0;   // throttles 401-triggered re-mints
    this.wsClients = 0;         // attached event streams; a backend with one is never culled
    this.keepAlive = false;     // user opted out of idle culling (dsh-hub-utils toggle)
    this.log = null;
    this.stdoutLine = '';
    this.stdoutTail = '';
  }

  /** Start the process and resolve once its loopback port accepts TCP. */
  async start() {
    if (this.starting) return this.ready;
    if (this.child && this.child.exitCode === null) return this;
    this.starting = true;
    this.ready = this.#start().finally(() => { this.starting = false; });
    await this.ready;
    return this;
  }

  async #start() {
    if (this.port === null) this.port = await randomFreePort();
    const args = [this.opts.bin, '--profile', this.opts.profile ?? 'web'];
    for (const patch of this.opts.patches ?? []) args.push('--patch', patch);
    args.push('--port', String(this.port), '--no-open');
    if (this.opts.trustMode === 'trusted-host') {
      for (const authority of this.opts.trustedHosts ?? []) args.push('--trusted-host', authority);
    }
    const spawnOpts = {
      cwd: this.opts.cwd,
      env: this.opts.env,
      // Own process group: shutdown can signal the whole dsh tree (terminals,
      // subagents), not only the direct child.
      detached: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    };
    if (this.opts.uid !== undefined) {
      spawnOpts.uid = this.opts.uid;
      spawnOpts.gid = this.opts.gid;
    }
    console.log(`[hub] spawning dsh for ${this.user} on 127.0.0.1:${this.port}`);
    const child = spawn(process.execPath, args, spawnOpts);
    this.child = child;
    this.onSpawn?.(this);
    this.log = openLog(this.opts.logPath);
    this.#attachOutput(child);
    child.once('error', (err) => {
      console.error(`[hub] dsh for ${this.user} failed to start:`, err.message);
      this.starting = false;
    });
    child.once('exit', (code, signal) => {
      console.log(`[hub] dsh for ${this.user} exited (code=${code} signal=${signal})`);
      if (this.stdoutLine !== '' && this.log) {
        this.log.write(this.stdoutLine.replace(/token=[^\s&]+/g, 'token=<redacted>'));
      }
      this.stdoutLine = '';
      this.log?.end();
      this.log = null;
      this.onExit?.(this);
    });
    await waitTcp(this.port, this.opts.spawnTimeoutMs ?? 60_000);
    this.lastActivity = Date.now();
    this.onStarted?.(this);
    return this;
  }

  /** Capture the launch token and forward (redacted) output to the log. */
  #attachOutput(child) {
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      if (!this.launchToken) {
        this.stdoutTail = (this.stdoutTail + chunk).slice(-8192);
        const line = /dsh web:\s+(\S+)/.exec(this.stdoutTail);
        if (line) {
          try {
            const token = new URL(line[1]).searchParams.get('token');
            if (token) this.setLaunchToken(token);
          } catch { /* URL not fully written yet — keep buffering */ }
        }
      }
      if (!this.log) return;
      this.stdoutLine += chunk;
      const lines = this.stdoutLine.split('\n');
      this.stdoutLine = lines.pop();
      for (const line of lines) {
        this.log.write(`${line.replace(/token=[^\s&]+/g, 'token=<redacted>')}\n`);
      }
    });
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk) => {
      if (this.log) this.log.write(chunk);
    });
    if (!this.log) {
      child.stdout.resume();
      child.stderr.resume();
    }
  }

  /** Record a launch token parsed from stdout and wake any waiters. */
  setLaunchToken(token) {
    this.launchToken = token;
    for (const resolve of this.launchTokenWaiters.splice(0)) resolve(true);
  }

  /** Resolve true once the process printed its launch token, false after timeoutMs. */
  waitLaunchToken(timeoutMs) {
    if (this.launchToken) return Promise.resolve(true);
    if (this.launchTokenUnavailable) return Promise.resolve(false);
    return new Promise((resolve) => {
      const waiter = (ok) => { clearTimeout(timer); resolve(ok); };
      const timer = setTimeout(() => {
        this.launchTokenUnavailable = true;
        this.launchTokenWaiters = this.launchTokenWaiters.filter((w) => w !== waiter);
        console.warn(`[hub] ${this.user}: dsh did not print its "dsh web: <url>?token=..." line; `
          + 'index requests cannot be bridged and dsh will refuse them');
        resolve(false);
      }, timeoutMs);
      this.launchTokenWaiters.push(waiter);
    });
  }

  touch() {
    this.lastActivity = Date.now();
  }

  /** Signal the instance's whole process group, falling back to the child. */
  kill(signal) {
    if (!this.child || this.child.exitCode !== null) return;
    try {
      process.kill(-this.child.pid, signal); // detached spawn ⇒ negative pid = its group
    } catch {
      try { this.child.kill(signal); } catch { /* already gone */ }
    }
  }

  /** SIGTERM, then SIGKILL after the grace period. */
  stop() {
    this.kill('SIGTERM');
    setTimeout(() => this.kill('SIGKILL'), 5000).unref();
  }
}

/**
 * Start the idle culler. `getInstances()` returns the instances to consider;
 * an instance that is starting, has an attached event stream, or is pinned by
 * keep-alive is never reaped.
 * @returns the interval, or null when culling is disabled.
 */
export function startCuller(getInstances, { idleCullMs, cullIntervalMs }) {
  if (!(idleCullMs > 0)) return null;
  return setInterval(() => {
    const now = Date.now();
    for (const be of getInstances()) {
      if (be.starting) continue;        // a spawn in flight is work, not idleness
      if (be.wsClients > 0) continue;   // a live event stream keeps the instance
      if (be.keepAlive) continue;       // the user pinned this instance from the web UI
      if (now - be.lastActivity > idleCullMs) {
        console.log(`[hub] culling dsh for ${be.user} (port ${be.port})`);
        be.stop();
      }
    }
  }, cullIntervalMs).unref();
}
