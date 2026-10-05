# dsh-hub

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%E2%89%A520-green.svg)](https://nodejs.org)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)](#)
[![dsh](https://img.shields.io/badge/works%20with-DeepSeek%20Harness%20(dsh)-8A2BE2.svg)](https://github.com/deepseek-ai/deepseek-harness)

A [JupyterHub](https://jupyterhub.readthedocs.io)-style multi-user front for
[DeepSeek Harness (dsh)](https://github.com/deepseek-ai/deepseek-harness) —
PAM login, one isolated dsh instance per system user, and a cookie-routed
HTTP/WebSocket proxy. **Zero modifications to dsh**: upstream upgrades and
per-user plugin installs keep working.

> **中文简介**:[dsh-hub](README.md) 是 [DeepSeek Harness (dsh)](https://github.com/deepseek-ai/deepseek-harness) 的多用户网关,思路完全对标
> JupyterHub:服务器系统账号(PAM)登录,每个用户一个完全隔离的 dsh 实例
> (独立 uid/gid、独立数据目录、iptables 端口防护),浏览器直接访问
> `http://<服务器IP>:3080` 即可使用。**不修改 dsh 任何代码**——上游升级、
> 每用户自行安装插件均不受影响。

```
browser ──http://<server-ip>:3080──▶ dsh-hub ──cookie──▶ 127.0.0.1:<port> ──▶ dsh (user A)
                                        │                127.0.0.1:<port> ──▶ dsh (user B)
                                        └─ spawn as uid/gid + iptables owner-guard
```

## Architecture (the JupyterHub analogy)

| JupyterHub | dsh-hub |
|---|---|
| Authenticator (PAM) | PAM via `authenticate-pam` (optional) with a `su`-based fallback; HMAC-signed session cookie |
| Spawner | `dsh web --port <random>` spawned with the user's uid/gid and a per-user `DSH_HOME` |
| Configurable HTTP proxy | `http-proxy` routes HTTP + WebSocket by session cookie |
| Idle culler (jupyterhub-idle-culler) | built-in culler, `IDLE_CULL_MS` (0 = never, tmux-style always-on) |
| Single-user server trusts the hub | loopback proxying with SameSite-cookie CSRF protection (JupyterHub's trust split) |

### Trust model

dsh's web server enforces a browser trust fence (`Origin`/`Host` authority
checks) against DNS-rebinding and CSRF. dsh-hub's proxy (default
`TRUST_MODE=origin-rewrite`) presents itself as a loopback same-origin client:
Host and Origin are rewritten to the backend's loopback authority, and
cross-site protection is carried by the hub's `SameSite=Lax` session cookie —
the same trust split JupyterHub uses between its proxy and single-user servers.

`TRUST_MODE=trusted-host` spawns instances with dsh's official
`--trusted-host` flag and forwards Host/Origin untouched. Note: as of current
dsh, the RPC host empties `trustedHosts` for loopback-authority `/api`
channels, so this mode only works when the fence actually consumes the flag
(direct LAN binds). It is kept for future upstream support of proxied
deployments.

### Insecure-context polyfill

Browsers only expose `crypto.randomUUID()` in secure contexts (HTTPS or
localhost). On bare `http://<server-ip>:3080`, dsh-hub injects a self-guarding
v4-UUID polyfill into every proxied HTML page (a no-op once dsh fixes its
remaining direct call or you serve over HTTPS).

### Remote settings (the isLoopback gate)

dsh's settings/credentials plane (the Settings → Models page) is browser-gated
to loopback pages: `connection.isLoopback` is derived from `location.hostname`,
so a LAN-hostname page reports `settings are unavailable in this browser` even
though the hub's origin-rewrite already passes the server-side loopback fence.
The flag also chooses the settings mirror's persistence (`host` on loopback,
`memory` elsewhere), and in `memory` mode the Models store never reads the
provider catalog. dsh-hub injects the transport hook dsh's connection client
already honors:

```js
window.__DSH_TRANSPORT__ = Object.assign({}, window.__DSH_TRANSPORT__, { ownsHost: true })
```

so `isLoopback` is true before the client looks at the hostname. The hook
carries no `rpc`/`fetch`/`openStream`, so the connection RPC caller falls back to
the page's global fetch, and no cordis service is rewritten. (Patching the
served plugin bundle does not work: the shell loads plugins through combo URLs —
`/plugins/??<id>/client.js,…&rev=…` — not the `*.js?rev=` chunk URLs a text patch
could target.) Trust stays with the hub: only PAM-authenticated users reach the
backend at all, and the SameSite=Lax session cookie still blocks cross-site
requests.

### Browser-session bridge (dsh's own auth)

Since dsh 0.2.0-rc, `dsh web` has its own browser auth on top of the hub's PAM
session: the index and every `/api` route require a signed `dsh-auth-*` cookie
that dsh mints **only** from the per-process `?token=` URL it prints once at
startup (`dsh web: http://127.0.0.1:<port>/?token=…`). The hub's cookie means
nothing to dsh, so a PAM login used to land on `401 dsh web authentication
required; reopen the URL printed by dsh web.`

dsh-hub bridges the two: it captures that token from the backend's stdout and
performs the exchange itself — one loopback `GET /?token=…` with the authority
the proxied browser request will present — then relays dsh's `Set-Cookie` to the
browser and redirects to the clean index. A stale cookie that dsh rejects is
re-minted on the 401. The token never reaches the browser, the URL bar stays
clean, and dsh is not modified. If upstream ever stops printing the token line,
the hub logs a warning and passes dsh's own 401 through unchanged.

## Isolation guarantees (run as root)

- Each dsh instance runs as the user's own **uid/gid** with `DSH_HOME=~/.dsh`
- Instances bind `127.0.0.1:<random port>`; an **iptables owner-guard**
  (loopback, `--uid-owner`) DROPs connections from other local users
- Login rate-limiting (5 failures → 1 min lockout per IP)
- Optional `ALLOW_USERS` allow-list

## Quick start

```bash
git clone https://github.com/Mpaperlee/dsh-hub.git /opt/dsh-hub
cd /opt/dsh-hub && npm install

# dev run (no root: no setuid/iptables, single-user semantics)
DSH_BIN=/path/to/deepseek-harness/apps/cli/lib/bin.js HUB_PORT=3080 \
  HUB_LOG_DIR=/tmp npm start
```

Production (root, systemd):

```bash
sudo cp dsh-hub.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now dsh-hub
```

Users browse to `http://<server-ip>:3080`, log in with their **system
username/password**, and get a private dsh instance.

## Configuration

| Env | Default | Meaning |
|---|---|---|
| `DSH_BIN` | *(required)* | dsh CLI entry (built checkout: `apps/cli/lib/bin.js`) |
| `HUB_HOST` / `HUB_PORT` | `0.0.0.0` / `3080` | hub listen address |
| `TRUST_MODE` | `origin-rewrite` | `trusted-host` forwards Host/Origin untouched (see trust model above) |
| `TRUSTED_HOSTS` | auto (LAN IPv4s) | extra authorities for `--trusted-host` (hostnames/DNS names) |
| `IDLE_CULL_MS` | `14400000` (4h) | `0` disables culling — backends keep running with the browser closed |
| `SESSION_TTL_MS` | 7 days | cookie lifetime |
| `ALLOW_USERS` | *(all)* | comma-separated username allow-list |
| `HUB_LOG_DIR` | `/var/log/dsh-hub` | per-user backend logs |
| `COOKIE_SECRET_FILE` | `$CWD/.cookie-secret` | HMAC secret (auto-generated, `0600`) |
| `HUB_CLEAN_ON_STOP` | `1` | on `SIGTERM`/`SIGINT`/`SIGHUP`, stop instances and delete `$CWD/cache` + the cookie secret; `0` keeps them |
| `SHUTDOWN_GRACE_MS` | `5000` | how long a backend may take to exit before it is `SIGKILL`ed |

## Notes

- A cold instance never holds a navigation open: the first request after login
  gets a static loading page (auto-refresh every 3 s, "首次加载可能需要等待几十秒")
  while the spawn runs in the background, then the page reloads into the app.
  Non-index requests during startup get `503` + `Retry-After: 3` instead of
  blocking, and a spawn failure surfaces as `dsh-hub: 无法启动你的实例`.
- Runtime state lives in the **working directory the hub is started from**
  (`WorkingDirectory` under systemd), never in the checkout: the HMAC secret at
  `$CWD/.cookie-secret` and the persisted `session.list` cache under
  `$CWD/cache/`. Point a service at a writable data directory and the source
  tree can stay read-only.
- On `SIGTERM`/`SIGINT`/`SIGHUP` the hub stops every spawned dsh instance (their
  whole process group, `SIGTERM` then `SIGKILL` after `SHUTDOWN_GRACE_MS`),
  releases their loopback guards, and deletes the persisted cache and the cookie
  secret — so a stopped hub leaves no running instances and no reusable session
  material behind. Cleanup is bounded and best-effort; a second signal exits
  immediately. Set `HUB_CLEAN_ON_STOP=0` to keep the cache and secret across
  restarts.
- Conversations survive browser close: goal/server-side drivers keep running
  in the spawned dsh process; re-login reattaches to the same instance.
- `sudo systemctl restart dsh-hub` after config changes.
- Non-root runs are degraded (dev) mode: no setuid spawn, no iptables guard.

## License

MIT
