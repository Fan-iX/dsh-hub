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
browser -- http://<server-ip>:3080 --> dsh-hub -- cookie --> 127.0.0.1:<port> --> dsh (user A)
                                          |                  127.0.0.1:<port> --> dsh (user B)
                                          `- spawn as uid/gid + iptables owner-guard
```
## Quick start

```bash
git clone https://github.com/Mpaperlee/dsh-hub.git /opt/dsh-hub
cd /opt/dsh-hub && npm install
# optional: install `@deepseek-ai/dsh` within the same repo
npm install @deepseek-ai/dsh
# or globally
sudo npm install -g @deepseek-ai/dsh

# dev run (no root: no setuid/iptables, single-user semantics)
DSH_BIN=/path/to/dsh HUB_PORT=3080 HUB_LOG_DIR=/tmp npm start
```

Production (root) — install the unit that matches your init system.

systemd:

```bash
sudo cp dsh-hub.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now dsh-hub
```

OpenRC:

```bash
sudo install -m 0755 dsh-hub.openrc.service /etc/init.d/dsh-hub
sudo rc-update add dsh-hub default
sudo rc-service dsh-hub start
```

sysvinit:

```bash
sudo install -m 0755 dsh-hub.sysvinit.service /etc/init.d/dsh-hub
sudo update-rc.d dsh-hub defaults   # Debian/Ubuntu
sudo chkconfig --add dsh-hub        # RHEL/CentOS
sudo service dsh-hub start
```

All three start the hub as root from `/var/lib/dsh-hub` — the working directory
that holds the cookie secret and the session cache — and accept the
[configuration](#configuration) environment variables. The hub's own defaults
(`HUB_PORT=3080`, `HUB_LOG_DIR=/var/log/dsh-hub`) apply unless you override them
in the init-system config file: `/etc/conf.d/dsh-hub` (OpenRC) or
`/etc/default/dsh-hub` / `/etc/sysconfig/dsh-hub` (sysvinit). Those files also
honour `DSH_HUB_DIR`, `DSH_HUB_DATA_DIR`, `DSH_HUB_PIDFILE` and `NODE_BINARY`.
`openrc-run` and sysvinit pass on **exported** variables only:

```sh
# /etc/conf.d/dsh-hub  ·  /etc/default/dsh-hub
export HUB_PORT=3080
export HUB_LOG_DIR=/var/log/dsh-hub
export IDLE_CULL_MS=0           # 0 = never cull idle backends
```

Users browse to `http://<server-ip>:3080`, log in with their **system
username/password**, and get a private dsh instance.

## Configuration

| Env | Default | Meaning |
|---|---|---|
| `DSH_BIN` | `$DSH_HUB_DIR/node_modules/.bin/dsh` | dsh CLI entry |
| `HUB_HOST` / `HUB_PORT` | `0.0.0.0` / `3080` | hub listen address |
| `TRUST_MODE` | `origin-rewrite` | `trusted-host` forwards Host/Origin untouched (see trust model above) |
| `TRUSTED_HOSTS` | auto (LAN IPv4s) | extra authorities for `--trusted-host` (hostnames/DNS names) |
| `IDLE_CULL_MS` | `14400000` (4h) | `0` disables culling — backends keep running with the browser closed |
| `CULL_INTERVAL_MS` | `60000` (1 min) | how often the culler checks; an attached event stream is never reaped |
| `HIDE_ACCOUNT_UI` | `1` | hide the DeepSeek account sign-in UI in hub-spawned instances (its PKCE callback must be loopback); `0` shows it |
| `SESSION_TTL_MS` | 7 days | cookie lifetime |
| `ALLOW_USERS` | *(all)* | comma-separated username allow-list |
| `HUB_LOG_DIR` | `/var/log/dsh-hub` | per-user backend logs |
| `COOKIE_SECRET_FILE` | `$CWD/.cookie-secret` | HMAC secret (auto-generated, `0600`) |
| `HUB_CLEAN_ON_STOP` | `1` | on `SIGTERM`/`SIGINT`/`SIGHUP`, stop instances and delete `$CWD/cache` + the cookie secret; `0` keeps them |
| `SHUTDOWN_GRACE_MS` | `5000` | how long a backend may take to exit before it is `SIGKILL`ed |
| `AUTH_WINDOW_MS` | `600000` (10 min) | sliding window for failed logins per client IP |
| `AUTH_MAX_FAILURES` | `5` | failures within the window before `/hub/login` answers `429` |
| `TRUSTED_PROXIES` | *(none)* | comma-separated IPs/CIDRs whose `X-Forwarded-For` / `X-Real-IP` is trusted |
| `HUB_AUTH_LOG` | `<HUB_LOG_DIR>/auth.log` | append-only authentication audit log (`0600`) |

## Architecture (the JupyterHub analogy)

| JupyterHub | dsh-hub |
|---|---|
| Authenticator (PAM) | PAM via `node-linux-pam` (optional) with a `su`-based fallback; HMAC-signed session cookie |
| Spawner | `dsh web --port <random>` spawned with the user's uid/gid and a per-user `DSH_HOME` |
| Configurable HTTP proxy | `http-proxy` routes HTTP + WebSocket by session cookie |
| Idle culler (jupyterhub-idle-culler) | built-in culler, `IDLE_CULL_MS` (0 = never, tmux-style always-on) |
| Single-user server trusts the hub | loopback proxying with SameSite-cookie CSRF protection (JupyterHub's trust split) |

### Source layout

`src/index.mjs` is only the composition root (wiring and startup logs); the rest
is split by responsibility:

| File | Responsibility |
|---|---|
| `index.mjs` | composition root: build the server, register signal handling, listen |
| `config.mjs` | environment → `CFG`, runtime paths (`SECRET_PATH`, `CACHE_DIR`, `AUTH_LOG_FILE`), trust mode, dsh binary detection |
| `server.mjs` | HTTP server plus the WebSocket upgrade path routed by session cookie |
| `router.mjs` | request gate, cold-start page, session-list interception, backend bridging and proxying |
| `auth.mjs` | session cookies, client-IP resolution, sliding-window guard, audit log, PAM verification, login/logout |
| `users.mjs` | cached `getent passwd` lookup |
| `http.mjs` | shared response and request-body helpers |
| `i18n.mjs` | zh/en dictionaries and request locale resolution |
| `pages.mjs` + `pages/*.html` + `pages/theme.css` | dsh-hub's own login and cold-start pages: real HTML templates, dsh-themed CSS, `{{key}}` i18n placeholders |
| `backends.mjs` | per-user spawn/stop, iptables loopback guards, backend logs, idle culler |
| `dsh-patch.mjs` | the `--patch` overlay that hides the DeepSeek account UI in spawned instances |
| `keepalive.mjs` | `GET`/`POST /hub/api/keepalive`: opt the current instance out of idle culling from the web UI |
| `browser-session.mjs` | dsh launch-token capture and the `dsh-auth-*` cookie bridge |
| `session-list-cache.mjs` | serve-stale `/api/session/list` cache |
| `proxy.mjs` | `http-proxy` instance, HTML injections, dsh `401` bridge |
| `shutdown.mjs` | signal teardown: kill instances, remove cache and cookie secret, exit |

### Bilingual pages

The hub's own pages (login and cold-start) render in Chinese or English, styled
after dsh's web UI tokens. The locale is resolved per request: an explicit
`?lang=zh|en`, then the `dshhub_lang` cookie it persists, then the browser's
`Accept-Language`, then Chinese. The login page exposes the choice as a
`中文 / English` switcher, and each response carries `Content-Language` plus
`Vary: Accept-Language`. Rendering happens on the server, so the cold-start page
stays a static, script-free document.

### DeepSeek account sign-in

dsh 0.2.1+ ships a DeepSeek account sign-in button (OAuth authorization code +
PKCE S256). Its flow validates the browser callback origin with `loginOrigin()`,
which accepts **only loopback HTTP** (`http://localhost|127.0.0.1|[::1]:<port>`) —
a deliberate RFC 8252 guard. A hub served on a LAN hostname can never satisfy
it, so the button cannot work there; only a loopback hub URL (local or
`ssh -L 3080:127.0.0.1:3080`) or a manually launched `dsh` can sign in.

Hub-spawned instances therefore hide the account UI by default: the hub writes a
`--patch` overlay (`<HUB_CWD>/hub-no-account-ui.patch.yml`) that disables the
`ui-settings-account` plugin, and passes it to the dsh it spawns. The user's own
`$DSH_HOME/cordis.patch.yml` is untouched, so a manually launched dsh keeps the
button; because both share `DSH_HOME=~/.dsh`, a grant obtained there is reused by
the hub instance (and the `deepseek-account` model provider keeps working).
Set `HIDE_ACCOUNT_UI=0` to show the button again — sensible only when every
browser reaches the hub over loopback.

### Idle culling vs. long-running work

The culler reaps a backend only after `IDLE_CULL_MS` without activity, and
activity means real traffic to that instance: every proxied HTTP request, every
byte of a streaming response, and every frame of the WebSocket event stream
refresh it. A backend with an **attached event stream is never reaped**, so a
long agent turn — including one blocked on a background job — cannot be
terminated while a browser is watching it. A spawn in flight is never reaped
either, and the idle clock restarts when the last stream detaches.

What the hub cannot see is work that outlives the browser (a goal or background
job still running after the client disconnects): dsh exposes no cheap "still
busy" query, so such an instance is still reaped after `IDLE_CULL_MS`. Set
`IDLE_CULL_MS=0` to keep every instance alive until it is stopped.

### Keep-alive from the web UI

The `dsh-hub-utils` plugin adds a **dsh-hub** button at the sidebar foot whose
panel carries the keep-alive switch (alongside a quit action), covering exactly
the browser-closed case above. The switch talks to two small hub routes,
authenticated by the normal hub session cookie and accepting only
`application/json` (the `SameSite=Lax` cookie plus the JSON content type is the
CSRF guard):

| Route | Body | Response |
|---|---|---|
| `GET /hub/api/keepalive` | — | `{"keepAlive":boolean,"running":boolean}` |
| `POST /hub/api/keepalive` | `{"keepAlive":boolean}` | the same JSON |

The flag lives on the per-user backend object: the culler skips a pinned
instance, and the flag resets when the instance is replaced (restart, crash,
hub restart). Nothing else in the hub changes — no dsh patch, no new process, no
persisted state.

The plugin is hub-only, and the hub marks its own pages so it can tell: the
proxied index carries `window.__DSH_HUB__={version:1}` (injected next to the
transport hook), and a spawned backend gets `DSH_HUB=1` in its environment. The
plugin registers its sidebar action and quit route only when those markers are
present, so a bare `dsh web` shows no button and exposes no extra route.

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

### Login guard and audit log

`/hub/login` counts failed attempts per client IP in a **sliding window**
(`AUTH_MAX_FAILURES` within `AUTH_WINDOW_MS`); reaching it answers `429` with
`Retry-After` until the oldest counted failure ages out. Client addresses are
canonicalized (zone ids, brackets, ports, IPv4-mapped IPv6, IPv6 spelling), and
`X-Forwarded-For` / `X-Real-IP` are honored **only** when the TCP peer is listed
in `TRUSTED_PROXIES`; otherwise the peer address is authoritative, and the
rightmost untrusted hop wins — a client cannot move the limit onto another
address.

Every outcome is appended to `HUB_AUTH_LOG` (default `<HUB_LOG_DIR>/auth.log`,
mode `0600`) as one line with the client IP last:

```text
2026-10-05T08:00:00.000Z [auth] login ok user=alice ip=10.0.0.5
2026-10-05T08:00:03.000Z [auth] login failed user=bob reason=auth-failed ip=10.0.0.9
2026-10-05T08:00:04.000Z [auth] login blocked ip=10.0.0.9 retry_after=587s
```

That lets an external log-driven banner (fail2ban/sshguard) filter `ip=<HOST>`
and apply the actual ban; the hub keeps no ban list. If the file cannot be
opened, lines fall back to stdout/journald.

## Isolation guarantees (run as root)

- Each dsh instance runs as the user's own **uid/gid** with `DSH_HOME=~/.dsh`
- Instances bind `127.0.0.1:<random port>`; an **iptables owner-guard**
  (loopback, `--uid-owner`) DROPs connections from other local users
- Login guard: sliding window of failed attempts per client IP
  (`AUTH_MAX_FAILURES` / `AUTH_WINDOW_MS`) plus a fail2ban-friendly audit log
- Optional `ALLOW_USERS` allow-list

## Notes

- A cold instance never holds a navigation open: the first request after login
  gets a static loading page (auto-refresh every 3 s)   while the spawn runs in
  the background, then the page reloads into the app.
  Non-index requests during startup get `503` + `Retry-After: 3` instead of
  blocking, and a spawn failure surfaces as `dsh-hub: fail to lauch dsh`.
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
- Restart after config changes: `sudo systemctl restart dsh-hub` (systemd),
  `sudo rc-service dsh-hub restart` (OpenRC), `sudo service dsh-hub restart`
  (sysvinit).
- Non-root runs are degraded (dev) mode: no setuid spawn, no iptables guard.

## License

MIT
