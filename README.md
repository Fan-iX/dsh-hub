# dsh-hub

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%E2%89%A522-green.svg)](https://nodejs.org)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)](#)
[![dsh](https://img.shields.io/badge/works%20with-DeepSeek%20Harness%20(dsh)-8A2BE2.svg)](https://github.com/deepseek-ai/deepseek-harness)

dsh-hub puts [DeepSeek Harness (dsh)](https://github.com/deepseek-ai/deepseek-harness)
behind an authenticated HTTP/WebSocket front. dsh itself has no login and binds
only to loopback; dsh-hub supplies both, without modifying dsh.

There are two entry points, sharing the same login page, session cookie, proxy
pipeline, page hooks, instance lifecycle, idle culler, and keep-alive/quit
integration:

- **Multi-user hub** (`src/hub/index.mjs`, runs as root): PAM login for system
  accounts, one dsh instance per user as that user's uid/gid, per-user
  `DSH_HOME` and logs, and iptables loopback owner guards.
- **Single-user proxy** (`src/proxy/index.mjs`, runs as an ordinary account):
  the same username/password login page, accepting only the account that runs
  the proxy; one dsh instance is spawned and managed as that account. There is
  no setuid and no iptables guard.

> **中文简介**: dsh-hub 给没有认证、只监听 loopback 的 DeepSeek Harness
> 加上登录和反向代理。多用户 hub 以 root 运行，用系统账号(PAM)登录，每个用户
> 一个独立 uid/gid 的 dsh 实例；单用户 proxy 以普通账号运行，只接受该账号
> 登录，管理一个 dsh 实例。两者共用登录页、会话、代理、冷启动、culler 和
> keepalive/quit 集成，且都不修改 dsh。

```
multi-user hub (root):
  browser -- http://<server-ip>:3080 --> dsh-hub -- cookie --> 127.0.0.1:<port> --> dsh (user A)
                                            |                  127.0.0.1:<port> --> dsh (user B)
                                            `- spawn as uid/gid + iptables owner-guard

single-user proxy (ordinary account):
  browser -- http://<server-ip>:3080 --> dsh-hub-proxy -- cookie --> 127.0.0.1:<port> --> dsh (that account)
```

## Quick start

```bash
git clone https://github.com/Mpaperlee/dsh-hub.git /opt/dsh-hub
cd /opt/dsh-hub && npm install
# optional: install dsh locally in the same repo
npm install @deepseek-ai/dsh
# or globally
sudo npm install -g @deepseek-ai/dsh
```

### Multi-user hub

Run as root; install the unit that matches your init system.

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

The installed units start the hub as root from `/var/lib/dsh-hub` — the working
directory that holds the session cache — and accept the
[configuration](#configuration) environment variables. The defaults
(`HUB_PORT=3080`, `HUB_LOG_DIR=/var/log/dsh-hub`) apply unless overridden in
`/etc/conf.d/dsh-hub` (OpenRC) or `/etc/default/dsh-hub` /
`/etc/sysconfig/dsh-hub` (sysvinit). Those files also honour `DSH_HUB_DIR`,
`DSH_HUB_DATA_DIR`, `DSH_HUB_PIDFILE` and `NODE_BINARY`. `openrc-run` and
sysvinit pass on **exported** variables only:

```sh
# /etc/conf.d/dsh-hub  ·  /etc/default/dsh-hub
export HUB_PORT=3080
export HUB_LOG_DIR=/var/log/dsh-hub
export IDLE_CULL_MS=0           # 0 = never cull idle instances
```

Users browse to `http://<server-ip>:3080`, log in with their **system
username/password**, and get a private dsh instance.

### Single-user proxy

Run as the account that should own the dsh instance:

```bash
cd /opt/dsh-hub
node src/proxy/index.mjs
```

The login page accepts that account's **system username and password**. With
defaults it listens on `0.0.0.0:3080`, spawns one dsh as the same user, and
writes its log under `$XDG_STATE_HOME/dsh-hub` (or
`~/.local/state/dsh-hub`). Configure it with the
[proxy variables](#configuration), for example:

```bash
HUB_PORT=3080 \
DSH_HOME=$HOME/.dsh \
HUB_WORKSPACE=$HOME/projects \
HUB_LOG_DIR=$HOME/.local/state/dsh-hub \
node src/proxy/index.mjs
```

The proxy is normally run from a systemd user unit
(`systemctl --user`, `Restart=on-failure`) or the corresponding OpenRC user
service, so the service manager can restart it; dsh is its child and is stopped
with it.

## Configuration

### Shared

| Env | Default | Meaning |
|---|---|---|
| `DSH_BIN` | repo `node_modules/.bin/dsh`, then `/usr/local/bin/dsh`, `/usr/bin/dsh` | dsh CLI entry |
| `HUB_HOST` / `HUB_PORT` | `0.0.0.0` / `3080` | listen address |
| `TRUST_MODE` | `origin-rewrite` | `trusted-host` forwards Host/Origin untouched (see [Trust model](#trust-model)) |
| `TRUSTED_HOSTS` | auto (LAN IPv4s) | extra authorities for `--trusted-host` |
| `SESSION_TTL_MS` | `86400000` (1 day) | session cookie lifetime |
| `IDLE_CULL_MS` | `14400000` (4 h) | `0` disables idle culling |
| `CULL_INTERVAL_MS` | `60000` (1 min) | how often the culler checks |
| `SPAWN_TIMEOUT_MS` | `60000` | how long to wait for a spawned dsh to accept TCP |
| `SHUTDOWN_GRACE_MS` | `5000` | grace before a stopping dsh is `SIGKILL`ed |
| `AUTH_WINDOW_MS` | `600000` (10 min) | sliding window for failed logins per client IP |
| `AUTH_MAX_FAILURES` | `5` | failures within the window before `/hub/login` answers `429` |
| `AUTH_DECOY_USER` | `nobody` | existing account whose PAM check equalizes unknown-username timing |
| `TRUSTED_PROXIES` | *(none)* | comma-separated IPs/CIDRs whose `X-Forwarded-For` / `X-Real-IP` is trusted |

### Multi-user hub

| Env | Default | Meaning |
|---|---|---|
| `HUB_LOG_DIR` | `/var/log/dsh-hub` | per-user dsh logs; also the default audit-log directory |
| `HUB_AUTH_LOG` | `<HUB_LOG_DIR>/auth.log` | append-only authentication audit log (`0600`) |
| `HUB_CLEAN_ON_STOP` | `1` | on stop, delete `$CWD/cache`; `0` keeps the session-list cache |
| `HUB_WEB_CONFIG_DIR` | `/etc/dsh-hub/web_config.d` | `*.yml` drop-ins applied as `--patch` to spawned instances, in file-name order |
| `ALLOW_USERS` | *(all)* | comma-separated username allow-list |
| `ALLOW_NOPASSWD` | `0` | allow an account whose shadow entry has no usable password to receive a session |
| `FINGERPRINT_TTL_MS` | `60000` | how often a cached shadow fingerprint is re-read (local `/etc/shadow` changes also force a refresh) |

### Single-user proxy

| Env | Default | Meaning |
|---|---|---|
| `DSH_HOME` | `~/.dsh` | data root of the spawned instance |
| `HUB_WORKSPACE` | `~/.dsh/hub-default-workspace`, then `$HOME` | working directory of the spawned dsh |
| `HUB_LOG_DIR` | `$XDG_STATE_HOME/dsh-hub` or `~/.local/state/dsh-hub` | directory for `dsh.log` (`0600`, launch token redacted) |
| `HUB_AUTH_LOG` | `$XDG_STATE_HOME/dsh-hub/auth.log` or `~/.local/state/dsh-hub/auth.log` | authentication audit log (`0600`) |

## Architecture

Both entry points run the same pipeline:

1. `/hub/login` verifies a username/password through the mode's `verify` hook
   and signs a session cookie with the mode's `keyFor` hook.
2. An authenticated navigation lazily spawns (or attaches to) the dsh instance,
   or answers with the static cold-start page while the spawn runs.
3. The first index navigation exchanges dsh's launch token for dsh's own
   `dsh-auth-*` cookie (see [Browser-session bridge](#browser-session-bridge)).
4. HTTP and WebSocket traffic is proxied to `127.0.0.1:<port>`, with the page
   hooks and dsh's own 401 handled by the shared proxy.
5. The idle culler stops an instance after `IDLE_CULL_MS` without activity; an
   attached event stream or the keep-alive switch prevents that.

The hub keeps a `Map<user, instance>`, spawns with the user's uid/gid, and adds
the iptables guard. The proxy keeps one instance, spawned as the service user.

### Source layout

`src/backend/` is the shared layer, `src/hub/` is the multi-user entry and its
policies, and `src/proxy/` is the single-user entry. `src/index.mjs` is the
installed-service entry and loads the multi-user hub.

| Path | Responsibility |
|---|---|
| `src/backend/config.mjs` | shared environment, paths, trust mode, dsh discovery |
| `src/backend/web.mjs` | HTTP helpers, zh/en dictionaries, login/cold-start pages, keep-alive route |
| `src/backend/auth.mjs` | login/guard/audit/session flow, PAM, system-account lookup |
| `src/backend/dsh-proxy.mjs` | `http-proxy`, HTML hooks, dsh browser-session bridge |
| `src/backend/instance.mjs` | one dsh process: spawn/ready/token/stop, logs, idle culler |
| `src/backend/pages/` | login and cold-start HTML templates plus the shared stylesheet |
| `src/hub/index.mjs` | multi-user composition root and startup logs |
| `src/hub/config.mjs` | root-only configuration (iptables, spawn, cache, overlays) |
| `src/hub/accounts.mjs` | PAM + shadow fingerprint, no-password/allow-list policy, per-user cookie key |
| `src/hub/instances.mjs` | per-user instance map, uid/gid spawn, iptables guards, culler wiring |
| `src/hub/server.mjs` | HTTP/WebSocket server, request gate, cold start, session-list cache, forwarding |
| `src/hub/session-list-cache.mjs` | serve-stale `/api/session/list` cache |
| `src/hub/web-config.mjs` | admin `web_config.d` overlay list |
| `src/hub/shutdown.mjs` | stop instances, release guards, remove cache |
| `src/proxy/index.mjs` | single-user composition root |
| `src/proxy/config.mjs` | service account, dsh home/workspace, user log paths |
| `src/proxy/auth.mjs` | service-account-only PAM check and in-memory cookie key |
| `src/proxy/server.mjs` | single-instance HTTP/WebSocket server and cold start |

## Authentication and sessions

Both modes render the same login form (username, password, language switcher)
and use the same sliding-window guard and audit log.

- **Hub**: the username must be an existing system account and the password is
  verified through PAM. The verifier tries the native `node-linux-pam` module
  first (in-process, any account); when PAM reports that it cannot verify in this
  context (e.g. `PAM_AUTHINFO_UNAVAIL`), it falls back to `su` on a
  pseudo-terminal through `node-pty` (works where `su` only reads a terminal),
  then to `su` with the password on stdin. A wrong password (`PAM_AUTH_ERR`)
  never falls through to `su`. `su` runs as `nobody`, so it asks for the target
  account's password instead of letting root bypass the check. The cookie key is
  derived from the account's shadow entry plus an in-process pepper, so a
  password change, lock, or forced change invalidates that user's existing
  cookies. A shadow entry with no usable password (empty, `!`, `*`, `x`) is
  denied by default (`ALLOW_NOPASSWD=1` overrides). A missing shadow entry is
  denied. No cookie secret is written to disk; a hub restart invalidates all
  sessions.
- **Proxy**: the only accepted username is the account running the proxy; the
  same native-PAM-first verifier checks it in-process (the proxy's own account,
  the case non-root PAM usually supports). When PAM cannot verify (e.g.
  `unix_chkpwd` restrictions), it falls back to `su <self>` the same way. The
  cookie key is an in-memory pepper, so a proxy restart logs the browser out. The
  proxy does not read `/etc/shadow` and does not detect a password change until
  the session expires or the proxy restarts.

`node-linux-pam` and `node-pty` are optional dependencies: `npm install` builds
them when the toolchain is present. If your npm blocks install scripts, run
`npm rebuild node-linux-pam node-pty` (the former needs libpam headers) so the
native PAM path is available; without them the verifier uses the `su` fallback,
and logs a warning when neither is usable.

Sessions are `HttpOnly; SameSite=Lax` cookies with `SESSION_TTL_MS` (default one
day). Logout clears the browser cookie; there is no server-side session list or
per-session revocation. Account deletion is picked up within the passwd-cache TTL
(60 s); login and instance spawn force a fresh NSS read.

### NSS lookups

Account existence and the shadow fingerprint go through `getent`, which can block
for seconds when a network backend (SSSD, LDAP, winbind) is unreachable. Both run
as **async children** with a hard 3 s `SIGKILL` timeout and a per-user cache
(single-flight; a stale entry is served while a background refresh runs), so a
slow NSS backend delays only the request that needs the fresh answer — it never
blocks the hub's event loop. A failed background shadow refresh keeps the cached
key and retries after the fingerprint TTL instead of signing everyone out.

A zombie child by itself does not block Node, but unreaped orphans can exhaust
the PID table. If the hub runs in a container, start it under an init (`tini`, or
`docker run --init` / `podman --init`) so NSS and `su` grandchildren are reaped;
under systemd, PID 1 already does this.

### Session expiry response

A request without a valid session is answered by kind:

- a **document navigation** (`GET` with `Sec-Fetch-Dest: document|iframe`, or
  `Accept: text/html`) gets `303 See Other` to `/hub/login`;
- every other request (the SPA's fetches, API calls, static assets) gets `401`
  with `{"error":"unauthenticated"}` and the header
  `x-dsh-hub-login: /hub/login`, so a page-level watcher can navigate without
  parsing an HTML login page.

`GET /hub/api/session` answers
`{"authenticated":true,"user":...,"expiresInSec":N}` for a live session (and is
covered by the same 401 when it is not). The hub-only `dsh-hub-utils` plugin
probes that endpoint on load and on tab activation, then keeps one timer at the
reported deadline; at expiry it reloads the page, which the hub answers with the
login redirect. No fetch wrapping or periodic polling is involved. The hub cannot
force a top-level navigation from a fetch or WebSocket failure, which is why the
redirect lives in the browser plugin rather than in the proxy.

### Login guard and audit log

`/hub/login` counts failed attempts per client IP in a sliding window
(`AUTH_MAX_FAILURES` within `AUTH_WINDOW_MS`); reaching it answers `429` with
`Retry-After` until the oldest failure ages out. Client addresses are
canonicalized (zone ids, brackets, ports, IPv4-mapped IPv6, IPv6 spelling), and
`X-Forwarded-For` / `X-Real-IP` are honored only when the TCP peer is listed in
`TRUSTED_PROXIES`; otherwise the peer address is authoritative, and the
rightmost untrusted hop wins.

Every outcome is appended to `HUB_AUTH_LOG` (mode `0600`) as one line with the
client IP last:

```text
2026-10-05T08:00:00.000Z [auth] login ok user=alice ip=10.0.0.5
2026-10-05T08:00:03.000Z [auth] login failed user=bob reason=auth-failed ip=10.0.0.9
2026-10-05T08:00:04.000Z [auth] login blocked ip=10.0.0.9 retry_after=587s
```

An external log-driven banner (fail2ban/sshguard) can filter `ip=<HOST>` and
apply the ban; the hub keeps no ban list. If the file cannot be opened, lines
fall back to stdout/journald.

## Instances

- Instances bind `127.0.0.1:<random port>` and run as the target user (hub) or
  the service user (proxy).
- A cold instance never holds a navigation open: the first index request gets a
  static loading page (auto-refresh every 3 s) while the spawn runs in the
  background, then reloads into the app. Other requests during startup get
  `503` + `Retry-After: 3`; a spawn failure surfaces as a `503` page.
- Readiness is checked at the HTTP layer (a no-token `GET /`), not just TCP, so
  a port that accepts connections before dsh's web handler is ready does not
  turn the loading page into a `502`. If a connection error still reaches the
  proxy before the first response, an index request gets the same loading page
  and other requests get `503` with `Retry-After`. After an instance has served
  a response, a connection failure is a real `502`; reloading starts a new
  instance if it exited.
- Idle culling measures real traffic: every proxied request, every byte of a
  streaming response, and every frame of the WebSocket event stream refresh the
  instance. An instance with an attached event stream or the keep-alive switch
  is never reaped; the idle clock restarts when the last stream detaches. Set
  `IDLE_CULL_MS=0` to keep instances until stopped.
- dsh stdout/stderr go to a per-instance log (`0600`); the launch-token line is
  redacted. The hub uses `<HUB_LOG_DIR>/<user>.log`; the proxy uses
  `<HUB_LOG_DIR>/dsh.log`.
- On `SIGTERM`/`SIGINT`/`SIGHUP` the whole dsh process group is stopped
  (`SIGTERM`, then `SIGKILL` after `SHUTDOWN_GRACE_MS`), the hub's loopback
  guards are released, and the hub's persisted cache is removed unless
  `HUB_CLEAN_ON_STOP=0`.

### Keep-alive and quit

The `dsh-hub-utils` plugin adds a **dsh-hub** panel at the sidebar foot with a
keep-alive switch and a quit action. Both modes inject
`window.__DSH_HUB__={version:1}` into proxied pages and set `DSH_HUB=1` in the
spawned dsh environment; the plugin registers its action and quit route only
when those markers are present. A bare `dsh web` shows no button and exposes no
extra route.

The keep-alive switch uses two hub routes, authenticated by the normal session
cookie and accepting only `application/json` (the `SameSite=Lax` cookie plus the
JSON content type is the CSRF guard):

| Route | Body | Response |
|---|---|---|
| `GET /hub/api/keepalive` | — | `{"keepAlive":boolean,"running":boolean}` |
| `POST /hub/api/keepalive` | `{"keepAlive":boolean}` | the same JSON |

The flag lives on the instance and resets when the instance is replaced. The
quit action is the plugin's own route on the dsh side; the proxy forwards it,
the instance exits, and the next authenticated request starts a new one.

## Proxy and page behavior

### Trust model

dsh's web server enforces a browser trust fence (`Origin`/`Host` authority
checks) against DNS rebinding and CSRF. With the default
`TRUST_MODE=origin-rewrite`, dsh-hub presents itself as a loopback same-origin
client: Host and Origin are rewritten to the backend's loopback authority, and
cross-site protection is carried by the `SameSite=Lax` session cookie — the
same trust split JupyterHub uses between its proxy and single-user servers.

`TRUST_MODE=trusted-host` spawns instances with dsh's official `--trusted-host`
flag and forwards Host/Origin untouched. As of current dsh, the RPC host empties
`trustedHosts` for loopback-authority `/api` channels, so that mode works when
the fence actually consumes the flag (direct LAN binds); it is kept for future
upstream support of proxied deployments.

### Insecure-context polyfill

Browsers only expose `crypto.randomUUID()` in secure contexts (HTTPS or
localhost). On bare `http://<server-ip>:3080`, dsh-hub injects a self-guarding
v4-UUID polyfill into every proxied HTML page (a no-op once dsh no longer needs
it or the page is served over HTTPS).

### Remote settings (the isLoopback gate)

dsh's settings/credentials plane is browser-gated to loopback pages:
`connection.isLoopback` is derived from `location.hostname`, so a LAN-hostname
page reports `settings are unavailable in this browser` even though the
origin-rewrite already passes the server-side loopback fence. The flag also
chooses the settings mirror's persistence (`host` on loopback, `memory`
elsewhere), and in `memory` mode the Models store never reads the provider
catalog. dsh-hub injects the transport hook dsh's connection client honors:

```js
window.__DSH_TRANSPORT__ = Object.assign({}, window.__DSH_TRANSPORT__, { ownsHost: true })
```

so `isLoopback` is true before the client looks at the hostname. The hook
carries no `rpc`/`fetch`/`openStream`, so the connection RPC caller falls back to
the page's global fetch, and no cordis service is rewritten.

### Browser-session bridge (dsh's own auth)

`dsh web` has its own browser auth on top of the session cookie: the index and
every `/api` route require a signed `dsh-auth-*` cookie that dsh mints only from
the per-process `?token=` URL it prints once at startup
(`dsh web: http://127.0.0.1:<port>/?token=…`).

dsh-hub captures that token from the instance's stdout and performs the exchange
itself — one loopback `GET /?token=…` with the authority the proxied browser
request will present — then relays dsh's `Set-Cookie` to the browser and
redirects to the clean index. A stale cookie that dsh rejects is re-minted on the
401. The token never reaches the browser; the URL bar stays clean; dsh is not
modified. If upstream stops printing the token line, the hub logs a warning and
passes dsh's own 401 through.

### Session-list cache (hub)

The hub serves a stale `/api/session/list` snapshot forever and refreshes it in
the background on a throttle. The cache makes the sidebar instant even when
dsh's projection is slow; it survives hub restarts under `$CWD/cache/`, and a
cache hit never spawns an instance. Only 200 responses whose envelope carries an
`items` array are cached, keyed by user plus request payload.

## Global dsh overlays (hub)

Administrators can layer dsh configuration onto every instance the hub spawns
without touching dsh or the hub: drop `*.yml` (or `*.yaml`) files into
`/etc/dsh-hub/web_config.d` (`HUB_WEB_CONFIG_DIR` overrides the path). Files are
passed to each spawned dsh as `--patch` overlays in file-name order, so prefixes
(`10-`, `20-`) control precedence. The directory is re-read on every spawn; the
startup log lists what was applied.

Global configuration is authoritative: dsh applies `--patch` after
`$DSH_HOME/cordis.patch.yml`, so a drop-in overrides the user's own patch for the
rows it touches. Keep drop-ins narrow and review them before installing. The
files are world-readable and are read by every user's dsh process; never put
secrets in them — per-user secrets belong in that user's
`~/.dsh/cordis.patch.yml` (`0600`). Keep the directory `0755` and files `0644`;
a file the spawned user cannot read is skipped with a warning.

A malformed drop-in breaks every spawn, so validate one before installing it:

```bash
dsh --profile web --patch /etc/dsh-hub/web_config.d/20-mine.patch.yml --dump-config
```

The proxy does not read `web_config.d`; its dsh uses the service user's own
`~/.dsh/cordis.patch.yml`.

## DeepSeek account sign-in

dsh 0.2.1+ ships a DeepSeek account sign-in button (OAuth authorization code +
PKCE S256). Its flow validates the browser callback origin with `loginOrigin()`,
which accepts only loopback HTTP (`http://localhost|127.0.0.1|[::1]:<port>`) — a
deliberate RFC 8252 guard. A hub or proxy served on a LAN hostname cannot satisfy
it, so the button cannot work there; only a loopback URL (local or
`ssh -L 3080:127.0.0.1:3080`) can sign in. A LAN-only deployment can hide the
dead button with a hub drop-in:

```yaml
# /etc/dsh-hub/web_config.d/10-hide-account-ui.patch.yml
- id: ui-settings-account
  disabled: true
```

A proxy user can hide it in their own `~/.dsh/cordis.patch.yml`.

## Isolation and deployment limits

**Multi-user hub** (root):

- Each dsh runs as the user's own uid/gid with `DSH_HOME=~/.dsh`.
- Instances bind `127.0.0.1:<random port>`; an iptables owner-guard (loopback,
  `--uid-owner`) DROPs connections from other local users.
- Optional `ALLOW_USERS` allow-list and `ALLOW_NOPASSWD` policy.
- The hub entry refuses to start as non-root; the non-root path is the proxy.

**Single-user proxy** (ordinary account):

- One dsh instance, running as the service account; every authenticated visitor
  shares it. It is not a multi-user isolation boundary.
- No setuid and no iptables guard: the dsh loopback port is reachable by other
  local users, and dsh itself has no login. Use the proxy on a single-user host
  or where local users are trusted; on a shared host use the multi-user hub.
- The proxy login is the service account's system password; there is no
  per-visitor account.

Both modes keep dsh unmodified and on loopback; the front is the only listener.

## Notes

- Cold start is visible: the loading page refreshes every 3 s until the
  instance's index is ready. A first launch can take a while; subsequent
  launches reuse the same data root and are faster.
- Runtime state for the hub lives in the working directory it is started from
  (`WorkingDirectory` under systemd): the persisted `session.list` cache lives
  under `$CWD/cache/`. The source tree can stay read-only.
- The hub's sessions are invalidated by a password change or lock because the
  cookie key follows the shadow entry; the proxy's sessions are not, because the
  proxy has no shadow access. Both are invalidated by a process restart.
- Logout clears the browser cookie; there is no server-side session list. An
  account deleted while a session is open is rejected on its next request.
- The installed service templates start the multi-user hub through
  `src/index.mjs` (which loads `src/hub/index.mjs`). There is no packaged
  service for the single-user proxy; run it from a systemd user unit or an
  OpenRC user service.
- Restart after config changes: `sudo systemctl restart dsh-hub` (systemd),
  `sudo rc-service dsh-hub restart` (OpenRC), `sudo service dsh-hub restart`
  (sysvinit).

## License

MIT
