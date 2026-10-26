// Shared web layer: HTTP response/body helpers, the bilingual page renderer,
// and the keep-alive route used by both entry points.
import fs from 'node:fs';

// ------------------------------------------------------------- i18n --------
// Locale resolution order: an explicit `?lang=` query, the persisted
// `dshhub_lang` cookie, the request's Accept-Language, then the default
// (Chinese). Rendering happens on the server so the static cold-start page
// needs no client JavaScript.

/** Locales with a complete dictionary. */
export const LOCALES = ['zh', 'en'];

/** Locale used when nothing else matches. */
export const DEFAULT_LOCALE = 'zh';

/** Cookie that remembers an explicit language choice. */
export const LANG_COOKIE = 'dshhub_lang';

const DICTS = {
  zh: {
    'app.name': 'DeepSeek Harness',
    'login.pageTitle': '登录 · dsh-hub',
    'login.subtitle': '使用服务器系统账号登录,每用户独立隔离实例',
    'login.username': '用户名',
    'login.password': '密码',
    'login.submit': '登录',
    'login.langLabel': '语言',
    'login.langZh': '中文',
    'login.langEn': 'English',
    'starting.pageTitle': '正在启动 · dsh-hub',
    'starting.message': '正在为你的账号启动 dsh 实例',
    'starting.hint': '首次加载可能需要等待几十秒,页面会自动刷新',
    'error.missingCredentials': '请输入用户名和密码',
    'error.badCredentials': '用户名或密码错误',
    'error.tooManyAttempts': '尝试过多,请 {wait} 后再试',
    'error.spawnFailed': '无法启动你的实例',
    'error.starting': 'dsh-hub: dsh 实例正在启动',
    'wait.seconds': '{n} 秒',
    'wait.minutes': '{n} 分钟',
  },
  en: {
    'app.name': 'DeepSeek Harness',
    'login.pageTitle': 'Sign in · dsh-hub',
    'login.subtitle': 'Sign in with your server account — each user gets an isolated instance',
    'login.username': 'Username',
    'login.password': 'Password',
    'login.submit': 'Sign in',
    'login.langLabel': 'Language',
    'login.langZh': '中文',
    'login.langEn': 'English',
    'starting.pageTitle': 'Starting · dsh-hub',
    'starting.message': 'Starting your dsh instance',
    'starting.hint': 'The first load can take tens of seconds; this page refreshes automatically',
    'error.missingCredentials': 'Enter your username and password',
    'error.badCredentials': 'Incorrect username or password',
    'error.tooManyAttempts': 'Too many attempts — try again in {wait}',
    'error.spawnFailed': 'Could not start your instance',
    'error.starting': 'dsh-hub: dsh instance is starting',
    'wait.seconds': '{n}s',
    'wait.minutes': '{n} min',
  },
};

/**
 * Translate one key, substituting `{name}` placeholders.
 * @param locale - a locale from {@link LOCALES}.
 * @param key - dictionary key.
 * @param vars - placeholder values.
 * @returns the localized string, falling back to the default locale, then the key.
 */
export function t(locale, key, vars) {
  const dict = DICTS[locale] ?? DICTS[DEFAULT_LOCALE];
  const text = dict[key] ?? DICTS[DEFAULT_LOCALE][key] ?? key;
  if (vars === undefined) return text;
  return text.replace(/\{(\w+)\}/g, (match, name) => (name in vars ? String(vars[name]) : match));
}

/**
 * Map an Accept-Language header (or any language tag) to a supported locale.
 * @param value - raw header or tag, e.g. `en-US,en;q=0.9,zh;q=0.8`.
 * @returns a locale from {@link LOCALES}.
 */
export function resolveLocale(value) {
  if (typeof value !== 'string') return DEFAULT_LOCALE;
  for (const part of value.split(',')) {
    const tag = part.split(';')[0].trim().toLowerCase();
    if (tag === '') continue;
    const base = tag.split('-')[0];
    if (LOCALES.includes(base)) return base;
  }
  return DEFAULT_LOCALE;
}

function cookieValue(header, name) {
  for (const part of String(header ?? '').split(';')) {
    const at = part.indexOf('=');
    if (at === -1) continue;
    if (part.slice(0, at).trim() === name) return part.slice(at + 1).trim();
  }
  return undefined;
}

/**
 * Resolve the page locale for one request.
 * @param req - the incoming request.
 * @returns a locale from {@link LOCALES}.
 */
export function localeFromRequest(req) {
  const query = new URL(req.url ?? '/', 'http://x').searchParams.get('lang');
  if (query !== null) {
    const asked = query.trim().toLowerCase();
    if (LOCALES.includes(asked)) return asked;
  }
  const cookie = cookieValue(req.headers.cookie, LANG_COOKIE);
  if (cookie !== undefined && LOCALES.includes(cookie)) return cookie;
  return resolveLocale(req.headers['accept-language']);
}

/**
 * Persist an explicit `?lang=` choice as a cookie.
 * @param req - the incoming request.
 * @returns a `Set-Cookie` value, or undefined when no valid explicit choice was made.
 */
export function languageCookie(req) {
  const query = new URL(req.url ?? '/', 'http://x').searchParams.get('lang');
  if (query === null) return undefined;
  const asked = query.trim().toLowerCase();
  if (!LOCALES.includes(asked)) return undefined;
  return `${LANG_COOKIE}=${asked}; Path=/; Max-Age=31536000; SameSite=Lax`;
}

/** Locale headers for a hub-rendered page, persisting an explicit `?lang=`. */
export function pageHeaders(req, locale) {
  const headers = { 'content-language': locale, vary: 'Accept-Language' };
  const cookie = languageCookie(req);
  if (cookie !== undefined) headers['set-cookie'] = cookie;
  return headers;
}

// ----------------------------------------------------------- HTTP --------

/** Write a small HTML response. */
export function sendHtml(res, status, body, headers = {}) {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', ...headers });
  res.end(body);
}

/** Write one JSON response. */
export function sendJson(res, status, value, headers = {}) {
  const body = JSON.stringify(value);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
    ...headers,
  });
  res.end(body);
}

/**
 * Whether a request asks for a top-level document. A missing session redirects
 * such a request to the login page; fetch/API calls get a machine-readable 401
 * instead, so a page-level watcher can navigate without parsing HTML.
 * @param req - the incoming request.
 * @returns true for a GET navigation or iframe request.
 */
export function wantsDocument(req) {
  if (req.method !== 'GET') return false;
  const dest = String(req.headers['sec-fetch-dest'] ?? '');
  if (dest === 'document' || dest === 'iframe') return true;
  return /text\/html/i.test(String(req.headers.accept ?? ''));
}

/** Read a request body as UTF-8 text, rejecting anything over `limit` bytes. */
export function readBody(req, limit = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString()));
    req.on('error', reject);
  });
}

/** Parse an `application/x-www-form-urlencoded` login body. */
export function urlencoded(body) {
  const params = new URLSearchParams(body);
  return { username: params.get('username') ?? '', password: params.get('password') ?? '' };
}

/** Read a request body as a Buffer, with no size cap. */
export function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/** Copy headers for a hub-internal backend request, forcing a loopback Host. */
export function sanitizeForwardHeaders(headers, bePort) {
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    const key = k.toLowerCase();
    if (['connection', 'transfer-encoding', 'upgrade', 'keep-alive', 'proxy-connection', 'te', 'content-length', 'host'].includes(key)) continue;
    out[k] = v;
  }
  out.host = `127.0.0.1:${bePort}`;
  return out;
}

// ---------------------------------------------------------- pages --------

const read = (name) => fs.readFileSync(new URL(`./pages/${name}`, import.meta.url), 'utf8');

const THEME = read('theme.css');
const LOGIN_TEMPLATE = read('login.html');
const STARTING_TEMPLATE = read('starting.html');

const PLACEHOLDER = /\{\{(\w+)\}\}/g;

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function render(template, vars) {
  return template.replace(PLACEHOLDER, (match, key) => (key in vars ? vars[key] : match));
}

/** The `中文 | English` switcher; the active locale is marked, not linked twice. */
function languageSwitch(locale) {
  return ['zh', 'en'].map((code) => {
    const label = t(locale, code === 'zh' ? 'login.langZh' : 'login.langEn');
    const active = code === locale;
    return `<a class="lang-opt${active ? ' active' : ''}" href="?lang=${code}" hreflang="${code}"`
      + (active ? ' aria-current="true"' : '') + `>${escapeHtml(label)}</a>`;
  }).join('');
}

/**
 * Render the login page.
 * @param locale - page locale from i18n.
 * @param message - already-localized error or notice for the message slot.
 * @returns the login page HTML.
 */
export function loginPage(locale, message = '') {
  return render(LOGIN_TEMPLATE, {
    lang: locale,
    style: THEME,
    title: t(locale, 'login.pageTitle'),
    brand: t(locale, 'app.name'),
    subtitle: t(locale, 'login.subtitle'),
    username: t(locale, 'login.username'),
    password: t(locale, 'login.password'),
    submit: t(locale, 'login.submit'),
    message: escapeHtml(message),
    langLabel: t(locale, 'login.langLabel'),
    langSwitch: languageSwitch(locale),
  });
}

/**
 * Render the cold-start page.
 * @param locale - page locale from i18n.
 * @returns the starting page HTML.
 */
export function startingPage(locale) {
  return render(STARTING_TEMPLATE, {
    lang: locale,
    style: THEME,
    title: t(locale, 'starting.pageTitle'),
    brand: t(locale, 'app.name'),
    message: t(locale, 'starting.message'),
    hint: t(locale, 'starting.hint'),
  });
}

// ------------------------------------------------------ keep-alive --------

/** Largest JSON body accepted by the keep-alive route; the only field is one boolean. */
const MAX_KEEPALIVE_BODY = 1024;

/**
 * Answer one request on the keep-alive route.
 * @param req - the incoming request, already authenticated by the entry point.
 * @param res - the response this handler owns.
 * @param be - the instance to pin, or undefined when none is running.
 */
export async function handleKeepAlive(req, res, be) {
  if (req.method === 'GET') {
    sendJson(res, 200, { keepAlive: be?.keepAlive === true, running: be !== undefined });
    return;
  }
  if (req.method !== 'POST') {
    res.writeHead(405, { allow: 'GET, POST', 'content-type': 'text/plain; charset=utf-8' });
    res.end('GET or POST only\n');
    return;
  }
  // CSRF: the session cookie is SameSite=Lax, and a cross-site form cannot send
  // application/json without a CORS preflight, so this pair is the guard.
  if (!/^application\/json\s*(;|$)/i.test(String(req.headers['content-type'] ?? ''))) {
    sendJson(res, 415, { error: 'content-type must be application/json' });
    return;
  }
  let raw;
  try {
    raw = await readBody(req, MAX_KEEPALIVE_BODY);
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
    console.log(`[hub] keep-alive ${be.keepAlive ? 'enabled' : 'disabled'} for ${be.user ?? 'proxy'}`);
  }
  if (typeof be.touch === 'function') be.touch();
  else be.lastActivity = Date.now();
  sendJson(res, 200, { keepAlive: be.keepAlive, running: true });
}
