// Minimal server-side i18n for dsh-hub's own pages.
//
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
