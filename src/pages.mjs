// Renders dsh-hub's own pages from the HTML templates plus the shared
// stylesheet. User-facing strings live in i18n.mjs and the templates reference
// them as `{{key}}`, so copy changes are dictionary edits, not markup surgery.
import fs from 'node:fs';

import { t } from './i18n.mjs';

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
