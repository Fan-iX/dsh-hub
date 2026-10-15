// dsh-hub's own browser pages, kept as real HTML files instead of inline
// template strings so they can be edited and reviewed as markup.
import fs from 'node:fs';

const readPage = (name) => fs.readFileSync(new URL(`./pages/${name}`, import.meta.url), 'utf8');

const LOGIN_TEMPLATE = readPage('login.html');

/** The cold-start page shown while a user's dsh instance is being spawned. */
export const STARTING_PAGE = readPage('starting.html');

/**
 * Render the login page.
 * @param message - text substituted into the `__MSG__` slot.
 * @returns the login page HTML.
 */
export function loginPage(message) {
  return LOGIN_TEMPLATE.replace('__MSG__', message);
}
