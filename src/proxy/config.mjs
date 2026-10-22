// Single-user proxy configuration: the service account, its dsh data root,
// workspace, and user-writable log paths.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  BASE, TRUSTED_HOSTS, TRUST_MODE,
} from '../backend/config.mjs';

export { TRUSTED_HOSTS, TRUST_MODE };

const HOME = os.homedir();
const STATE_DIR = process.env.XDG_STATE_HOME
  ? path.join(process.env.XDG_STATE_HOME, 'dsh-hub')
  : path.join(HOME, '.local', 'state', 'dsh-hub');

function defaultWorkspace(dshHome) {
  if (process.env.HUB_WORKSPACE) return process.env.HUB_WORKSPACE;
  try {
    const dflt = fs.readFileSync(path.join(dshHome, 'hub-default-workspace'), 'utf8').trim();
    if (dflt && fs.statSync(dflt).isDirectory()) return dflt;
  } catch { /* no default workspace configured */ }
  return HOME;
}

const dshHome = process.env.DSH_HOME ?? path.join(HOME, '.dsh');

export const CFG = {
  ...BASE,
  // The only account allowed to sign in. The proxy spawns dsh as this user, so
  // the username cannot be a different system account.
  serviceUser: os.userInfo().username,
  home: HOME,
  dshHome,
  workspace: defaultWorkspace(dshHome),
  logDir: process.env.HUB_LOG_DIR ?? STATE_DIR,
  logPath: process.env.HUB_LOG_DIR
    ? path.join(process.env.HUB_LOG_DIR, 'dsh.log')
    : path.join(STATE_DIR, 'dsh.log'),
  authLogPath: process.env.HUB_AUTH_LOG ?? path.join(STATE_DIR, 'auth.log'),
};
