// Admin-maintained global dsh overlays for instances the hub spawns.
//
// `/etc/dsh-hub/web_config.d/*.yml` (or HUB_WEB_CONFIG_DIR) are applied in
// file-name order as dsh `--patch` layers. They are world-readable and are
// passed to every user's dsh process, so they must never hold secrets — per-user
// secrets belong in that user's `~/.dsh/cordis.patch.yml` (0600).
//
// dsh applies `--patch` AFTER `$DSH_HOME/cordis.patch.yml`, so a global drop-in
// overrides the user's own patch for the rows it touches. That is deliberate:
// the administrator's configuration is authoritative. Keep drop-ins small and
// review them before installing; an over-broad one changes every user's UI.
import fs from 'node:fs';
import path from 'node:path';

import { CFG } from './config.mjs';

let warnedInsecureDir = false;

function warnIfInsecureDir() {
  if (warnedInsecureDir) return;
  warnedInsecureDir = true;
  try {
    if (fs.statSync(CFG.webConfigDir).mode & 0o022) {
      console.warn(`[hub] web config: ${CFG.webConfigDir} is group/other-writable; only root should own it`);
    }
  } catch { /* a missing directory is allowed */ }
}

/**
 * The admin drop-ins: `*.yml`/`*.yaml` regular files in the configured
 * directory, in file-name order. Files the spawned user could not read are
 * skipped with a warning, because dsh would fail to boot on them.
 * @returns absolute patch paths, in application order.
 */
export function webConfigPatches() {
  const patches = [];
  let entries;
  try {
    entries = fs.readdirSync(CFG.webConfigDir, { withFileTypes: true });
  } catch (err) {
    if (err.code !== 'ENOENT') console.warn(`[hub] web config: ${CFG.webConfigDir}: ${err.message}`);
    return patches;
  }
  warnIfInsecureDir();
  const names = entries
    .filter((entry) => !entry.name.startsWith('.') && /\.ya?ml$/i.test(entry.name))
    .map((entry) => entry.name)
    .sort();
  for (const name of names) {
    const file = path.join(CFG.webConfigDir, name);
    let stat;
    try {
      stat = fs.statSync(file);
    } catch {
      continue;
    }
    if (!stat.isFile()) continue;
    if ((stat.mode & 0o004) === 0) {
      console.warn(`[hub] web config: skipping ${file}: not world-readable for the spawned user`);
      continue;
    }
    patches.push(file);
  }
  return patches;
}
