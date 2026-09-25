#!/usr/bin/env node
/**
 * Post-build asset copier.
 *
 * `tsc` only emits .ts files. Anything else our code reads from disk at
 * runtime (SQL migrations; the known-legacy-rules-template snapshots — fix
 * round 2, item 1 — used to recognise a pre-item-7 dev-guardian install
 * without risking a whole-file rewrite of unrelated content) has to be
 * mirrored into `dist/` after the build. This script does that,
 * cross-platform.
 */

import { cpSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

const pairs = [
  {
    from: resolve(root, 'src', 'storage', 'migrations'),
    to: resolve(root, 'dist', 'storage', 'migrations'),
    filter: (path) => path.endsWith('.sql') || !path.includes('.'),
  },
  {
    from: resolve(root, 'src', 'hostsetup', 'legacyRulesTemplates'),
    to: resolve(root, 'dist', 'hostsetup', 'legacyRulesTemplates'),
    // Every file in this directory is a known legacy template snapshot —
    // no extension-based filtering needed (unlike migrations/, this
    // directory holds nothing else).
    filter: () => true,
  },
];

for (const { from, to, filter } of pairs) {
  if (!existsSync(from)) continue;
  if (!existsSync(to)) mkdirSync(to, { recursive: true });
  cpSync(from, to, { recursive: true, filter: (src) => filter(src) });
  console.log(`copied ${from} -> ${to}`);
}
