#!/usr/bin/env node
/**
 * Post-build asset copier.
 *
 * `tsc` only emits .ts files. Anything else our code reads from disk at
 * runtime (currently: SQL migrations) has to be mirrored into `dist/` after
 * the build. This script does that, cross-platform.
 */

import { cpSync, existsSync, mkdirSync, statSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

const pairs = [
  {
    from: resolve(root, 'src', 'storage', 'migrations'),
    to: resolve(root, 'dist', 'storage', 'migrations'),
    // Directories by stat, not by "has no dot in it": `src` is the FULL path,
    // so the old test rejected the root directory itself — and with it every
    // file — in any checkout whose path contains a '.' (e.g. `.claude/`).
    filter: (path) => path.endsWith('.sql') || statSync(path).isDirectory(),
  },
];

for (const { from, to, filter } of pairs) {
  if (!existsSync(from)) continue;
  if (!existsSync(to)) mkdirSync(to, { recursive: true });
  cpSync(from, to, { recursive: true, filter: (src) => filter(src) });
  console.log(`copied ${from} -> ${to}`);
}
