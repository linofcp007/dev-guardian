#!/usr/bin/env node
/**
 * Post-build asset copier.
 *
 * `tsc` only emits .ts files. Anything else our code reads from disk at
 * runtime (currently: SQL migrations) has to be mirrored into `dist/` after
 * the build. This script does that, cross-platform.
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
];

for (const { from, to, filter } of pairs) {
  if (!existsSync(from)) continue;
  if (!existsSync(to)) mkdirSync(to, { recursive: true });
  cpSync(from, to, { recursive: true, filter: (src) => filter(src) });
  console.log(`copied ${from} -> ${to}`);
}
