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

import { cpSync, existsSync, mkdirSync, rmSync, statSync } from 'node:fs';
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
  {
    from: resolve(root, 'src', 'hostsetup', 'legacyRulesTemplates'),
    to: resolve(root, 'dist', 'hostsetup', 'legacyRulesTemplates'),
    // Every file in this directory is a known legacy template snapshot —
    // no extension-based filtering needed (unlike migrations/, this
    // directory holds nothing else).
    filter: () => true,
    // Fix round 3, item 2: `cpSync` only ever ADDS/overwrites — renaming a
    // source file here (as this same fix did, to non-magic names Gemini
    // CLI / AGENTS.md-aware tools won't treat as live instructions) leaves
    // the OLD-named copy sitting in `dist/` forever otherwise, silently
    // wrong (stale content, under a name nothing in `src/` produces
    // anymore) until someone notices. `clean: true` wipes the destination
    // before every copy so it can only ever hold what `src/` currently
    // does — deliberately scoped to this ONE pair, not migrations/, which
    // has never had a rename and whose behaviour this fix has no reason to
    // touch.
    clean: true,
  },
];

for (const { from, to, filter, clean } of pairs) {
  if (!existsSync(from)) continue;
  if (clean) rmSync(to, { recursive: true, force: true });
  if (!existsSync(to)) mkdirSync(to, { recursive: true });
  cpSync(from, to, { recursive: true, filter: (src) => filter(src) });
  console.log(`copied ${from} -> ${to}`);
}
