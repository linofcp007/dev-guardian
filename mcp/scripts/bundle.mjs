#!/usr/bin/env node
/**
 * Build `mcp/dist/`: the two self-contained bundles — the engine, and the
 * hooks bundle with its four per-event parts — the server's entry file and
 * the two bundles' type declarations (`scripts/bundleOptions.mjs` says what
 * each is). It empties `dist/` first, so it holds only what this build makes
 * — then `copy-assets.mjs` adds the files the code reads at run time (the SQL
 * migrations, the legacy rules templates).
 *
 * Why bundles: the plugin is distributed by git clone, and `mcp/node_modules`
 * is git-ignored. Code that imports an npm package by name crashes in an
 * install with ERR_MODULE_NOT_FOUND — 3.2.0's CLI `scan` and `status`, which
 * imported tsc's per-file output, failed on `yaml` in every install. esbuild
 * inlines every npm dependency (SDK, yaml, zod), so the server, the CLI and
 * the hooks run with **zero** runtime node_modules. The only database engine
 * is `node:sqlite` (a builtin), which stays external — no native module to
 * ship.
 *
 * Nothing else is emitted (review 8, finding 3): tsc only type-checks
 * (`tsconfig.json` is `noEmit`), and no source maps ship — the bundles are
 * readable as they are.
 */

import { chmodSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DECLARATIONS, SERVER_JS, buildDist } from './bundleOptions.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dist = resolve(root, 'dist');

rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });

// The builds live in bundleOptions.mjs, shared with the test that rebuilds
// them in memory and compares them with the committed files.
const { outputs } = await buildDist(root, { logLevel: 'warning' });
for (const [path, text] of outputs) writeFileSync(path, text);

const server = resolve(dist, 'server.js');
writeFileSync(server, SERVER_JS);
chmodSync(server, 0o755);

for (const [name, text] of DECLARATIONS) writeFileSync(resolve(dist, name), text);

const names = [...outputs.keys()].map((p) => relative(dist, p).split('\\').join('/'));
const parts = names.filter((n) => /^hooks[A-Z]/.test(n)).length;
console.log(
  `bundled dist/engine.js, dist/hooks.js and its ${parts} parts, dist/server.js (self-contained, no runtime node_modules) and the bundles' declarations`,
);
