#!/usr/bin/env node
/**
 * Build `mcp/dist/`: the two self-contained bundles and the server's entry
 * file (`scripts/bundleOptions.mjs` says what each is). It empties `dist/`
 * first, so it holds only what this build makes — then `copy-assets.mjs` adds
 * the files the code reads at run time (the SQL migrations, the legacy rules
 * templates).
 *
 * Why bundles: the plugin is distributed by git clone, and `mcp/node_modules`
 * is git-ignored. Code that imports an npm package by name crashes in an
 * install with ERR_MODULE_NOT_FOUND — 3.2.0's CLI `scan` and `status`, which
 * imported tsc's per-file output, failed on `yaml` in every install. esbuild
 * inlines every npm dependency (SDK, execa, yaml, zod), so the server, the
 * CLI and the hooks run with **zero** runtime node_modules. The only database
 * engine is `node:sqlite` (a builtin), which stays external — no native
 * module to ship.
 *
 * Nothing else is emitted (review 8, finding 3): tsc only type-checks
 * (`tsconfig.json` is `noEmit`), and no source maps ship — the bundles are
 * readable as they are.
 */

import { build } from 'esbuild';
import { chmodSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BUNDLES, SERVER_JS, bundleOptions } from './bundleOptions.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dist = resolve(root, 'dist');

rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });

// The options live in bundleOptions.mjs, shared with the test that rebuilds
// the bundles in memory and compares them with the committed files.
await build({ ...bundleOptions(root), logLevel: 'info' });

const server = resolve(dist, 'server.js');
writeFileSync(server, SERVER_JS);
chmodSync(server, 0o755);

console.log(`bundled ${BUNDLES.map((b) => `dist/${b.out}.js`).join(' and ')}, and dist/server.js (self-contained, no runtime node_modules)`);
