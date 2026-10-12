#!/usr/bin/env node
/**
 * Bundle the MCP server and the CLI's engine into two single, self-contained
 * files: `dist/server.js` and `dist/cli.js`.
 *
 * Why: the plugin is distributed by git clone, and `mcp/node_modules` is
 * git-ignored. Without bundling, the installed server crashes on its first
 * `import '@modelcontextprotocol/sdk'` with ERR_MODULE_NOT_FOUND — and the
 * CLI (`cli/dev-guardian.mjs`, through `src/cli.ts`) on the first package its
 * subcommand reaches: 3.2.0's `scan` and `status`, which imported tsc's
 * per-file output, failed on `yaml` in every install. esbuild inlines every
 * npm dependency (SDK, execa, yaml, zod) so both run with **zero** runtime
 * node_modules. The only database engine is `node:sqlite` (a builtin), which
 * stays external — no native module to ship.
 *
 * The per-file `tsc` output in `dist/` is kept too: the hooks launch
 * `dist/hooks/*.js` directly, and `dist/storage/migrations/*.sql` is read at
 * runtime. Only `dist/server.js` and `dist/cli.js` are replaced by bundles.
 */

import { build } from 'esbuild';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BUNDLES, bundleOptions } from './bundleOptions.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

// The options live in bundleOptions.mjs, shared with the test that rebuilds
// the bundles in memory and compares them with the committed files.
await build({ ...bundleOptions(root), logLevel: 'info' });

console.log(`bundled ${BUNDLES.map((name) => `dist/${name}.js`).join(' and ')} (self-contained, no runtime node_modules)`);
