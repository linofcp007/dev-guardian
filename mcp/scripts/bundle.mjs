#!/usr/bin/env node
/**
 * Bundle the MCP server into a single, self-contained `dist/server.js`.
 *
 * Why: the plugin is distributed by git clone, and `mcp/node_modules` is
 * git-ignored. Without bundling, the installed server crashes on its first
 * `import '@modelcontextprotocol/sdk'` with ERR_MODULE_NOT_FOUND. esbuild
 * inlines every npm dependency (SDK, execa, zod) so the server starts with
 * **zero** runtime node_modules. The only database engine is `node:sqlite`
 * (a builtin), which stays external — no native module to ship.
 *
 * The per-file `tsc` output in `dist/` is kept too: the hooks launch
 * `dist/hooks/*.js` directly, and `dist/storage/migrations/*.sql` is read at
 * runtime. Only `dist/server.js` is replaced by the bundle.
 */

import { build } from 'esbuild';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { bundleOptions } from './bundleOptions.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

// The options live in bundleOptions.mjs, shared with the test that rebuilds
// the bundle in memory and compares it with the committed dist/server.js.
await build({ ...bundleOptions(root), logLevel: 'info' });

console.log('bundled dist/server.js (self-contained, no runtime node_modules)');
