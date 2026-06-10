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

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

await build({
  entryPoints: [resolve(root, 'src', 'server.ts')],
  outfile: resolve(root, 'dist', 'server.js'),
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node22',
  // node:sqlite (and every other `node:` builtin) stays external; everything
  // from node_modules gets inlined.
  external: ['node:sqlite'],
  // Some bundled deps call `require()` at runtime (e.g. `require('node:fs')`);
  // ESM output has no `require`, so provide one via createRequire.
  banner: {
    js: "import { createRequire as __createRequire } from 'node:module'; const require = __createRequire(import.meta.url);",
  },
  legalComments: 'none',
  logLevel: 'info',
});

console.log('bundled dist/server.js (self-contained, no runtime node_modules)');
