/**
 * What `npm run build` writes to `mcp/dist/`, shared by `scripts/bundle.mjs`
 * (the build) and `test/unit/pluginSurface/distSync.test.ts` (which rebuilds
 * it in memory and compares it with the committed files), so the two can
 * never bundle differently. See `bundle.mjs` for why everything is bundled.
 *
 * - `dist/engine.js` — `src/engine.ts`: the MCP server and everything the CLI
 *   uses, one self-contained bundle (review 8, finding 2).
 * - `dist/hooks.js` — `src/hooksEntry.ts`: the detectors the hook dispatcher
 *   loads, one bundle of its own, kept small because the hook runs on every
 *   tool call (review 8, finding 3).
 * - `dist/server.js` — {@link SERVER_JS}: two lines that start the server in
 *   `engine.js`, at the path `plugin.json` and every host configuration name.
 *
 * One esbuild build, two entry points, no code splitting: each bundle is
 * self-contained, made with the same options. Every `node:` builtin stays
 * external; every npm package is inlined.
 */
import { resolve } from 'node:path';

/** Every bundle: `dist/<out>.js` from `src/<in>.ts`. */
export const BUNDLES = [
  { in: 'engine', out: 'engine' },
  { in: 'hooksEntry', out: 'hooks' },
];

/**
 * `dist/server.js`, written as it is by the build: the MCP server, started
 * from the engine bundle. The process's entry module is this file, and
 * `engine.js` is loaded by it — so `import.meta.url` inside the engine is
 * `dist/engine.js`, the depth every path probe in `src/` expects of a bundle.
 */
export const SERVER_JS = [
  '#!/usr/bin/env node',
  '// The dev-guardian MCP server: started from the engine bundle (mcp/src/engine.ts), built by `npm run build`.',
  "await (await import('./engine.js')).startServer();",
  '',
].join('\n');

/**
 * @param {string} root the `mcp/` directory
 * @returns {import('esbuild').BuildOptions}
 */
export function bundleOptions(root) {
  return {
    entryPoints: BUNDLES.map((b) => ({ in: resolve(root, 'src', `${b.in}.ts`), out: b.out })),
    outdir: resolve(root, 'dist'),
    // The paths esbuild writes into the bundle's comments are relative to
    // this; `npm run build` runs from `mcp/`, and so must anything that
    // compares against its output.
    absWorkingDir: root,
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
  };
}
