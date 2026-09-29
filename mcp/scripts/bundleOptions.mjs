/**
 * The esbuild options that make `dist/server.js` — shared by
 * `scripts/bundle.mjs` (the build) and `test/unit/pluginSurface/distSync.test.ts`
 * (which rebuilds the bundle in memory and compares it with the committed
 * one), so the two can never bundle differently. See `bundle.mjs` for why the
 * server is bundled at all.
 *
 * @param {string} root the `mcp/` directory
 * @returns {import('esbuild').BuildOptions}
 */
import { resolve } from 'node:path';

export function bundleOptions(root) {
  return {
    entryPoints: [resolve(root, 'src', 'server.ts')],
    outfile: resolve(root, 'dist', 'server.js'),
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
