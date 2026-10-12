/**
 * The esbuild options that make the two bundles — `dist/server.js` (the MCP
 * server) and `dist/cli.js` (what `cli/dev-guardian.mjs` runs) — shared by
 * `scripts/bundle.mjs` (the build) and `test/unit/pluginSurface/distSync.test.ts`
 * (which rebuilds them in memory and compares them with the committed ones),
 * so the two can never bundle differently. See `bundle.mjs` for why they are
 * bundled at all.
 *
 * One build, two entry points, no code splitting: each output is a
 * self-contained bundle of its own, made with the same options.
 *
 * @param {string} root the `mcp/` directory
 * @returns {import('esbuild').BuildOptions}
 */
import { resolve } from 'node:path';

/** Every bundle, by its entry under `src/`: `src/<name>.ts` is written to `dist/<name>.js`, over tsc's file of that name. */
export const BUNDLES = ['server', 'cli'];

export function bundleOptions(root) {
  return {
    entryPoints: BUNDLES.map((name) => resolve(root, 'src', `${name}.ts`)),
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
