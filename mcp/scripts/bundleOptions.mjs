/**
 * What `npm run build` writes to `mcp/dist/`, shared by `scripts/bundle.mjs`
 * (the build) and `test/unit/pluginSurface/distSync.test.ts` (which rebuilds
 * it in memory and compares it with the committed files), so the two can
 * never bundle differently. See `bundle.mjs` for why everything is bundled.
 *
 * - `dist/engine.js` — `src/engine.ts`: the MCP server and everything the CLI
 *   uses, one self-contained bundle (review 8, finding 2).
 * - `dist/hooks.js` — `src/hooksEntry.ts`: what every hook event needs, and
 *   the loaders of the four parts ({@link HOOK_PARTS}) — `dist/hooksBash.js`,
 *   `hooksVet.js`, `hooksWrite.js`, `hooksSession.js` — each a self-contained
 *   bundle of what one kind of event runs (3.4.0), so a write no longer parses
 *   the 144 KB shell guard, nor any event the `node:crypto` and
 *   `node:child_process` only SessionStart needs. The entry's `import()` of a
 *   part is left to the runtime ({@link HOOK_PART_IMPORT}); code two parts
 *   share is in each. Not esbuild's code splitting: a chunk per module made
 *   every event open a dozen files, slower on Windows than the one bundle.
 *   The parts sit beside the bundles, at the depth every `import.meta.url`
 *   probe in `src/` expects of one.
 * - `dist/server.js` — {@link SERVER_JS}: two lines that start the server in
 *   `engine.js`, at the path `plugin.json` and every host configuration name.
 * - `dist/engine.d.ts`, `dist/hooks.d.ts` — {@link DECLARATIONS}: the two
 *   bundles' types, their sources', for the type check of the CLI and the hook.
 *
 * Two esbuild builds, the engine first: the hooks bundle carries the engine's
 * size and SHA-256 ({@link ENGINE_DIGEST}), so SessionStart can say that a
 * damaged or missing `engine.js` leaves the MCP tools and the CLI unable to
 * run, without loading it. Every `node:` builtin stays external; every npm
 * package is inlined.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

/** Every bundle's entry: `dist/<out>.js` from `src/<in>.ts`. */
export const BUNDLES = [
  { in: 'engine', out: 'engine' },
  { in: 'hooksEntry', out: 'hooks' },
];

/** The hooks bundle's parts: `dist/<part>.js` from `src/<part>.ts`, each loaded by `src/hooksEntry.ts`. */
export const HOOK_PARTS = ['hooksBash', 'hooksVet', 'hooksWrite', 'hooksSession'];

/**
 * The type declarations of the bundles the hand-written JavaScript imports —
 * `dist/engine.js` (`cli/dev-guardian.mjs`) and `dist/hooks.js`
 * (`hooks/guardian-hook.mjs`) — by their name in `dist/`. Each re-exports its
 * source's types, so `tsconfig.js.json` checks a caller against `src/` and
 * never reads a bundle. Written by `bundle.mjs`; `distSync.test.ts` holds the
 * committed ones to these.
 */
export const DECLARATIONS = new Map(
  BUNDLES.map((b) => [
    `${b.out}.d.ts`,
    `// Written by mcp/scripts/bundle.mjs: the types of dist/${b.out}.js are those of its source, src/${b.in}.ts.\nexport * from '../src/${b.in}.js';\n`,
  ]),
);

/** How `src/hooksEntry.ts` imports a part: left to the runtime, which finds it beside `dist/hooks.js`. */
export const HOOK_PART_IMPORT = new RegExp(`^\\./(?:${HOOK_PARTS.join('|')})\\.js$`);

/** The identifier the hooks bundle reads the engine's digest from (`src/hooks/distCheck.ts`). */
export const ENGINE_DIGEST = '__GUARDIAN_ENGINE_DIGEST__';

/**
 * Turning Node's compile cache on in a directory only this account can write:
 * the block from `// compile-cache:begin` to `// compile-cache:end` of
 * `hooks/guardian-hook.mjs`, which `cli/dev-guardian.mjs` holds too
 * (`hooksDispatcher.test.ts` holds the two equal) and {@link SERVER_JS} is
 * written with.
 */
export const COMPILE_CACHE_BLOCK = (() => {
  const hook = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'hooks', 'guardian-hook.mjs'), 'utf8');
  const begin = hook.indexOf('// compile-cache:begin');
  const end = hook.indexOf('// compile-cache:end');
  if (begin < 0 || end < begin) throw new Error('hooks/guardian-hook.mjs holds no compile-cache block');
  return hook.slice(begin, end + '// compile-cache:end'.length);
})();

/**
 * `dist/server.js`, written as it is by the build: the MCP server, started
 * from the engine bundle. The process's entry module is this file, and
 * `engine.js` is loaded by it — so `import.meta.url` inside the engine is
 * `dist/engine.js`, the depth every path probe in `src/` expects of a bundle.
 *
 * It turns Node's compile cache on before it loads the 4 MB engine
 * ({@link COMPILE_CACHE_BLOCK}), and has the cache written as soon as the
 * engine is loaded: Node writes it at an orderly exit, and a server is usually
 * stopped otherwise — killed, on Windows — so it was never written, and every
 * start compiled the engine anew (3.4.0: `initialize` ~70 ms sooner).
 */
export const SERVER_JS = [
  '#!/usr/bin/env node',
  '// The dev-guardian MCP server: started from the engine bundle (mcp/src/engine.ts), built by `npm run build`.',
  "import { existsSync, lstatSync, mkdirSync } from 'node:fs';",
  "import module from 'node:module';",
  "import { tmpdir } from 'node:os';",
  "import { join } from 'node:path';",
  '',
  COMPILE_CACHE_BLOCK,
  '',
  "const engine = await import('./engine.js');",
  'module.flushCompileCache?.();',
  'await engine.startServer();',
  '',
].join('\n');

/**
 * The options both builds share.
 *
 * @param {string} root the `mcp/` directory
 * @returns {import('esbuild').BuildOptions}
 */
function common(root) {
  return {
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

/**
 * `dist/engine.js`: one file, no splitting.
 *
 * @param {string} root the `mcp/` directory
 * @returns {import('esbuild').BuildOptions}
 */
export function engineOptions(root) {
  return { ...common(root), entryPoints: [{ in: resolve(root, 'src', 'engine.ts'), out: 'engine' }] };
}

/**
 * `dist/hooks.js` and its parts, with the engine's digest defined.
 *
 * @param {string} root the `mcp/` directory
 * @param {{ bytes: number, sha256: string }} engineDigest
 * @returns {import('esbuild').BuildOptions}
 */
export function hooksOptions(root, engineDigest) {
  const entry = resolve(root, 'src', 'hooksEntry.ts');
  return {
    ...common(root),
    entryPoints: [{ in: entry, out: 'hooks' }, ...HOOK_PARTS.map((part) => ({ in: resolve(root, 'src', `${part}.ts`), out: part }))],
    define: { [ENGINE_DIGEST]: JSON.stringify(engineDigest) },
    plugins: [
      {
        name: 'hook-parts',
        setup(b) {
          // The entry's `import('./hooksBash.js')` stays as written: the part is a bundle of its own.
          b.onResolve({ filter: HOOK_PART_IMPORT }, (args) => (resolve(args.importer) === entry ? { path: args.path, external: true } : undefined));
        },
      },
    ],
  };
}

/**
 * The size and SHA-256 of a bundle's text, as it is written to disk.
 *
 * @param {string} text
 * @returns {{ bytes: number, sha256: string }}
 */
export function digestOf(text) {
  const bytes = Buffer.from(text, 'utf8');
  return { bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') };
}

/**
 * Builds `dist/`'s bundles: the engine, then the hooks with its digest. Nothing
 * is written — the outputs come back in memory, for `bundle.mjs` to write and
 * for the drift test to compare.
 *
 * @param {string} root the `mcp/` directory
 * @param {{ logLevel?: import('esbuild').LogLevel }} [opts]
 * @returns {Promise<{ outputs: Map<string, string>, metafiles: { engine: import('esbuild').Metafile, hooks: import('esbuild').Metafile } }>}
 */
export async function buildDist(root, opts = {}) {
  const logLevel = opts.logLevel ?? 'silent';
  const engine = await build({ ...engineOptions(root), write: false, metafile: true, logLevel });
  const engineFile = engine.outputFiles.find((f) => resolve(f.path) === resolve(root, 'dist', 'engine.js'));
  if (engineFile === undefined) throw new Error('the engine build wrote no dist/engine.js');
  const hooks = await build({ ...hooksOptions(root, digestOf(engineFile.text)), write: false, metafile: true, logLevel });
  const outputs = new Map([...engine.outputFiles, ...hooks.outputFiles].map((f) => [resolve(f.path), f.text]));
  return { outputs, metafiles: { engine: engine.metafile, hooks: hooks.metafile } };
}
