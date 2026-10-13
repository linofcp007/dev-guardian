/**
 * The committed `mcp/dist/` is what `npm run build` makes of `mcp/src/` —
 * byte for byte (review 3.0, R7).
 *
 * The repository IS the distribution: Claude Code runs `mcp/dist/server.js`,
 * the CLI `mcp/dist/engine.js` and the hooks `mcp/dist/hooks.js` (and its
 * parts) straight from the clone, with no install-time build (CLAUDE.md,
 * "Commit the compiled mcp/dist/"). A change to `src/` committed without a
 * rebuild ships the OLD behaviour, with every test green — the tests import
 * `src/`. Nothing checked it.
 *
 * What `npm run build` puts in `dist/`, and what is checked here:
 *
 * - `scripts/bundle.mjs`: the bundles `dist/engine.js`, and `dist/hooks.js`
 *   with its parts `dist/hooksBash.js`, `hooksVet.js`, `hooksWrite.js`,
 *   `hooksSession.js` (3.4.0) — rebuilt in memory by the same function
 *   (`buildDist` in `scripts/bundleOptions.mjs`, shared with the build so the
 *   two cannot differ) and compared — and `dist/server.js`, the two lines that
 *   start the server from the engine (`SERVER_JS` there). The bundles inline
 *   `node_modules`, so a checkout whose `node_modules` is not the lockfile's
 *   (`npm ci`) can fail this part legitimately. And each imports nothing but
 *   Node's builtins and — the hooks entry — its parts (esbuild's metafile):
 *   what a plugin install — no `node_modules` — can load.
 * - `scripts/copy-assets.mjs`: the migrations' `.sql` and the legacy rules
 *   templates, mirrored from `src/` — compared with their sources.
 * - Nothing else: tsc emits nothing and no source map ships (review 8,
 *   finding 3: 355 per-file `.js` and 361 maps, 11 MB that only the hooks'
 *   27 modules were ever loaded from). A file in `dist/` that none of the
 *   above makes is stale, and fails.
 *
 * The fix for a failure is `npm run build` and committing `mcp/dist/` with the
 * change — never editing a file in `dist/`.
 */

import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { isBuiltin } from 'node:module';
import { pathToFileURL } from 'node:url';
import type { Metafile } from 'esbuild';
import { describe, expect, it, vi } from 'vitest';
import { MCP_ROOT } from '../../helpers/tsxNode.js';

vi.setConfig({ testTimeout: 120_000 });

const DIST = join(MCP_ROOT, 'dist');
const rel = (abs: string): string => relative(DIST, abs).split('\\').join('/');

/** Every file under `dir`, absolute. */
function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const abs = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(abs));
    else out.push(abs);
  }
  return out;
}

interface BundleOptionsModule {
  HOOK_PARTS: string[];
  SERVER_JS: string;
  buildDist: (root: string) => Promise<{ outputs: Map<string, string>; metafiles: { engine: Metafile; hooks: Metafile } }>;
}

const options = (await import(pathToFileURL(join(MCP_ROOT, 'scripts', 'bundleOptions.mjs')).href)) as BundleOptionsModule;

const SERVER_PATH = join(DIST, 'server.js');
/** Every bundle the build writes, by its name in `dist/`. */
const BUNDLE_NAMES = ['engine.js', 'hooks.js', ...options.HOOK_PARTS.map((p) => `${p}.js`)].sort();

interface Bundled {
  /** Each output's text, by its absolute path in `dist/`. */
  texts: Map<string, string>;
  /** Each output's imports esbuild left to the runtime, by `dist/<name>.js`. */
  imports: Map<string, string[]>;
}

/** What `scripts/bundle.mjs` writes to `dist/` — the engine, the hooks bundle and its parts — in memory. */
async function bundleAll(): Promise<Bundled> {
  const { outputs, metafiles } = await options.buildDist(MCP_ROOT);
  const imports = new Map(
    [...Object.entries(metafiles.engine.outputs), ...Object.entries(metafiles.hooks.outputs)].map(([out, meta]) => [out, meta.imports.map((i) => i.path)]),
  );
  return { texts: outputs, imports };
}

/** The directories `scripts/copy-assets.mjs` mirrors from `src/` into `dist/`, with its filter. */
const ASSET_DIRS: ReadonlyArray<{ dir: string; take: (name: string) => boolean }> = [
  { dir: join('storage', 'migrations'), take: (name) => name.endsWith('.sql') },
  { dir: join('hostsetup', 'legacyRulesTemplates'), take: () => true },
];

/** The built files the committed `dist/` does not hold byte for byte. */
function drift(built: ReadonlyMap<string, string>): string[] {
  return [...built]
    .filter(([abs, text]) => !existsSync(abs) || readFileSync(abs, 'utf8') !== text)
    .map(([abs]) => `${rel(abs)}: ${existsSync(abs) ? 'differs from' : 'missing, but'} what npm run build makes of src/ — run npm run build`);
}

describe('the committed mcp/dist is the build of mcp/src', () => {
  let bundled: Bundled | undefined;
  /** Bundled once, by the first test that needs it. */
  const bundles = async (): Promise<Bundled> => (bundled ??= await bundleAll());

  it('the bundles: dist/engine.js, dist/hooks.js and its parts are what scripts/bundle.mjs makes of src/', async () => {
    const { texts } = await bundles();
    expect([...texts.keys()].map(rel).sort()).toEqual(BUNDLE_NAMES);
    expect(BUNDLE_NAMES).toEqual(['engine.js', 'hooks.js', 'hooksBash.js', 'hooksSession.js', 'hooksVet.js', 'hooksWrite.js']);
    // Not toBe on megabytes of text: the failure should be a sentence.
    expect(drift(texts)).toEqual([]);
  });

  it('positive control: one changed character in one bundle is reported, and only that bundle', async () => {
    const altered = new Map((await bundles()).texts);
    const hooks = join(DIST, 'hooks.js');
    altered.set(hooks, `${altered.get(hooks) ?? ''} `);
    expect(drift(altered)).toEqual(['hooks.js: differs from what npm run build makes of src/ — run npm run build']);
  });

  it('the hooks bundle carries the engine’s digest, so SessionStart can tell a damaged engine', async () => {
    const { texts } = await bundles();
    const bytes = Buffer.byteLength(texts.get(join(DIST, 'engine.js')) ?? '', 'utf8');
    expect(texts.get(join(DIST, 'hooksSession.js')) ?? '').toContain(`bytes: ${String(bytes)}`);
  });

  it('dist/server.js starts the server from dist/engine.js, the compile cache on and written once the engine is loaded', () => {
    expect(readFileSync(SERVER_PATH, 'utf8')).toBe(options.SERVER_JS);
    expect(options.SERVER_JS).toMatch(/^#!\/usr\/bin\/env node\n/);
    const enable = options.SERVER_JS.indexOf('module.enableCompileCache?.(dir)');
    const load = options.SERVER_JS.indexOf("await import('./engine.js')");
    const flush = options.SERVER_JS.indexOf('module.flushCompileCache?.()');
    const start = options.SERVER_JS.indexOf('await engine.startServer()');
    expect(enable).toBeGreaterThan(0);
    expect([enable < load, load < flush, flush < start]).toEqual([true, true, true]);
  });

  it('the bundles import nothing but Node builtins, and the hooks entry its parts — every package is inlined, as an install without node_modules needs', async () => {
    const { imports } = await bundles();
    expect([...imports.keys()].sort()).toEqual(BUNDLE_NAMES.map((n) => `dist/${n}`));
    const parts = new Set(options.HOOK_PARTS.map((p) => `./${p}.js`));
    for (const [out, specifiers] of imports) {
      expect(specifiers.length, out).toBeGreaterThan(0);
      const foreign = specifiers.filter((s) => !isBuiltin(s) && !(out === 'dist/hooks.js' && parts.has(s)));
      expect(foreign, `${out} leaves these to the runtime`).toEqual([]);
    }
    // The entry loads every part; no part loads another.
    expect([...new Set((imports.get('dist/hooks.js') ?? []).filter((s) => parts.has(s)))].sort()).toEqual([...parts].sort());
    // Positive control: the check reads a package as what it is.
    expect(['yaml', 'execa', '@modelcontextprotocol/sdk/server/mcp.js'].filter((s) => !isBuiltin(s))).toHaveLength(3);
  });

  it('no source map ships, and the bundles name none', async () => {
    const { texts } = await bundles();
    expect(walk(DIST).filter((abs) => abs.endsWith('.map')).map(rel)).toEqual([]);
    for (const [abs, text] of texts) expect(text.includes('sourceMappingURL'), rel(abs)).toBe(false);
  });

  it('copy-assets: every asset is its source, byte for byte, and none is missing', () => {
    const missing: string[] = [];
    for (const { dir, take } of ASSET_DIRS) {
      const src = join(MCP_ROOT, 'src', dir);
      for (const name of readdirSync(src).filter(take)) {
        const target = join(DIST, dir, name);
        if (!existsSync(target)) missing.push(`${rel(target)}: missing`);
        else if (!readFileSync(target).equals(readFileSync(join(src, name)))) missing.push(`${rel(target)}: differs from src`);
      }
    }
    expect(missing).toEqual([]);
  });

  it('nothing else: every file in dist/ is something the build makes — no per-file output, no output of a deleted source', async () => {
    const { texts } = await bundles();
    const assets = new Set(
      ASSET_DIRS.flatMap(({ dir, take }) =>
        readdirSync(join(MCP_ROOT, 'src', dir))
          .filter(take)
          .map((name) => join(DIST, dir, name)),
      ),
    );
    const built = new Set(texts.keys());
    const stale = walk(DIST)
      .filter((abs) => !built.has(abs) && abs !== SERVER_PATH && !assets.has(abs))
      .map(rel);
    expect(stale).toEqual([]);
  });
});
