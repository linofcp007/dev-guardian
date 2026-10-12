/**
 * The committed `mcp/dist/` is what `npm run build` makes of `mcp/src/` —
 * byte for byte (review 3.0, R7).
 *
 * The repository IS the distribution: Claude Code runs `mcp/dist/server.js`
 * and the hooks run `mcp/dist/hooks/*.js` straight from the clone, with no
 * install-time build (CLAUDE.md, "Commit the compiled mcp/dist/"). A change
 * to `src/` committed without a rebuild ships the OLD behaviour, with every
 * test green — the tests import `src/`. Nothing checked it.
 *
 * What `npm run build` puts in `dist/`, and what is checked here:
 *
 * - `tsc -p tsconfig.json`: every `.js` and `.js.map` — compiled here in
 *   memory with the TypeScript compiler API and the same tsconfig, and
 *   compared with the committed files. (~8 s: the whole program.)
 * - `scripts/bundle.mjs`: `dist/server.js` and `dist/cli.js`, which replace
 *   tsc's — rebuilt in memory with the same esbuild options
 *   (`scripts/bundleOptions.mjs`, shared with the build so the two cannot
 *   differ) and compared. The bundles inline `node_modules`, so a checkout
 *   whose `node_modules` is not the lockfile's (`npm ci`) can fail this part
 *   legitimately. And each imports nothing but Node's builtins (esbuild's
 *   metafile): what a plugin install — no `node_modules` — can load.
 * - `scripts/copy-assets.mjs`: the migrations' `.sql` and the legacy rules
 *   templates, mirrored from `src/` — compared with their sources.
 * - Nothing else: a file in `dist/` that none of those makes (the output of a
 *   `src/` file since deleted) is stale, and fails.
 *
 * The fix for a failure is `npm run build` and committing `mcp/dist/` with the
 * change — never editing a file in `dist/`.
 */

import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { isBuiltin } from 'node:module';
import { pathToFileURL } from 'node:url';
import type { BuildOptions } from 'esbuild';
import { build } from 'esbuild';
import ts from 'typescript';
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

/** What `tsc -p tsconfig.json` emits, by absolute output path — in memory, nothing written. */
function compileSrc(): Map<string, string> {
  const configPath = join(MCP_ROOT, 'tsconfig.json');
  const read = ts.readConfigFile(configPath, (p) => ts.sys.readFile(p));
  if (read.error !== undefined) throw new Error(ts.flattenDiagnosticMessageText(read.error.messageText, '\n'));
  const parsed = ts.parseJsonConfigFileContent(read.config, ts.sys, MCP_ROOT);
  const program = ts.createProgram({ rootNames: parsed.fileNames, options: parsed.options });
  const emitted = new Map<string, string>();
  const result = program.emit(undefined, (fileName, text) => emitted.set(resolve(fileName), text));
  if (result.emitSkipped) throw new Error('tsc skipped the emit');
  return emitted;
}

interface Bundled {
  /** Each bundle's text, by its absolute path in `dist/`. */
  texts: Map<string, string>;
  /** Each bundle's imports esbuild left to the runtime, by `dist/<name>.js`. */
  imports: Map<string, string[]>;
}

const bundleOptionsModule = async (): Promise<{ BUNDLES: string[]; bundleOptions: (root: string) => BuildOptions }> =>
  (await import(pathToFileURL(join(MCP_ROOT, 'scripts', 'bundleOptions.mjs')).href)) as {
    BUNDLES: string[];
    bundleOptions: (root: string) => BuildOptions;
  };

/** The bundles' absolute paths in `dist/` — tsc emits a file at each, which the bundle replaces. */
const BUNDLE_PATHS: ReadonlySet<string> = new Set((await bundleOptionsModule()).BUNDLES.map((name) => join(DIST, `${name}.js`)));

/** What `scripts/bundle.mjs` writes to `dist/server.js` and `dist/cli.js`, in memory. */
async function bundleAll(): Promise<Bundled> {
  const mod = await bundleOptionsModule();
  const result = await build({ ...mod.bundleOptions(MCP_ROOT), write: false, metafile: true, logLevel: 'silent' });
  const texts = new Map((result.outputFiles ?? []).filter((f) => f.path.endsWith('.js')).map((f) => [resolve(f.path), f.text]));
  const imports = new Map(Object.entries(result.metafile.outputs).map(([out, meta]) => [out, meta.imports.map((i) => i.path)]));
  return { texts, imports };
}

/** The directories `scripts/copy-assets.mjs` mirrors from `src/` into `dist/`, with its filter. */
const ASSET_DIRS: ReadonlyArray<{ dir: string; take: (name: string) => boolean }> = [
  { dir: join('storage', 'migrations'), take: (name) => name.endsWith('.sql') },
  { dir: join('hostsetup', 'legacyRulesTemplates'), take: () => true },
];

/** The emitted files the committed `dist/` does not hold byte for byte (`dist/server.js` and `dist/cli.js` are the bundles'). */
function tscDrift(emitted: ReadonlyMap<string, string>): string[] {
  return [...emitted]
    .filter(([abs]) => !BUNDLE_PATHS.has(abs))
    .filter(([abs, text]) => !existsSync(abs) || readFileSync(abs, 'utf8') !== text)
    .map(([abs]) => `${rel(abs)}: ${existsSync(abs) ? 'differs from' : 'missing, but'} what tsc makes of src/ — run npm run build`);
}

describe('the committed mcp/dist is the build of mcp/src', () => {
  let compiled: Map<string, string> | undefined;
  /** Compiled once, by the first test that needs it. */
  const emitted = (): Map<string, string> => (compiled ??= compileSrc());

  it('tsc: every file it emits is committed, byte for byte (dist/server.js and dist/cli.js are the bundles, checked below)', () => {
    expect(emitted().size).toBeGreaterThan(300);
    expect(tscDrift(emitted())).toEqual([]);
  });

  it('positive control: one changed character in one emitted file is reported, and only that file', () => {
    const altered = new Map(emitted());
    const [abs, text] = [...altered].find(([p]) => p.endsWith('.js') && !BUNDLE_PATHS.has(p)) ?? ['', ''];
    altered.set(abs, `${text} `);
    expect(tscDrift(altered)).toEqual([`${rel(abs)}: differs from what tsc makes of src/ — run npm run build`]);
  });

  let bundled: Bundled | undefined;
  /** Bundled once, by the first test that needs it. */
  const bundles = async (): Promise<Bundled> => (bundled ??= await bundleAll());

  it('the bundles: dist/server.js and dist/cli.js are what scripts/bundle.mjs makes of src/', async () => {
    const { texts } = await bundles();
    expect([...texts.keys()].sort()).toEqual([...BUNDLE_PATHS].sort());
    expect([...BUNDLE_PATHS].map(rel).sort()).toEqual(['cli.js', 'server.js']);
    for (const [abs, text] of texts) {
      // Not toBe on megabytes of text: the failure should be a sentence.
      expect(
        existsSync(abs) && readFileSync(abs, 'utf8') === text,
        `${rel(abs)} differs from a fresh bundle of src/ — run npm run build (with node_modules from npm ci)`,
      ).toBe(true);
    }
  });

  it('the bundles import nothing but Node builtins — every package is inlined, as an install without node_modules needs', async () => {
    const { imports } = await bundles();
    expect([...imports.keys()].sort()).toEqual(['dist/cli.js', 'dist/server.js']);
    for (const [out, specifiers] of imports) {
      expect(specifiers.length, out).toBeGreaterThan(0);
      expect(specifiers.filter((s) => !isBuiltin(s)), `${out} leaves these to the runtime`).toEqual([]);
    }
    // Positive control: the check reads a package as what it is.
    expect(['yaml', 'execa', '@modelcontextprotocol/sdk/server/mcp.js'].filter((s) => !isBuiltin(s))).toHaveLength(3);
  });

  it('copy-assets: every asset is its source, byte for byte, and none is missing', () => {
    const drift: string[] = [];
    for (const { dir, take } of ASSET_DIRS) {
      const src = join(MCP_ROOT, 'src', dir);
      for (const name of readdirSync(src).filter(take)) {
        const target = join(DIST, dir, name);
        if (!existsSync(target)) drift.push(`${rel(target)}: missing`);
        else if (!readFileSync(target).equals(readFileSync(join(src, name)))) drift.push(`${rel(target)}: differs from src`);
      }
    }
    expect(drift).toEqual([]);
  });

  it('nothing else: every file in dist/ is something the build makes (no output of a deleted source)', () => {
    const assets = new Set(
      ASSET_DIRS.flatMap(({ dir, take }) =>
        readdirSync(join(MCP_ROOT, 'src', dir))
          .filter(take)
          .map((name) => join(DIST, dir, name)),
      ),
    );
    const built = emitted();
    const stale = walk(DIST)
      .filter((abs) => !built.has(abs) && !assets.has(abs))
      .map(rel);
    expect(stale).toEqual([]);
  });
});
