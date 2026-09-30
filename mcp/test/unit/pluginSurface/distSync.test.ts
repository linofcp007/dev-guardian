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
 * - `scripts/bundle.mjs`: `dist/server.js`, which replaces tsc's — rebuilt in
 *   memory with the same esbuild options (`scripts/bundleOptions.mjs`, shared
 *   with the build so the two cannot differ) and compared. The bundle inlines
 *   `node_modules`, so a checkout whose `node_modules` is not the lockfile's
 *   (`npm ci`) can fail this part legitimately.
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

/** What `scripts/bundle.mjs` writes to `dist/server.js`, in memory. */
async function bundleServer(): Promise<string> {
  const url = pathToFileURL(join(MCP_ROOT, 'scripts', 'bundleOptions.mjs')).href;
  const mod = (await import(url)) as { bundleOptions: (root: string) => BuildOptions };
  const result = await build({ ...mod.bundleOptions(MCP_ROOT), write: false, logLevel: 'silent' });
  const file = result.outputFiles?.find((f) => resolve(f.path) === join(DIST, 'server.js'));
  if (file === undefined) throw new Error('esbuild produced no dist/server.js');
  return file.text;
}

/** The directories `scripts/copy-assets.mjs` mirrors from `src/` into `dist/`, with its filter. */
const ASSET_DIRS: ReadonlyArray<{ dir: string; take: (name: string) => boolean }> = [
  { dir: join('storage', 'migrations'), take: (name) => name.endsWith('.sql') },
  { dir: join('hostsetup', 'legacyRulesTemplates'), take: () => true },
];

/** The emitted files the committed `dist/` does not hold byte for byte (`dist/server.js` is the bundle's). */
function tscDrift(emitted: ReadonlyMap<string, string>): string[] {
  return [...emitted]
    .filter(([abs]) => abs !== join(DIST, 'server.js'))
    .filter(([abs, text]) => !existsSync(abs) || readFileSync(abs, 'utf8') !== text)
    .map(([abs]) => `${rel(abs)}: ${existsSync(abs) ? 'differs from' : 'missing, but'} what tsc makes of src/ — run npm run build`);
}

describe('the committed mcp/dist is the build of mcp/src', () => {
  let compiled: Map<string, string> | undefined;
  /** Compiled once, by the first test that needs it. */
  const emitted = (): Map<string, string> => (compiled ??= compileSrc());

  it('tsc: every file it emits is committed, byte for byte (dist/server.js is the bundle, checked below)', () => {
    expect(emitted().size).toBeGreaterThan(300);
    expect(tscDrift(emitted())).toEqual([]);
  });

  it('positive control: one changed character in one emitted file is reported, and only that file', () => {
    const altered = new Map(emitted());
    const [abs, text] = [...altered].find(([p]) => p.endsWith('.js') && p !== join(DIST, 'server.js')) ?? ['', ''];
    altered.set(abs, `${text} `);
    expect(tscDrift(altered)).toEqual([`${rel(abs)}: differs from what tsc makes of src/ — run npm run build`]);
  });

  it('the bundle: dist/server.js is what scripts/bundle.mjs makes of src/', async () => {
    const bundled = await bundleServer();
    // Not toBe on 1.5 MB of text: the failure should be a sentence.
    expect(
      readFileSync(join(DIST, 'server.js'), 'utf8') === bundled,
      'dist/server.js differs from a fresh bundle of src/ — run npm run build (with node_modules from npm ci)',
    ).toBe(true);
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
