/**
 * The hook dispatcher (`hooks/guardian-hook.mjs`) loads its detectors from one
 * bundle, `mcp/dist/hooks.js` (`src/hooksEntry.ts`), in an install that has no
 * `node_modules` — the repository is the distribution (CLAUDE.md). A loader it
 * calls that the bundle lacks, or one whose module lacks a function it takes,
 * fails, and the dispatcher fails OPEN: that guard is silently off (SessionStart
 * says so, `hooksDispatcher.test.ts`). Until 3.3.0 the dispatcher imported 27
 * of tsc's per-file modules, and this file walked their imports; the build now
 * emits no per-file output (review 8, finding 3).
 *
 * Held here:
 *
 * - every loader the dispatcher calls is one the bundle exports, and each
 *   resolves to a module with the functions the dispatcher takes from it —
 *   on the committed `dist/hooks.js`;
 * - the bundle's inputs are this repository's own sources, no npm package and
 *   no storage layer (`node:sqlite`): the hook runs on every tool call, and a
 *   package one detector pulls in grows every call's load. Review of 3.0, W2E:
 *   the data directory's resolution, once mirrored in `hooks/dataRegistry.ts`
 *   and `storage/userData.ts`, is one module, `hooks/userDataDir.ts` — a first
 *   attempt that imported the storage layer from the hook broke the CLI.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import type { BuildOptions } from 'esbuild';
import { describe, expect, it, vi } from 'vitest';
import { MCP_ROOT } from '../../helpers/tsxNode.js';

vi.setConfig({ testTimeout: 60_000 });

const DISPATCHER = join(MCP_ROOT, '..', 'hooks', 'guardian-hook.mjs');
const BUNDLE = join(MCP_ROOT, 'dist', 'hooks.js');

/** The functions the dispatcher takes from each loader's module. */
const USED: Readonly<Record<string, readonly string[]>> = {
  loadConfigFile: ['readSmallJsonFile', 'walkLinksUnder', 'readSmallTextFile', 'isNetworkPath'],
  loadGuardedPath: ['guardedPath', 'hardLinkedTo'],
  loadBashGuard: ['assessBashCommand'],
  loadInstallGate: ['mayInstall'],
  loadInstallVetting: ['decideInstallCommand'],
  loadSecretScan: ['scanForSecrets'],
  loadSettingsGuard: ['isClaudeSettingsPath', 'newlyLoosened', 'applyEdit'],
  loadDataRegistry: ['writesRegistry'],
  loadGitSafety: ['execGitSync'],
  loadDbRegistry: ['databaseRegistration'],
};

/** Every loader the dispatcher names: `detector('loadX')` calls and the `GUARD_MODULES` table. */
function dispatcherLoaders(): string[] {
  const text = readFileSync(DISPATCHER, 'utf8');
  const out = new Set<string>();
  for (const m of text.matchAll(/detector\('(load\w+)'\)/g)) out.add(m[1] ?? '');
  for (const m of text.matchAll(/\bloader: '(load\w+)'/g)) out.add(m[1] ?? '');
  return [...out].sort();
}

describe('the hooks bundle has what the dispatcher loads', () => {
  it('the dispatcher loads every detector through the bundle, by the loaders it exports', () => {
    expect(dispatcherLoaders()).toEqual(Object.keys(USED).sort());
    const text = readFileSync(DISPATCHER, 'utf8');
    // One file from the build, and no per-file dist path.
    expect(text).toContain("join(PLUGIN_ROOT, 'mcp', 'dist', 'hooks.js')");
    expect(text).not.toMatch(/'dist', '(?:hooks|pkgvet|platform|storage)', /);
  });

  it('each loader of the committed dist/hooks.js resolves to a module with the functions the dispatcher takes', async () => {
    const bundle = (await import(pathToFileURL(BUNDLE).href)) as Record<string, unknown>;
    const missing: string[] = [];
    for (const [loader, names] of Object.entries(USED)) {
      const load = bundle[loader];
      if (typeof load !== 'function') {
        missing.push(`${loader}: not exported`);
        continue;
      }
      const mod = (await (load as () => Promise<Record<string, unknown>>)()) as Record<string, unknown>;
      for (const name of names) if (typeof mod[name] !== 'function') missing.push(`${loader}: ${name}`);
    }
    expect(missing).toEqual([]);
  });

  it('its inputs are this repository’s sources — no npm package, no storage layer', async () => {
    const options = (
      (await import(pathToFileURL(join(MCP_ROOT, 'scripts', 'bundleOptions.mjs')).href)) as { bundleOptions: (root: string) => BuildOptions }
    ).bundleOptions(MCP_ROOT);
    const entries = options.entryPoints as Array<{ in: string; out: string }>;
    const hooks = entries.filter((e) => e.out === 'hooks');
    expect(hooks).toHaveLength(1);
    const result = await build({ ...options, entryPoints: hooks, write: false, metafile: true, logLevel: 'silent' });
    const inputs = Object.keys(result.metafile.inputs);
    expect(inputs).toContain('src/hooks/userDataDir.ts');
    expect(inputs).toContain('src/hooks/bashGuard.ts');
    expect(inputs.filter((p) => !p.startsWith('src/')), 'a package the hooks bundle inlines').toEqual([]);
    expect(inputs.filter((p) => /^src\/storage\/(?:db|index)\.ts$/.test(p)), 'the storage layer').toEqual([]);
    const imports = Object.values(result.metafile.outputs).flatMap((o) => o.imports.map((i) => i.path));
    expect(imports).not.toContain('node:sqlite');
  });
});
