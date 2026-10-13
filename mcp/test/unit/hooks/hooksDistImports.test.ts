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
import type { BuildOptions, Metafile } from 'esbuild';
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
  loadGitSafety: ['execGit'],
  loadDbRegistry: ['databaseRegistration'],
  loadDistCheck: ['engineDamage'],
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
    // One file from the build — its parts it loads itself — and no per-file dist path.
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

  /** The hooks build, in memory, with its metafile. */
  const hooksBuild = async (): Promise<Metafile> => {
    const { hooksOptions } = (await import(pathToFileURL(join(MCP_ROOT, 'scripts', 'bundleOptions.mjs')).href)) as {
      hooksOptions: (root: string, digest: { bytes: number; sha256: string }) => BuildOptions;
    };
    const result = await build({ ...hooksOptions(MCP_ROOT, { bytes: 0, sha256: '' }), write: false, metafile: true, logLevel: 'silent' });
    return result.metafile;
  };

  it('its inputs are this repository’s sources — no npm package, no storage layer', async () => {
    const meta = await hooksBuild();
    const inputs = Object.keys(meta.inputs);
    expect(inputs).toContain('src/hooks/userDataDir.ts');
    expect(inputs).toContain('src/hooks/bashGuard.ts');
    // `<define:…>`: the engine's digest the build defines (`bundleOptions.mjs`, ENGINE_DIGEST).
    expect(inputs.filter((p) => !p.startsWith('src/') && p !== '<define:__GUARDIAN_ENGINE_DIGEST__>'), 'a package the hooks bundle inlines').toEqual([]);
    expect(inputs.filter((p) => /^src\/storage\/(?:db|index)\.ts$/.test(p)), 'the storage layer').toEqual([]);
    const imports = Object.values(meta.outputs).flatMap((o) => o.imports.map((i) => i.path));
    expect(imports).not.toContain('node:sqlite');
  });

  // 3.4.0: the bundle is split by event so that an event reads only what it
  // runs — 3.3.0's one file made a write parse the whole 368 KB, the shell
  // guard and `node:crypto` / `node:child_process` included (PostToolUse 66 →
  // 76 ms).
  it('each event loads only its own part: a write never the shell guard, no event but SessionStart crypto or child_process', async () => {
    const meta = await hooksBuild();
    const output = (entry: string): { sources: string[]; builtins: string[] } => {
      const o = Object.values(meta.outputs).find((x) => x.entryPoint === `src/${entry}.ts`);
      expect(o, entry).toBeDefined();
      return { sources: Object.keys(o?.inputs ?? {}), builtins: (o?.imports ?? []).map((i) => i.path).filter((p) => p.startsWith('node:')) };
    };
    const common = output('hooksEntry');
    const write = output('hooksWrite');
    const bash = output('hooksBash');
    expect(common.sources).toEqual(expect.arrayContaining(['src/hooks/configFile.ts', 'src/hooks/guardedPath.ts']));
    expect(write.sources).toContain('src/hooks/secretScan.ts');
    expect([...common.sources, ...write.sources].filter((s) => /bashGuard|pkgvet\//.test(s)), 'a write loads the shell guard or the vetting').toEqual([]);
    expect(bash.sources).toContain('src/hooks/bashGuard.ts');
    expect([...common.sources, ...bash.sources].filter((s) => /secretScan|pkgvet\/hookDecision/.test(s)), 'a Bash call loads the secret scan or the vetting').toEqual([]);
    const builtins = [...common.builtins, ...write.builtins, ...bash.builtins];
    expect(builtins.filter((b) => b === 'node:crypto' || b === 'node:child_process')).toEqual([]);
    // SessionStart's part is where they are.
    expect(output('hooksSession').builtins).toEqual(expect.arrayContaining(['node:crypto', 'node:child_process']));
  });
});
