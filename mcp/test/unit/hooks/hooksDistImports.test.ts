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
  loadHeartbeat: ['writeHeartbeat', 'pruneHeartbeats'],
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

  // The session mark is the one thing a hook writes, and only SessionStart
  // writes it: no other event may even parse the module (hooks-heartbeat).
  it('T-25 the session mark lives in the session part alone, and brings no package', async () => {
    const meta = await hooksBuild();
    const sources = (entry: string): string[] =>
      Object.keys(Object.values(meta.outputs).find((x) => x.entryPoint === `src/${entry}.ts`)?.inputs ?? {});
    expect(sources('hooksSession')).toContain('src/hooks/heartbeat.ts');
    for (const part of ['hooksEntry', 'hooksBash', 'hooksWrite', 'hooksVet']) {
      expect(sources(part), part).not.toContain('src/hooks/heartbeat.ts');
    }
    expect(Object.keys(meta.inputs).filter((p) => !p.startsWith('src/') && p !== '<define:__GUARDIAN_ENGINE_DIGEST__>')).toEqual([]);
    // What the module itself reaches for: Node, the bounded reader and the data directory's path — no storage.
    const reaches = (meta.inputs['src/hooks/heartbeat.ts']?.imports ?? []).map((i) => i.path);
    expect(reaches.length).toBeGreaterThan(0);
    // (`<define:…>` is the build's own injection, listed against every input.)
    expect(
      reaches.filter((p) => !p.startsWith('node:') && !p.startsWith('<define:') && !/^src\/hooks\/(?:configFile|userDataDir)\.ts$/.test(p)),
    ).toEqual([]);
    // The dispatcher takes it through its loader, as it takes every detector.
    expect(dispatcherLoaders()).toContain('loadHeartbeat');
  });
});

// Bugfix `hook-unc-cwd-hang`: which folders a call works in is chosen by a module of the common part, and a folder on
// the network is asked about by a part of its own (`hooksProbe`), so that only a call with such a folder parses it
// and its `node:child_process`. Task 2 merges these two loaders into `USED` above; until then they are held here, so
// that the loaders the dispatcher does not name yet leave the two tests over `USED` as they are.
describe('hook-unc-cwd-hang', () => {
  const UNC_LOADERS: Readonly<Record<string, readonly string[]>> = {
    loadSessionDirs: ['chooseSessionDirs', 'unreachableLines'],
    loadFolderProbe: ['probeFolders'],
  };

  it('T-09 the bundle gives the dispatcher what it loads: loadSessionDirs and loadFolderProbe, named by the dispatcher and resolving to the two functions', async () => {
    expect(dispatcherLoaders()).toEqual(expect.arrayContaining(Object.keys(UNC_LOADERS)));
    const bundle = (await import(pathToFileURL(BUNDLE).href)) as Record<string, unknown>;
    const missing: string[] = [];
    for (const [loader, names] of Object.entries(UNC_LOADERS)) {
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

  it('T-09 the common, write, shell and session parts gain no node:child_process from this; hooksProbe is the one, with the session part, that loads it', async () => {
    const { hooksOptions, HOOK_PARTS } = (await import(pathToFileURL(join(MCP_ROOT, 'scripts', 'bundleOptions.mjs')).href)) as {
      hooksOptions: (root: string, digest: { bytes: number; sha256: string }) => BuildOptions;
      HOOK_PARTS: readonly string[];
    };
    // `dist/<part>.js` for each of these is what `distSync.test.ts` lists as BUNDLE_NAMES.
    expect(HOOK_PARTS).toContain('hooksProbe');
    const meta = (await build({ ...hooksOptions(MCP_ROOT, { bytes: 0, sha256: '' }), write: false, metafile: true, logLevel: 'silent' })).metafile;
    const output = (entry: string): { sources: string[]; builtins: string[] } => {
      const o = Object.values(meta.outputs).find((x) => x.entryPoint === `src/${entry}.ts`);
      expect(o, entry).toBeDefined();
      return { sources: Object.keys(o?.inputs ?? {}), builtins: (o?.imports ?? []).map((i) => i.path).filter((p) => p.startsWith('node:')) };
    };
    const withChildProcess = ['hooksEntry', 'hooksWrite', 'hooksBash', 'hooksSession', 'hooksProbe']
      .filter((entry) => output(entry).builtins.includes('node:child_process'))
      .sort();
    expect(withChildProcess).toEqual(['hooksProbe', 'hooksSession']);
    expect(output('hooksEntry').sources).toContain('src/hooks/sessionDirs.ts');
    expect(output('hooksProbe').sources.sort()).toEqual(['src/hooks/folderProbe.ts', 'src/hooksProbe.ts']);
  });
});
