/**
 * End-to-end proof that `cli/dev-guardian.mjs` loads the storage layer
 * (`node:sqlite`) and the scan pipeline LAZILY — Task 5 of the 2026-09-25 full
 * review, item 2; reshaped in 3.2.1, when the CLI moved onto the bundle.
 *
 * `--help`, `check`, `mcp-config` and `ci-init` touch no database, and must
 * run on any Node — including one without `node:sqlite` (below this project's
 * floor, 22.13), where a CLI that loaded it at start crashed every
 * invocation, before `main()` ran, with a raw `ERR_UNKNOWN_BUILTIN_MODULE`.
 *
 * Since 3.2.1 the CLI imports one module, the self-contained bundle
 * `mcp/dist/cli.js` (`mcp/src/cli.ts`; why: `pluginInstall.test.ts`), and
 * reaches the scan pipeline and the storage layer only through its
 * `load*Modules()` functions, whose dynamic `import()`s esbuild keeps lazy.
 * Two independent proofs, because neither alone rules out the defect:
 *
 * 1. STATIC, on the source text: the CLI imports Node builtins statically,
 *    and the bundle with its one `import()` — after it turns Node's compile
 *    cache on, which only caches a module loaded after the call (3.3.0,
 *    review 8 finding 17).
 * 2. BEHAVIOURAL, on an isolated copy of the CLI and the bundle, run with a
 *    preload that makes `node:sqlite` unavailable the way an old Node does
 *    (`ERR_UNKNOWN_BUILTIN_MODULE`): `--help`, `check` and `mcp-config` still
 *    succeed; `status`, `dashboard`, `db adopt`, `import-sarif` and `scan`
 *    fail with one line — "this command requires Node.js >= 22.13" — and
 *    exit 3, never a stack trace.
 *
 * `isNodeSqliteUnavailable`'s own message/code matching is covered directly
 * in `mcp/test/unit/cli/lazyStorage.test.ts`.
 */

import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { spawnSyncCapped, timeoutAbove } from '../helpers/spawnCap.js';

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const REAL_CLI = resolve(REPO_ROOT, 'cli', 'dev-guardian.mjs');
const REAL_DIST = resolve(REPO_ROOT, 'mcp', 'dist');
const TIMEOUT_MS = 15_000;
// Above the cap: a hung CLI is reported by the cap, naming it (R7-I1).
vi.setConfig({ testTimeout: timeoutAbove(TIMEOUT_MS) });

/** Every module specifier a source names: static imports and re-exports, and dynamic `import()`. */
function specifiers(source: string): { staticSpecs: string[]; dynamicSpecs: string[] } {
  const staticSpecs = [...source.matchAll(/^(?:import|export)\s[^;]*?\sfrom\s*['"]([^'"]+)['"]/gm)].map((m) => m[1] ?? '');
  const dynamicSpecs = [...source.matchAll(/\bimport\(\s*['"]?([^'")]*)/g)].map((m) => m[1] ?? '');
  return { staticSpecs, dynamicSpecs };
}

describe('cli/dev-guardian.mjs — imports Node builtins and the bundle, nothing else', () => {
  it('every static import names a node: builtin', () => {
    const { staticSpecs } = specifiers(readFileSync(REAL_CLI, 'utf8'));
    expect(staticSpecs.length).toBeGreaterThan(0);
    expect(staticSpecs.filter((s) => !s.startsWith('node:'))).toEqual([]);
  });

  it('its one dynamic import() is the bundle — the lazy loading inside it is the bundle’s', () => {
    expect(specifiers(readFileSync(REAL_CLI, 'utf8')).dynamicSpecs).toEqual(['../mcp/dist/cli.js']);
  });

  it('turns the compile cache on before it loads the bundle', () => {
    const source = readFileSync(REAL_CLI, 'utf8');
    const enable = source.indexOf('module.enableCompileCache?.()');
    const load = source.indexOf("await import('../mcp/dist/cli.js')");
    expect(enable).toBeGreaterThan(0);
    expect(load).toBeGreaterThan(enable);
  });

  it('positive control: the reader sees a per-file dist import, static or dynamic', () => {
    const { staticSpecs, dynamicSpecs } = specifiers(
      [
        "import { a } from '../mcp/dist/storage/index.js';",
        "import {\n  b,\n  c,\n} from '../mcp/dist/cli.js';",
        "const m = await import('../mcp/dist/ci/types.js');",
      ].join('\n'),
    );
    expect(staticSpecs).toEqual(['../mcp/dist/storage/index.js', '../mcp/dist/cli.js']);
    expect(dynamicSpecs).toEqual(['../mcp/dist/ci/types.js']);
  });
});

describe('cli/dev-guardian.mjs — on a Node without node:sqlite', () => {
  let sandbox: string;
  let cli: string;
  let noSqlite: string;
  let project: string;

  beforeAll(() => {
    // An isolated copy — the CLI, its bundle, and what the bundle reads at
    // run time (the migrations; server.js, whose path mcp-config prints).
    sandbox = mkdtempSync(join(tmpdir(), 'guardian-lazy-'));
    const dist = join(sandbox, 'mcp', 'dist');
    mkdirSync(join(sandbox, 'cli'), { recursive: true });
    mkdirSync(dist, { recursive: true });
    cli = join(sandbox, 'cli', 'dev-guardian.mjs');
    cpSync(REAL_CLI, cli);
    for (const file of ['cli.js', 'server.js']) cpSync(join(REAL_DIST, file), join(dist, file));
    cpSync(join(REAL_DIST, 'storage', 'migrations'), join(dist, 'storage', 'migrations'), { recursive: true });

    // What an old Node does on `node:sqlite` — through every require, which
    // is how storage/db.ts loads it (createRequire, at first use).
    noSqlite = join(sandbox, 'no-sqlite.cjs');
    writeFileSync(
      noSqlite,
      [
        "const Module = require('node:module');",
        'const load = Module._load;',
        'Module._load = function (request, ...rest) {',
        "  if (request === 'node:sqlite') {",
        "    const e = new Error('No such built-in module: node:sqlite');",
        "    e.code = 'ERR_UNKNOWN_BUILTIN_MODULE';",
        '    throw e;',
        '  }',
        '  return load.call(this, request, ...rest);',
        '};',
        '',
      ].join('\n'),
    );

    project = join(sandbox, 'proj');
    mkdirSync(project, { recursive: true });
  });

  afterAll(() => {
    rmSync(sandbox, { recursive: true, force: true });
  });

  function run(args: string[], opts: { sqlite: boolean } = { sqlite: false }) {
    const r = spawnSyncCapped(process.execPath, [...(opts.sqlite ? [] : ['--require', noSqlite]), cli, ...args], {
      encoding: 'utf8',
      env: { ...process.env, NO_COLOR: '1' },
      timeout: TIMEOUT_MS,
    });
    return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
  }

  it('positive control: the preload makes node:sqlite unavailable, with the code an old Node uses', () => {
    const r = spawnSyncCapped(
      process.execPath,
      ['--require', noSqlite, '-e', "try { require('node:sqlite'); } catch (e) { process.stdout.write(e.code); }"],
      { encoding: 'utf8', timeout: TIMEOUT_MS },
    );
    expect(r.stdout).toBe('ERR_UNKNOWN_BUILTIN_MODULE');
  });

  it('positive control: without the preload, the same copy runs status', () => {
    const r = run(['status', '--project', project], { sqlite: true });
    expect(r.status, r.stderr).toBe(0);
  });

  it('--help still works', () => {
    const r = run(['--help']);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/dev-guardian/);
  });

  it('check --bash still works', () => {
    const r = run(['check', '--bash', 'echo hi']);
    expect(r.status).toBe(0);
    expect(r.stderr).toBe('');
  });

  it('mcp-config preview (no --write) still works', () => {
    const r = run(['mcp-config', 'cursor']);
    expect(r.status).toBe(0);
    expect(r.stderr).not.toMatch(/sqlite|ERR_|Cannot find/i);
  });

  const NEEDS_SQLITE: ReadonlyArray<[string, () => string[]]> = [
    ['status', () => ['status', '--project', project]],
    ['dashboard', () => ['dashboard', '--project', project, '--no-open']],
    ['db adopt', () => ['db', 'adopt', '--project', project]],
    ['import-sarif', () => ['import-sarif', join(project, 'none.sarif'), '--project', project]],
    ['scan', () => ['scan', '--project', project]],
  ];

  for (const [name, args] of NEEDS_SQLITE) {
    it(`${name} fails with one line naming the Node it needs, exit 3 — not a stack trace`, () => {
      const r = run(args());
      expect(r.status).toBe(3);
      expect(r.stderr).toMatch(/^dev-guardian: this command requires Node\.js >= 22\.13 \(built-in node:sqlite support\)\. Current: v[\d.]+\.\n$/);
    });
  }
});

// Review 8, finding 17: the CLI compiled its 3.9 MB bundle from scratch on
// every run. With Node's compile cache on before the bundle loads, a run with
// no NODE_COMPILE_CACHE of its own writes the cache under the OS temp
// directory — the next run reads it instead of compiling.
describe('cli/dev-guardian.mjs — Node compile cache', () => {
  it('writes the compile cache under the OS temp directory, with no NODE_COMPILE_CACHE set', () => {
    const tmp = mkdtempSync(join(tmpdir(), 'guardian-ccache-'));
    try {
      const env: NodeJS.ProcessEnv = { ...process.env, TMP: tmp, TEMP: tmp, TMPDIR: tmp };
      delete env['NODE_COMPILE_CACHE'];
      delete env['NODE_DISABLE_COMPILE_CACHE'];
      const r = spawnSyncCapped(process.execPath, [REAL_CLI, '--help'], { encoding: 'utf8', env, timeout: TIMEOUT_MS });
      expect(r.status).toBe(0);
      const cache = join(tmp, 'node-compile-cache');
      expect(existsSync(cache)).toBe(true);
      expect(readdirSync(cache, { recursive: true }).length).toBeGreaterThan(0);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});
