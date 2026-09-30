/**
 * End-to-end proof that `cli/dev-guardian.mjs` loads `storage/*` /
 * `dashboard/*` LAZILY — Task 5 of the 2026-09-25 full review, item 2.
 *
 * `storage/db.ts` requires `node:sqlite` at MODULE LOAD TIME
 * (`createRequire(import.meta.url)('node:sqlite')`, top-level, not inside a
 * function). Before this fix, `cli/dev-guardian.mjs` statically imported
 * `storage/index.js` (and four sibling modules) at the top of the file, so
 * EVERY invocation — including `--help`, `check`, and `mcp-config`, none of
 * which touch a database — paid that cost: on a Node build lacking
 * `node:sqlite` (below this project's floor, Global Constraint 12), the
 * whole CLI crashed before `main()` even ran, with a raw
 * `ERR_UNKNOWN_BUILTIN_MODULE` stack trace, regardless of which subcommand
 * was requested.
 *
 * Two independent proofs, because neither alone rules out the defect:
 *
 * 1. A STATIC check on the source text: no top-level `import` line names any
 *    `storage/*` or `dashboard/*` module, and `loadDashboardModules` (the
 *    only place that may) reaches them via dynamic `import()`. This is the
 *    direct, mechanical property the fix requires.
 * 2. A BEHAVIOURAL check against an isolated copy of the CLI + a `dist/`
 *    with `storage/` and `dashboard/` removed (a safe, self-contained stand-in
 *    for "unavailable on this Node build" that never touches the real,
 *    shared `mcp/dist/` other test files depend on): `--help`, `check`, and
 *    `mcp-config` (preview mode) must still succeed; `status`/`dashboard`
 *    must fail with the friendly "MCP server not built" message this
 *    project's own `loadCiModules()` already establishes as the house style
 *    for this situation, never a raw stack trace.
 *
 * `isNodeSqliteUnavailable`'s own message/code matching is covered directly
 * in `mcp/test/unit/cli/lazyStorage.test.ts` — this file proves the
 * STRUCTURAL property (lazy loading) and the "not built" friendly path;
 * that one proves the Node-version-message predicate in isolation.
 */

import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { spawnSyncCapped, testTimeoutAbove } from '../helpers/spawnCap.js';

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const REAL_CLI = resolve(REPO_ROOT, 'cli', 'dev-guardian.mjs');
const REAL_DIST = resolve(REPO_ROOT, 'mcp', 'dist');
const TIMEOUT_MS = 15_000;
// Above the cap: a hung CLI is reported by the cap, naming it (R7-I1).
vi.setConfig({ testTimeout: testTimeoutAbove(TIMEOUT_MS) });

describe('cli/dev-guardian.mjs — storage/dashboard modules load lazily', () => {
  it('no top-level import names storage/* or dashboard/*', () => {
    const source = readFileSync(REAL_CLI, 'utf8');
    // Only the module's own top-of-file import statements — one per line,
    // this file's own convention (confirmed by every existing import in it).
    const topLevelImportLines = source.split('\n').filter((l) => /^import\s/.test(l));
    for (const line of topLevelImportLines) {
      expect(line).not.toMatch(/storage\/(index|migrations\/runner)\.js/);
      expect(line).not.toMatch(/dashboard\/(snapshot|renderStatus|renderHtml)\.js/);
    }
  });

  it('loadDashboardModules reaches them only via dynamic import()', () => {
    const source = readFileSync(REAL_CLI, 'utf8');
    const fnMatch = /async function loadDashboardModules\(\)[\s\S]*?\n\}/.exec(source);
    expect(fnMatch).toBeTruthy();
    const body = fnMatch?.[0] ?? '';
    expect(body).toMatch(/import\(['"]\.\.\/mcp\/dist\/storage\/index\.js['"]\)/);
    expect(body).toMatch(/import\(['"]\.\.\/mcp\/dist\/storage\/migrations\/runner\.js['"]\)/);
    expect(body).toMatch(/import\(['"]\.\.\/mcp\/dist\/dashboard\/snapshot\.js['"]\)/);
    expect(body).toMatch(/import\(['"]\.\.\/mcp\/dist\/dashboard\/renderStatus\.js['"]\)/);
    expect(body).toMatch(/import\(['"]\.\.\/mcp\/dist\/dashboard\/renderHtml\.js['"]\)/);
  });
});

describe('cli/dev-guardian.mjs — behaves correctly when storage/dashboard are unavailable', () => {
  let sandbox: string;
  let cli: string;
  let project: string;

  beforeAll(() => {
    // An isolated copy — never the real, shared mcp/dist/ other test files
    // (running possibly in parallel) depend on.
    sandbox = mkdtempSync(join(tmpdir(), 'guardian-lazy-'));
    const sandboxMcpDist = join(sandbox, 'mcp', 'dist');
    mkdirSync(sandboxMcpDist, { recursive: true });
    cpSync(REAL_DIST, sandboxMcpDist, { recursive: true });
    rmSync(join(sandboxMcpDist, 'storage'), { recursive: true, force: true });
    rmSync(join(sandboxMcpDist, 'dashboard'), { recursive: true, force: true });

    const sandboxCliDir = join(sandbox, 'cli');
    mkdirSync(sandboxCliDir, { recursive: true });
    cli = join(sandboxCliDir, 'dev-guardian.mjs');
    cpSync(REAL_CLI, cli);

    project = join(sandbox, 'proj');
    mkdirSync(project, { recursive: true });
  });

  afterAll(() => {
    rmSync(sandbox, { recursive: true, force: true });
  });

  function run(args: string[]) {
    const r = spawnSyncCapped(process.execPath, [cli, ...args], {
      encoding: 'utf8',
      env: { ...process.env, NO_COLOR: '1' },
      timeout: TIMEOUT_MS,
    });
    return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
  }

  it('--help still works with storage/dashboard missing', () => {
    const r = run(['--help']);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/dev-guardian/);
  });

  it('check --bash still works with storage/dashboard missing', () => {
    const r = run(['check', '--bash', 'echo hi']);
    expect(r.status).toBe(0);
    expect(r.stderr).not.toMatch(/ERR_MODULE_NOT_FOUND|Cannot find module/);
  });

  it('mcp-config preview (no --write) still works with storage/dashboard missing', () => {
    const r = run(['mcp-config', 'cursor']);
    expect(r.status).toBe(0);
    expect(r.stderr).not.toMatch(/ERR_MODULE_NOT_FOUND|Cannot find module/);
  });

  it('status fails with the friendly "not built" message, not a raw stack trace', () => {
    const r = run(['status', '--project', project]);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/MCP server not built/);
    expect(r.stderr).not.toMatch(/at Object|at async|ERR_MODULE_NOT_FOUND/);
  });

  it('dashboard fails with the friendly "not built" message, not a raw stack trace', () => {
    const r = run(['dashboard', '--project', project, '--no-open']);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/MCP server not built/);
    expect(r.stderr).not.toMatch(/at Object|at async|ERR_MODULE_NOT_FOUND/);
  });
});
