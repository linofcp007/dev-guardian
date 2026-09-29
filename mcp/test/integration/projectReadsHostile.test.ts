/**
 * The sweep of raw `fs` reads of the scanned repository (review of 3.0.0,
 * item 1(d)), against the shapes that broke them: a link to `/dev/zero`, a
 * FIFO, a link to a file outside the project, a `.guardian` that links out,
 * and an oversized file. One representative per mechanism — the tree hash
 * every scan computes, spec discovery, the report directory every scanner
 * writes into, `report_export`'s predictable output path, the budgets file
 * and `.guardianignore` — each driven through its real entry point.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { loadBudgets } from '../../src/budgets/budgets.js';
import type { PluginContext } from '../../src/context.js';
import { loadProjectExclusions } from '../../src/platform/guardianIgnore.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { discoverSpecs } from '../../src/surface/specDiscover.js';
import { TOOLS } from '../../src/tools/index.js';
import { ensureReportDir } from '../../src/tools/scanHelpers.js';
import { computeTreeHash } from '../../src/treeHash/computeTreeHash.js';
import { CAN_SYMLINK, POSIX } from '../helpers/fsCapabilities.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

beforeAll(async () => {
  await import('../../src/tools/reportExport.js');
});

const DIR_LINK = POSIX ? 'dir' : 'junction';

function gitInit(dir: string): void {
  const r = spawnSync('git', ['init', '-q', dir], { encoding: 'utf8' });
  expect(r.status).toBe(0);
}

async function within<T>(ms: number, p: Promise<T>): Promise<T> {
  const t0 = Date.now();
  const out = await p;
  expect(Date.now() - t0).toBeLessThan(ms);
  return out;
}

describe('computeTreeHash — hostile entries', () => {
  it.skipIf(!CAN_SYMLINK)('never reads through a link to a file outside the project', async () => {
    const project = makeTempDir('rh-tree-');
    const outside = makeTempDir('rh-outside-');
    gitInit(project);
    writeFileSync(join(project, 'a.txt'), 'a');
    writeFileSync(join(outside, 'secret'), 'one');
    symlinkSync(join(outside, 'secret'), join(project, 'leak'), 'file');

    const before = await computeTreeHash(project);
    writeFileSync(join(outside, 'secret'), 'two');
    const after = await computeTreeHash(project);

    // The link is hashed by what it names, not by the bytes at the end of it.
    expect(after).toBe(before);
  });

  it.skipIf(!POSIX)('a git-listed link to /dev/zero is hashed at once (POSIX)', async () => {
    const project = makeTempDir('rh-tree-');
    gitInit(project);
    writeFileSync(join(project, 'a.txt'), 'a');
    symlinkSync('/dev/zero', join(project, 'zero'));
    const h1 = await within(5000, computeTreeHash(project));
    const h2 = await within(5000, computeTreeHash(project, { forceFilesystemWalk: true }));
    expect(h1).toMatch(/^[0-9a-f]{64}$/);
    expect(h2).toMatch(/^[0-9a-f]{64}$/);
  }, 20_000);
});

describe('discoverSpecs — hostile candidates', () => {
  it.skipIf(!CAN_SYMLINK)('never reads a discovered spec that links outside the project', () => {
    const project = makeTempDir('rh-spec-');
    const outside = makeTempDir('rh-outside-');
    writeFileSync(join(outside, 'private.json'), '{"openapi":"3.0.0","info":{"title":"OUTSIDE"}}');
    symlinkSync(join(outside, 'private.json'), join(project, 'openapi.json'), 'file');
    const r = discoverSpecs(project);
    expect(r.specs.some((s) => s.text.includes('OUTSIDE'))).toBe(false);
  });

  it.skipIf(!POSIX)('a FIFO named openapi.yaml does not block discovery (POSIX)', () => {
    const project = makeTempDir('rh-spec-');
    expect(spawnSync('mkfifo', [join(project, 'openapi.yaml')]).status).toBe(0);
    const t0 = Date.now();
    const r = discoverSpecs(project);
    expect(Date.now() - t0).toBeLessThan(2000);
    expect(r.specs).toEqual([]);
  });

  it('an oversized spec is reported oversized, not read', () => {
    const project = makeTempDir('rh-spec-');
    writeFileSync(join(project, 'openapi.json'), `{"x":"${'a'.repeat(5 * 1024 * 1024 + 10)}"}`);
    const r = discoverSpecs(project);
    expect(r.specs).toEqual([]);
    expect(r.oversized).toHaveLength(1);
  });
});

describe('ensureReportDir — a .guardian that links out', () => {
  it.skipIf(!CAN_SYMLINK)('never creates the report directory at the end of the link', () => {
    const project = makeTempDir('rh-rep-');
    const outside = makeTempDir('rh-outside-');
    symlinkSync(outside, join(project, '.guardian'), DIR_LINK);
    const dir = ensureReportDir(project, '0123456789abcdef', 'sast');
    expect(readdirSync(outside)).toEqual([]);
    expect(relative(project, dir).startsWith('.guardian')).toBe(false);
    expect(existsSync(dir)).toBe(true);
  });

  it.skipIf(!CAN_SYMLINK)('never writes into a planted, predictable leaf that is a link', () => {
    const project = makeTempDir('rh-rep-');
    const outside = makeTempDir('rh-outside-');
    mkdirSync(join(project, '.guardian', 'reports'), { recursive: true });
    symlinkSync(outside, join(project, '.guardian', 'reports', 'surface-01234567'), DIR_LINK);
    const dir = ensureReportDir(project, '0123456789abcdef', 'surface');
    // What a scanner then does with it.
    writeFileSync(join(dir, 'semgrep.json'), '{}');
    expect(readdirSync(outside)).toEqual([]);
  });

  it('a plain project gets its report directory where it always did', () => {
    const project = makeTempDir('rh-rep-');
    const dir = ensureReportDir(project, '0123456789abcdef', 'sast');
    expect(dir).toBe(join(project, '.guardian', 'reports', 'sast-01234567'));
  });
});

describe('report_export — a planted output path', () => {
  function ctx(): PluginContext {
    const db = new Database(':memory:');
    runMigrations(db);
    return { storage: new Storage(db), shell: null, scriptsDir: '', progressNotifier: { send: () => {} } };
  }

  it.skipIf(!CAN_SYMLINK)('never creates the target of a dangling link at .guardian/reports/report-<title>/report.md', async () => {
    const project = makeTempDir('rh-export-');
    const outside = makeTempDir('rh-outside-');
    mkdirSync(join(project, '.guardian', 'reports', 'report-status'), { recursive: true });
    symlinkSync(join(outside, 'planted.md'), join(project, '.guardian', 'reports', 'report-status', 'report.md'), 'file');
    const tool = TOOLS.find((t) => t.name === 'report_export');
    if (tool === undefined) throw new Error('report_export not registered');

    const r = await tool.handler({ project_path: project, content_markdown: '# hi', title: 'Status' }, ctx());

    expect(r.ok).toBe(false);
    expect(existsSync(join(outside, 'planted.md'))).toBe(false);
  });
});

describe('budgets and .guardianignore — hostile files', () => {
  it.skipIf(!CAN_SYMLINK)('a budgets.yml that links outside the project is reported, not read', () => {
    const project = makeTempDir('rh-budget-');
    const outside = makeTempDir('rh-outside-');
    mkdirSync(join(project, '.guardian'));
    writeFileSync(join(outside, 'b.yml'), 'perf:\n  lcp_ms: 1\n');
    symlinkSync(join(outside, 'b.yml'), join(project, '.guardian', 'budgets.yml'), 'file');
    const r = loadBudgets(project);
    expect(r.kind).toBe('invalid');
    if (r.kind === 'invalid') expect(r.error).toMatch(/outside the project/);
  });

  it.skipIf(!POSIX)('a FIFO budgets.yml is answered at once (POSIX)', () => {
    const project = makeTempDir('rh-budget-');
    mkdirSync(join(project, '.guardian'));
    expect(spawnSync('mkfifo', [join(project, '.guardian', 'budgets.yml')]).status).toBe(0);
    const t0 = Date.now();
    const r = loadBudgets(project);
    expect(Date.now() - t0).toBeLessThan(2000);
    expect(r.kind).toBe('invalid');
  });

  it('an oversized .guardianignore is an error the caller reports, never "nothing excluded"', async () => {
    const project = makeTempDir('rh-ignore-');
    writeFileSync(join(project, '.guardianignore'), `${'x/\n'.repeat(400 * 1024)}`);
    const r = await loadProjectExclusions(project);
    expect(r).not.toBeNull();
    expect(r !== null && 'error' in r ? r.error : '').toMatch(/larger than the size cap/);
  });
});
