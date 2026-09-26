/**
 * What a scoped scan and the `.guardianignore` result filter cost on disk:
 * one check per DIRECTORY, never one per file or per finding.
 *
 * `realpathSync.native` opens a handle on Windows; one per file made a
 * 50 000-file directory scope take 11 s where the walk itself took 0.25 s,
 * synchronously and on a cache hit too. `existsSync` per finding cost the
 * result filter 2-4 s on 20 000 findings. Timing tests would be flaky; these
 * count the calls instead, through a pass-through `node:fs`.
 *
 * The containment checks themselves (a link out of the project, last
 * component or mid-path) are `scope.test.ts`'s; this file only pins that the
 * memoised form is still reached for every file.
 */

import { execa } from 'execa';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

const calls = vi.hoisted(() => ({ realpath: [] as string[], exists: [] as string[] }));

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>();
  const native = (p: import('node:fs').PathLike): string => {
    calls.realpath.push(String(p));
    return actual.realpathSync.native(p);
  };
  const realpathSync = Object.assign((p: import('node:fs').PathLike): string => actual.realpathSync(p), { native });
  const existsSync = (p: import('node:fs').PathLike): boolean => {
    calls.exists.push(String(p));
    return actual.existsSync(p);
  };
  return { ...actual, realpathSync, existsSync, default: { ...actual, realpathSync, existsSync } };
});

import type { PluginContext } from '../../../src/context.js';
import { isProjectPath, loadProjectExclusions, projectPathTest } from '../../../src/platform/guardianIgnore.js';
import { resolveProjectPath } from '../../../src/platform/projectPath.js';
import { resolveScope, ScanScopeInput } from '../../../src/platform/scope.js';
import { makeFinding } from '../../../src/runners/scannerParsers/index.js';
import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { Storage } from '../../../src/storage/index.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { makeScanTool, type ScannerInvocation } from '../../../src/tools/scanToolFactory.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';
import { okResult } from '../../helpers/toolResult.js';

/** Real `git` processes: a file-level ceiling for a loaded full-suite run. */
vi.setConfig({ testTimeout: 60_000 });

afterAll(cleanupTempDirs);

beforeEach(() => {
  calls.realpath.length = 0;
  calls.exists.length = 0;
});

const DIRS = ['bulk/d0', 'bulk/d1', 'bulk/d1/deep'];
const PER_DIR = 40;

/** A project holding `PER_DIR` files in each of `DIRS` — 120 files, 3 directories. */
function tree(): { dir: string; files: string[] } {
  const dir = resolveProjectPath(makeTempDir('path-cost-')).path;
  const files: string[] = [];
  for (const d of DIRS) {
    mkdirSync(join(dir, ...d.split('/')), { recursive: true });
    for (let n = 0; n < PER_DIR; n++) {
      writeFileSync(join(dir, ...d.split('/'), `f${n}.py`), 'x = 1\n');
      files.push(`${d}/f${n}.py`);
    }
  }
  return { dir, files: files.sort() };
}

const underBulk = (list: readonly string[]): number => list.filter((p) => p.replace(/\\/g, '/').includes('/bulk/')).length;

describe('scope resolution: one realpath per directory, not per file', () => {
  it('a directory entry', async () => {
    const { dir, files } = tree();
    const r = await resolveScope(dir, { paths: ['bulk'] }, { exclusions: null });
    expect(r.files).toEqual(files);
    // The entry itself, and each of the three directories — at most once.
    expect(underBulk(calls.realpath)).toBeLessThanOrEqual(1 + DIRS.length);
  });

  it('a glob entry', async () => {
    const { dir, files } = tree();
    const r = await resolveScope(dir, { paths: ['bulk/**/*.py'] }, { exclusions: null });
    expect(r.files).toEqual(files);
    expect(underBulk(calls.realpath)).toBeLessThanOrEqual(DIRS.length);
  });

  it('a diff of untracked files', async () => {
    const { dir, files } = tree();
    await execa('git', ['init', '-q'], { cwd: dir });
    const r = await resolveScope(dir, { diff: {} }, { exclusions: null });
    expect(r.files).toEqual(files);
    expect(underBulk(calls.realpath)).toBeLessThanOrEqual(DIRS.length);
  });
});

describe('projectPathTest — isProjectPath, one existence check per directory', () => {
  it('answers exactly as isProjectPath does', () => {
    const { dir } = tree();
    writeFileSync(join(dir, 'top.py'), '');
    const inProject = projectPathTest(dir);
    for (const p of [
      'bulk/d0/f1.py', // a file
      'bulk/d0/gone.py', // deleted, its directory still here
      'bulk/gone/deeper/x.py', // deleted with its directory, an ancestor still here
      'top.py', // a top-level file
      'gone-top.py', // a deleted top-level file: nothing left to place it by
      'nowhere/x.py', // no ancestor at all
      './bulk\\d1\\f2.py', // another spelling
      'bulk/d1/', // a directory
      'nowhere/..', // lexically the project root
      'bulk/d0/./f1.py',
      'nowhere/../top.py',
      'alpine:3.18 (alpine 3.18.4)', // an image target
      'Node.js', // Trivy's pseudo-target
      '/etc/passwd',
      'C:/Windows/x.py',
      '../outside.py',
      '..',
      '',
    ]) {
      expect(inProject(p), p).toBe(isProjectPath(dir, p));
    }
  });

  it('checks each directory once, however many findings sit in it', () => {
    const { dir, files } = tree();
    const inProject = projectPathTest(dir);
    calls.exists.length = 0;
    const paths = [...files, ...files.map((f) => f.replace('/f', '/gone-f')), ...files.map((f) => f.replace('bulk/', 'bulk/missing/'))];
    expect(paths.every((p) => inProject(p))).toBe(true);
    // bulk/d0, bulk/d1, bulk/d1/deep, and the three missing ones plus their
    // existing ancestors — a handful, never one per path (360 here).
    expect(calls.exists.length).toBeLessThanOrEqual(12);
  });
});

describe('the scan factory result filter', () => {
  function plugin(): PluginContext {
    const db = new Database(':memory:');
    runMigrations(db);
    return { storage: new Storage(db), shell: null, scriptsDir: '', progressNotifier: { send: () => {} } };
  }

  it('asks the disk only about findings a pattern matches, once per directory', async () => {
    const { dir, files } = tree();
    writeFileSync(join(dir, '.guardianignore'), 'bulk/d1/deep/\n');
    const ex = await loadProjectExclusions(dir);
    if (ex === null || 'error' in ex) throw new Error('expected exclusions');
    const findings = files.map((f) =>
      makeFinding({ tool: 'mock', severity: 'high', category: 'security', title: f, file_path: f, line_start: 1 }),
    );
    const tool = makeScanTool({
      name: 'path_cost',
      scan_type: 'sast',
      category: 'security',
      description: '',
      inputSchema: { project_path: z.string().optional(), scope: ScanScopeInput },
      supportsScope: true,
      invoke: async (): Promise<ScannerInvocation> => ({
        outcome: 'completed',
        tools_run: [{ name: 'mock', status: 'ok' }],
        missing_tools: [],
        parser_inputs: [{ parser: { name: 'mock', parse: () => ({ findings, cves: [] }) }, input: {} }],
        report_paths: [],
      }),
    });
    calls.exists.length = 0;
    const r = okResult<{ exclusions?: { findings_excluded: number } }>(await tool.handler({ project_path: dir }, plugin()));
    expect(r.exclusions?.findings_excluded).toBe(PER_DIR);
    // 40 findings excluded from one directory: one check of it, not 40 — and
    // none at all for the 80 findings no pattern matches.
    expect(underBulk(calls.exists)).toBeLessThanOrEqual(1);
  });
});
