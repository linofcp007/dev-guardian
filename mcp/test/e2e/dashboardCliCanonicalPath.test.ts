/**
 * `status` finds a project's scans however `--project` spells the project.
 *
 * Every MCP tool stores `project_path` as `resolveProjectPath()`'s canonical
 * spelling (long names, links resolved, upper-case drive letter). The CLI
 * used to key its lookup on `resolve(--project)` instead, so a symlinked
 * checkout, an 8.3 short name or a lower-case drive letter read "No scan yet"
 * over a database full of scans. Runs the real CLI (`cli/dev-guardian.mjs`,
 * against `mcp/dist`) as a subprocess, like `dashboardCli.test.ts`.
 */

import { symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { spawnSyncCapped, timeoutAbove } from '../helpers/spawnCap.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { openDatabase, Storage } from '../../src/storage/index.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const CLI = resolve(REPO_ROOT, 'cli', 'dev-guardian.mjs');
/** Hang-breaker for one CLI run; nothing asserts by reaching it. */
const TIMEOUT_MS = 15_000;
// Above the cap, so a hung child is reported by the cap — naming it — and
// not by vitest's 10 s default failing the test after the fact (R7-I1).
vi.setConfig({ testTimeout: timeoutAbove(TIMEOUT_MS) });

function runStatus(project: string) {
  const r = spawnSyncCapped(process.execPath, [CLI, 'status', '--project', project], {
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
    timeout: TIMEOUT_MS,
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

/** A project with one completed scan, stored exactly as a tool stores it. */
function projectWithScan(): string {
  const dir = makeTempDir('guardian-cli-canonical-');
  const key = resolveProjectPath(dir).path;
  const { db } = openDatabase({ projectPath: dir });
  const storage = new Storage(db);
  try {
    storage.scans.insert({ scan_id: 'seed', scan_type: 'security_full', project_path: key, tree_hash: 't' });
    storage.scans.finalize({
      scan_id: 'seed',
      status: 'completed',
      tools_run: [{ name: 'semgrep', status: 'ok' }],
      missing_tools: [],
    });
    storage.findings.bulkInsert([
      {
        scan_id: 'seed', fingerprint: 'fp-crit', tool: 'semgrep', severity: 'critical',
        category: 'security', title: 'seeded', fix_available: false,
      },
    ]);
  } finally {
    storage.close();
  }
  return dir;
}

function expectScanFound(r: ReturnType<typeof runStatus>): void {
  expect(r.stderr).toBe('');
  expect(r.status).toBe(0);
  expect(r.stdout).not.toMatch(/No scan yet/);
  expect(r.stdout).toMatch(/1 crit/);
}

describe('dev-guardian status — --project in a non-canonical spelling', () => {
  it('through a link (symlink / junction) to the project', () => {
    const dir = projectWithScan();
    const link = join(makeTempDir('guardian-cli-link-'), 'linked-project');
    symlinkSync(dir, link, 'junction');

    expectScanFound(runStatus(link));
  });

  const rawTmpdir = process.env['GUARDIAN_TEST_RAW_TMPDIR'];
  it.skipIf(rawTmpdir === undefined)('through the OS temp-dir alias (8.3 short name / symlink)', () => {
    const dir = projectWithScan();
    const viaAlias = join(rawTmpdir ?? '', relative(tmpdir(), dir));
    expect(viaAlias).not.toBe(dir);

    expectScanFound(runStatus(viaAlias));
  });

  it.runIf(process.platform === 'win32')('with a lower-case drive letter', () => {
    const dir = projectWithScan();
    const lower = dir.replace(/^([A-Za-z]):/, (_m, d: string) => `${d.toLowerCase()}:`);

    expectScanFound(runStatus(lower));
  });
});
