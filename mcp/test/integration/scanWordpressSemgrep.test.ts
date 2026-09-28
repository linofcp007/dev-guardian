/**
 * `scan_wordpress`'s Semgrep pass (`semgrep-wp`) is judged by the shared
 * Semgrep judge (`runners/semgrepReport.ts`) — fix round 1 of follow-up X.
 * It was judged by the exit code alone: a file Semgrep only partly parsed
 * (PHP's legal `const NAMESPACE` on 1.176.1) read `ok` at coverage full, and
 * so did a run that scanned no file at all.
 *
 *   - partial → `ok`, listed missing as `semgrep-wp`, the files named;
 *   - scanned nothing, and the project has no `.php` file → `skipped`, not
 *     applicable, no gap;
 *   - scanned nothing although `.php` files exist → `skipped`, a gap;
 *   - anything fatal (a rule error, an unclean exit) → `failed`, reason kept.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));
vi.mock('../../src/tools/scanHelpers.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/tools/scanHelpers.js')>();
  return { ...actual, scannerAvailable: vi.fn() };
});

import { runProcess } from '../../src/runners/processRunner.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import type { PluginContext } from '../../src/context.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import type { ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/scanWordpress.js');
});

function plugin(project: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: project, progressNotifier: { send: () => {} } };
}

/** Semgrep writes `report` and exits `exitCode`; nothing else is installed. */
function semgrepWrites(report: Record<string, unknown>, exitCode = 0): void {
  vi.mocked(scannerAvailable).mockImplementation(async (name: string) => (name === 'semgrep' ? '/fake/bin/semgrep' : null));
  vi.mocked(runProcess).mockImplementation(async (opts) => {
    const args = opts.args ?? [];
    const i = args.indexOf('--output');
    const out = i >= 0 ? args[i + 1] : undefined;
    if (opts.command === 'semgrep' && out !== undefined) writeFileSync(out, JSON.stringify({ results: [], errors: [], ...report }));
    return { outcome: exitCode === 0 ? 'completed' : 'failed', exitCode, stdout: '', stderr: '', truncated: false };
  });
}

interface Result {
  ok: true;
  tools_run: Array<ToolRun & { partially_parsed?: Array<{ file: string }> }>;
  missing_tools: string[];
  coverage: string;
}

async function scan(dir: string): Promise<{ run: Result['tools_run'][number] | undefined; r: Result }> {
  const tool = TOOLS.find((t) => t.name === 'scan_wordpress');
  if (!tool) throw new Error('scan_wordpress not registered');
  const r = (await tool.handler({ project_path: dir, force: true }, plugin(dir))) as unknown as Result;
  return { run: r.tools_run.find((t) => t.name === 'semgrep-wp'), r };
}

function wpProject(withPhp: boolean): string {
  const dir = makeTempDir('wp-semgrep-');
  writeFileSync(join(dir, 'readme.txt'), '=== Plugin ===\n');
  if (withPhp) {
    mkdirSync(join(dir, 'includes'));
    writeFileSync(join(dir, 'includes', 'rest-controller.php'), '<?php\nclass A { const NAMESPACE = "x"; }\n');
  }
  return dir;
}

beforeEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(scannerAvailable).mockReset();
});

describe('scan_wordpress: semgrep-wp judged by the shared Semgrep judge', () => {
  it('control: a clean run that scanned files is ok, and no gap', async () => {
    const dir = wpProject(true);
    semgrepWrites({ paths: { scanned: [join(dir, 'includes', 'rest-controller.php')] } }, 1);
    const { run, r } = await scan(dir);
    expect(run?.status).toBe('ok');
    expect(r.missing_tools).not.toContain('semgrep-wp');
  });

  it('a file only partly parsed: ok, listed missing, the file named', async () => {
    const dir = wpProject(true);
    const file = join(dir, 'includes', 'rest-controller.php');
    semgrepWrites({
      paths: { scanned: [file] },
      errors: [{ code: 3, level: 'warn', type: ['PartialParsing', [{ path: file }]], message: 'Syntax error at line x:2', path: file }],
    });
    const { run, r } = await scan(dir);
    expect(run?.status).toBe('ok');
    expect(run?.reason).toMatch(/partial: 1 file\(s\) only partly parsed/);
    expect(run?.partially_parsed?.map((p) => p.file)).toEqual(['includes/rest-controller.php']);
    expect(r.missing_tools).toContain('semgrep-wp');
  });

  it('scanned nothing, with no .php file in the project: skipped, not applicable, no gap', async () => {
    const dir = wpProject(false);
    semgrepWrites({ paths: { scanned: [] } });
    const { run, r } = await scan(dir);
    expect(run?.status).toBe('skipped');
    expect(run?.reason).toMatch(/^not applicable/);
    expect(r.missing_tools).not.toContain('semgrep-wp');
    expect(r.missing_tools).not.toContain('semgrep');
  });

  it('scanned nothing although .php files exist: skipped, and a gap', async () => {
    const dir = wpProject(true);
    semgrepWrites({ paths: { scanned: [] } });
    const { run, r } = await scan(dir);
    expect(run?.status).toBe('skipped');
    expect(run?.reason).toMatch(/scanned 0 files/);
    expect(r.missing_tools).toContain('semgrep-wp');
  });

  it('a rule error is failed, with the reason — never ok', async () => {
    const dir = wpProject(true);
    semgrepWrites(
      {
        paths: { scanned: [join(dir, 'includes', 'rest-controller.php')] },
        errors: [{ code: 2, level: 'error', type: 'Rule parse error', message: 'Rule parse error in rule php.x' }],
      },
      2,
    );
    const { run } = await scan(dir);
    expect(run?.status).toBe('failed');
    expect(run?.reason).toMatch(/Rule parse error/);
  });
});
