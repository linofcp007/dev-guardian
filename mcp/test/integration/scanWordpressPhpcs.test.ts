/**
 * `scan_wordpress`'s PHPCS pass (`phpcs-wpcs`), 3.6.1: a file PHPCS did not
 * process — `Internal.Exception` (a sniff threw, "checking has been
 * aborted"), `Internal.Tokenizer.Exception`, `Internal.NoCodeFound` — was an
 * ordinary finding and the pass stayed `ok`, coverage full. It is now
 * `partially_parsed`, named in the reason, and the pass is missing too —
 * "ran, with a narrower gap", as `semgrep-wp` is.
 *
 * PHPCS is mocked at `runProcess` and writes the real PHPCS 3.13.5 / WPCS
 * 3.3.0 report of `test/fixtures/scanners/phpcs/internal-messages.json`
 * (see `test/unit/runners/scannerParsers/phpcs.test.ts`), its file names made
 * absolute as PHPCS writes them for an absolute target.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
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

const here = dirname(fileURLToPath(import.meta.url));
const REPORT = resolve(here, '..', 'fixtures', 'scanners', 'phpcs', 'internal-messages.json');

function plugin(project: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: project, progressNotifier: { send: () => {} } };
}

/** PHPCS alone is installed; it writes `report` with its file names under `dir`. */
function phpcsWrites(dir: string, report: string, exitCode = 2): void {
  vi.mocked(scannerAvailable).mockImplementation(async (name: string) => (name === 'phpcs' ? '/fake/bin/phpcs' : null));
  vi.mocked(runProcess).mockImplementation(async (opts) => {
    const out = (opts.args ?? []).find((a) => a.startsWith('--report-file='))?.slice('--report-file='.length);
    if (opts.command === 'phpcs' && out !== undefined) {
      const parsed = JSON.parse(report) as { totals: unknown; files: Record<string, unknown> };
      const files = Object.fromEntries(Object.entries(parsed.files).map(([name, v]) => [join(dir, name), v]));
      writeFileSync(out, JSON.stringify({ totals: parsed.totals, files }));
    }
    return { outcome: exitCode === 0 ? 'completed' : 'failed', exitCode, stdout: '', stderr: '', truncated: false };
  });
}

interface Result {
  ok: true;
  tools_run: ToolRun[];
  missing_tools: string[];
  coverage: string;
}

async function scan(dir: string): Promise<{ run: ToolRun | undefined; r: Result }> {
  const tool = TOOLS.find((t) => t.name === 'scan_wordpress');
  if (!tool) throw new Error('scan_wordpress not registered');
  const r = (await tool.handler({ project_path: dir, force: true }, plugin(dir))) as unknown as Result;
  return { run: r.tools_run.find((t) => t.name === 'phpcs-wpcs'), r };
}

function wpProject(): string {
  const dir = makeTempDir('wp-phpcs-');
  writeFileSync(join(dir, 'readme.txt'), '=== Plugin ===\n');
  for (const f of ['nocode.php', 'broken5.php', 'ok.php']) writeFileSync(join(dir, f), '<?php\n');
  return dir;
}

beforeEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(scannerAvailable).mockReset();
});

describe('scan_wordpress: phpcs-wpcs names the files PHPCS did not process', () => {
  it('Internal.Exception and Internal.NoCodeFound: ok, partially_parsed, listed missing', async () => {
    const dir = wpProject();
    phpcsWrites(dir, readFileSync(REPORT, 'utf8'));
    const { run, r } = await scan(dir);
    expect(run?.status).toBe('ok');
    expect(run?.partially_parsed?.map((p) => p.file)).toEqual(['nocode.php', 'broken5.php']);
    expect(run?.reason).toMatch(/nocode\.php/);
    expect(r.missing_tools).toContain('phpcs-wpcs');
  });

  it('control: a report with no such message is ok and no gap', async () => {
    const dir = wpProject();
    const clean = JSON.stringify({ totals: { errors: 0, warnings: 0, fixable: 0 }, files: { 'ok.php': { errors: 0, warnings: 0, messages: [] } } });
    phpcsWrites(dir, clean, 0);
    const { run, r } = await scan(dir);
    expect(run?.status).toBe('ok');
    expect(run?.partially_parsed).toBeUndefined();
    expect(r.missing_tools).not.toContain('phpcs-wpcs');
  });
});
