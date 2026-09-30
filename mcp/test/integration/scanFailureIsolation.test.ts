/**
 * One scanner's exception must cost that scanner, never the scan around it.
 *
 * Review of the first version: `scan_wordpress` ran its gitleaks pass inside
 * `Promise.all` with its other scanners, so a throw there failed the whole
 * scan; `security_scan_full` called each child with no try/catch, so one
 * throwing child made the parent `scanner_failed` and threw away every
 * sibling's results.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const faults = vi.hoisted(() => ({ gitleaksThrows: false }));

vi.mock('../../src/runners/gitleaksScan.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/runners/gitleaksScan.js')>();
  return {
    ...actual,
    runGitleaksScan: async (...args: Parameters<typeof actual.runGitleaksScan>) => {
      if (faults.gitleaksThrows) throw new Error('boom: gitleaks helper exploded');
      return actual.runGitleaksScan(...args);
    },
  };
});
vi.mock('../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));
vi.mock('../../src/tools/scanHelpers.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/tools/scanHelpers.js')>();
  return { ...actual, scannerAvailable: vi.fn() };
});

import { runProcess, type ProcessRunOptions, type ProcessRunResult } from '../../src/runners/processRunner.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import type { PluginContext } from '../../src/context.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS, type ToolModule } from '../../src/tools/index.js';
import type { ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/scanWordpress.js');
  await import('../../src/tools/securityScanFull.js');
});

const here = dirname(fileURLToPath(import.meta.url));
const FIX = resolve(here, '..', 'fixtures', 'scanners');
const fixture = (name: string): string => readFileSync(join(FIX, name), 'utf8');

async function fakeScanner(opts: ProcessRunOptions): Promise<ProcessRunResult> {
  const args = opts.args ?? [];
  const after = (flag: string): string | undefined => {
    const i = args.indexOf(flag);
    return i >= 0 ? args[i + 1] : undefined;
  };
  if (opts.command === 'semgrep') {
    const out = after('--output');
    if (out) writeFileSync(out, JSON.stringify({ ...JSON.parse(fixture('semgrep.json')), paths: { scanned: ['a.php'] } }));
    return { outcome: 'failed', exitCode: 1, stdout: '', stderr: '', truncated: false };
  }
  if (opts.command === 'gitleaks') {
    const report = args.find((a) => a.startsWith('--report-path='));
    if (report) writeFileSync(report.slice('--report-path='.length), fixture('gitleaks.json'));
    return { outcome: 'failed', exitCode: 1, stdout: '', stderr: '', truncated: false };
  }
  const out = after('--output');
  if (out) writeFileSync(out, fixture(args[0] === 'fs' ? 'trivy-fs.json' : 'trivy-dockerfile.json'));
  return { outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false };
}

const replaced = new Map<string, ToolModule['handler']>();

beforeEach(() => {
  faults.gitleaksThrows = false;
  vi.mocked(scannerAvailable).mockReset();
  vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
    ['semgrep', 'gitleaks', 'trivy'].includes(name) ? `/fake/bin/${name}` : null,
  );
  vi.mocked(runProcess).mockReset();
  vi.mocked(runProcess).mockImplementation(fakeScanner);
});

afterEach(() => {
  for (const [name, handler] of replaced) {
    const tool = TOOLS.find((t) => t.name === name);
    if (tool) tool.handler = handler;
  }
  replaced.clear();
});

function plugin(project: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: project, progressNotifier: { send: () => {} } };
}

function project(): string {
  const dir = makeTempDir('isolation-');
  writeFileSync(join(dir, 'a.php'), '<?php echo $_GET["x"];\n');
  return dir;
}

interface Result {
  ok: true;
  scan_id: string;
  coverage: string;
  tools_run: ToolRun[];
}

async function call(name: string, dir: string, p: PluginContext) {
  const tool = TOOLS.find((t) => t.name === name);
  if (!tool) throw new Error(`${name} not registered`);
  return tool.handler({ project_path: dir, force: true }, p);
}

describe('failure isolation', () => {
  it('scan_wordpress: a throwing secrets pass fails gitleaks only; Semgrep and Trivy results survive', async () => {
    faults.gitleaksThrows = true;
    const dir = project();
    const p = plugin(dir);
    const r = await call('scan_wordpress', dir, p);
    expect(r.ok).toBe(true);
    const res = r as unknown as Result;
    const gl = res.tools_run.find((t) => t.name === 'gitleaks');
    expect(gl?.status).toBe('failed');
    expect(gl?.reason).toMatch(/boom: gitleaks helper exploded/);
    expect(res.tools_run.find((t) => t.name === 'semgrep-wp')?.status).toBe('ok');
    const tools = new Set(p.storage.findings.listByScan(res.scan_id).map((f) => f.tool));
    expect(tools.has('semgrep')).toBe(true);
    expect(res.coverage).toBe('partial');
  }, 30_000); // Measured in full-suite runs (review 3.0, R7): past 10 s under load, like its sibling (5.2 s).

  it('security_scan_full: a child that throws is a failed entry; its siblings are kept', async () => {
    const iac = TOOLS.find((t) => t.name === 'scan_iac');
    if (!iac) throw new Error('scan_iac not registered');
    replaced.set('scan_iac', iac.handler);
    iac.handler = () => Promise.reject(new Error('boom: scan_iac crashed'));

    const dir = project();
    const p = plugin(dir);
    const r = await call('security_scan_full', dir, p);
    expect(r.ok).toBe(true);
    const res = r as unknown as Result;
    const failed = res.tools_run.find((t) => t.name === 'scan_iac');
    expect(failed?.status).toBe('failed');
    expect(failed?.reason).toMatch(/boom: scan_iac crashed/);
    const tools = new Set(p.storage.findings.listByScan(res.scan_id).map((f) => f.tool));
    expect(tools.has('semgrep')).toBe(true);
    expect(tools.has('gitleaks')).toBe(true);
    expect(tools.has('trivy')).toBe(true);
    expect(res.coverage).toBe('partial');
  });
});
