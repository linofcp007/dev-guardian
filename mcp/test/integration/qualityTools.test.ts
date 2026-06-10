/**
 * Integration tests for `bug_hunt`, `quality_check`, and `review_pr`.
 *
 * Same pattern as `securityTools.test.ts`: mock `runProcess`,
 * `runShellScript`, and `scannerAvailable` to drop canned reports and
 * return success; assert ScanResult shape, findings count, and routing.
 */

import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../src/runners/processRunner.js', () => ({
  runProcess: vi.fn(),
}));
vi.mock('../../src/runners/shellRunner.js', () => ({
  runShellScript: vi.fn(),
}));
vi.mock('../../src/tools/scanHelpers.js', async () => {
  const actual =
    await vi.importActual<typeof import('../../src/tools/scanHelpers.js')>(
      '../../src/tools/scanHelpers.js',
    );
  return { ...actual, scannerAvailable: vi.fn() };
});

// review_pr also calls execa directly (to resolve refs + diff files), so
// stub that module too.
vi.mock('execa', () => ({
  execa: vi.fn(async (cmd: string, args: string[]) => {
    if (args.includes('symbolic-ref')) {
      return { exitCode: 0, stdout: 'refs/remotes/origin/main', stderr: '' };
    }
    if (args.includes('diff') && args.includes('--name-only')) {
      return { exitCode: 0, stdout: 'src/app.js\nsrc/util.ts', stderr: '' };
    }
    return { exitCode: 0, stdout: '', stderr: '' };
  }),
}));

import { runProcess } from '../../src/runners/processRunner.js';
import { runShellScript } from '../../src/runners/shellRunner.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';

import type { PluginContext } from '../../src/context.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';

beforeAll(async () => {
  await import('../../src/tools/securityScanFull.js');
  await import('../../src/tools/scanSast.js');
  await import('../../src/tools/scanSecrets.js');
  await import('../../src/tools/scanDeps.js');
  await import('../../src/tools/scanContainers.js');
  await import('../../src/tools/scanIac.js');
  await import('../../src/tools/bugHunt.js');
  await import('../../src/tools/qualityCheck.js');
  await import('../../src/tools/reviewPr.js');
});

const here = dirname(fileURLToPath(import.meta.url));
const FIX = resolve(here, '..', 'fixtures', 'scanners');

function tempProject(): string {
  return mkdtempSync(join(tmpdir(), 'qual-tools-'));
}

function getTool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`Tool '${name}' not registered`);
  return t;
}

function makePlugin(projectPath: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  const storage = new Storage(db);
  return {
    storage,
    shell: {
      command: 'bash',
      args_prefix: [],
      needs_wsl_path_translate: false,
      label: 'fake',
    },
    scriptsDir: projectPath,
    progressNotifier: { send: () => {} },
  };
}

const semgrepFx = () => readFileSync(join(FIX, 'semgrep.json'), 'utf8');
const ruffFx = () => readFileSync(join(FIX, 'ruff.json'), 'utf8');
const jscpdFx = () => readFileSync(join(FIX, 'jscpd.json'), 'utf8');
const gitleaksFx = () => readFileSync(join(FIX, 'gitleaks.json'), 'utf8');
const trivyFsFx = () => readFileSync(join(FIX, 'trivy-fs.json'), 'utf8');

beforeEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(runShellScript).mockReset();
  vi.mocked(scannerAvailable).mockReset();
});

afterEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(runShellScript).mockReset();
  vi.mocked(scannerAvailable).mockReset();
});

describe('bug_hunt', () => {
  it('runs semgrep with p/bugs + p/security-audit and tags findings as bug', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      expect(opts.args).toContain('--config=p/bugs');
      expect(opts.args).toContain('--config=p/security-audit');
      const outIdx = opts.args?.findIndex((a) => a === '--output');
      const path = outIdx !== undefined && outIdx >= 0 ? opts.args?.[outIdx + 1] : undefined;
      if (path) writeFileSync(path, semgrepFx(), 'utf8');
      return {
        outcome: 'completed' as const,
        exitCode: 1,
        stdout: '',
        stderr: '',
        truncated: false,
      };
    });

    const tool = getTool('bug_hunt');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      top_findings: { category: string; subcategory?: string }[];
      findings_count_by_severity: Record<string, number>;
    };
    expect(r.ok).toBe(true);
    // All findings recategorised as `bug`, regardless of source metadata.
    expect(r.top_findings.every((f) => f.category === 'bug')).toBe(true);
  });
});

describe('quality_check', () => {
  it('routes jscpd subdir + ruff.json to their parsers', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    vi.mocked(runShellScript).mockImplementation(async () => {
      const reportDir = join(project, '.guardian', 'reports', 'quality-20260526');
      mkdirSync(join(reportDir, 'dup'), { recursive: true });
      writeFileSync(join(reportDir, 'dup', 'jscpd-report.json'), jscpdFx(), 'utf8');
      writeFileSync(join(reportDir, 'ruff.json'), ruffFx(), 'utf8');
      return {
        outcome: 'completed' as const,
        exitCode: 0,
        stdout: '',
        stderr: '',
        truncated: false,
      };
    });

    const tool = getTool('quality_check');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      tools_run: { name: string; status: string }[];
      findings_count_by_severity: Record<string, number>;
    };
    expect(r.ok).toBe(true);
    expect(r.tools_run.map((t) => t.name)).toEqual(expect.arrayContaining(['jscpd', 'ruff']));
    const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
    // 2 jscpd duplicates + 3 ruff = 5
    expect(total).toBe(5);
  });

  it('surfaces missing_tools when the script produced no reports', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    vi.mocked(runShellScript).mockResolvedValue({
      outcome: 'completed',
      exitCode: 0,
      stdout: '',
      stderr: '',
      truncated: false,
    });

    const tool = getTool('quality_check');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      missing_tools: string[];
    };
    expect(r.ok).toBe(true);
    expect(r.missing_tools).toEqual(expect.arrayContaining(['jscpd', 'ruff']));
  });
});

describe('review_pr', () => {
  it('resolves base_ref + diff and routes diff-scoped reports to parsers', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    vi.mocked(runShellScript).mockImplementation(async () => {
      const reportDir = join(project, '.guardian', 'reports', 'review-20260526');
      mkdirSync(reportDir, { recursive: true });
      writeFileSync(join(reportDir, 'sast.json'), semgrepFx(), 'utf8');
      writeFileSync(join(reportDir, 'secrets.json'), gitleaksFx(), 'utf8');
      writeFileSync(join(reportDir, 'deps.json'), trivyFsFx(), 'utf8');
      return {
        outcome: 'completed' as const,
        exitCode: 0,
        stdout: '',
        stderr: '',
        truncated: false,
      };
    });

    const tool = getTool('review_pr');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      tools_run: { name: string; status: string }[];
      findings_count_by_severity: Record<string, number>;
    };
    expect(r.ok).toBe(true);
    expect(r.tools_run.map((t) => t.name).sort()).toEqual(['gitleaks', 'semgrep', 'trivy']);
    // 3 semgrep + 2 gitleaks + 3 trivy fs = 8 findings
    const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
    expect(total).toBe(8);
  });
});
