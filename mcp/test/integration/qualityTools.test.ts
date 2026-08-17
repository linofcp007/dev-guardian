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
import { BUG_HUNT_PACKS } from '../../src/tools/bugHunt.js';

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
  // Read from the tool's own export rather than hardcoded literals, so
  // these tests keep pinning real behaviour if the pack list ever changes
  // again (as it already has once — see the fix report for `p/bugs`).
  function requirePack(index: number): string {
    const pack = BUG_HUNT_PACKS[index];
    if (pack === undefined) {
      throw new Error(`bug_hunt: expected a configured pack at index ${index}`);
    }
    return pack;
  }
  const PRIMARY_PACK = requirePack(0);
  const SECONDARY_PACK = requirePack(1);

  /** Shape of a real Semgrep JSON report where every named pack 404'd:
   *  `results`/`paths.scanned` empty, one `errors[]` entry per pack — the
   *  exact output captured from `semgrep --config=<dead> --json` (1.164.0),
   *  see semgrepConfigFailure.ts's header comment. */
  function configFailureJson(...failedPacks: string[]): string {
    return JSON.stringify({
      version: '1.164.0',
      results: [],
      errors: failedPacks.map((pack) => ({
        code: 2,
        level: 'error',
        type: 'SemgrepError',
        message: `Failed to download configuration from https://semgrep.dev/c/${pack} HTTP 404.`,
      })),
      paths: { scanned: [] },
    });
  }

  function writeOutput(opts: { args?: string[] }, content: string): void {
    const outIdx = opts.args?.findIndex((a) => a === '--output');
    const path = outIdx !== undefined && outIdx >= 0 ? opts.args?.[outIdx + 1] : undefined;
    if (path) writeFileSync(path, content, 'utf8');
  }

  it(`runs semgrep with ${PRIMARY_PACK} + ${SECONDARY_PACK} and tags findings as bug`, async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      expect(opts.args).toContain(`--config=${PRIMARY_PACK}`);
      expect(opts.args).toContain(`--config=${SECONDARY_PACK}`);
      writeOutput(opts, semgrepFx());
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
      coverage?: string;
    };
    expect(r.ok).toBe(true);
    // All findings recategorised as `bug`, regardless of source metadata.
    expect(r.top_findings.every((f) => f.category === 'bug')).toBe(true);
    // The clean-scan case must still read as clean — this test is also the
    // control for the gap-reporting tests below.
    expect(r.coverage).toBe('full');
  });

  it('re-runs with the surviving pack when one config fails to download, and still reports its findings', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');

    let calls = 0;
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      calls += 1;
      if (calls === 1) {
        expect(opts.args).toContain(`--config=${PRIMARY_PACK}`);
        expect(opts.args).toContain(`--config=${SECONDARY_PACK}`);
        // Semgrep's real behaviour: one dead config aborts the WHOLE run —
        // nothing scanned, not even by the pack that is still alive.
        writeOutput(opts, configFailureJson(PRIMARY_PACK));
        return { outcome: 'failed' as const, exitCode: 7, stdout: '', stderr: '', truncated: false };
      }
      // The retry must drop the dead pack and keep the live one.
      expect(opts.args).not.toContain(`--config=${PRIMARY_PACK}`);
      expect(opts.args).toContain(`--config=${SECONDARY_PACK}`);
      writeOutput(opts, semgrepFx());
      return { outcome: 'completed' as const, exitCode: 1, stdout: '', stderr: '', truncated: false };
    });

    const tool = getTool('bug_hunt');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      top_findings: { category: string }[];
      findings_count_by_severity: Record<string, number>;
      missing_tools: string[];
      tools_run: { name: string; status: string; reason?: string }[];
      warnings: string[];
      coverage?: string;
    };
    expect(calls).toBe(2);
    expect(r.ok).toBe(true);
    // The surviving pack's findings still reach the caller — a retirement
    // must not waste the packs that still resolve.
    const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
    expect(total).toBeGreaterThan(0);
    expect(r.top_findings.every((f) => f.category === 'bug')).toBe(true);
    // But the gap is not hidden: this is a partial result, not a clean one.
    expect(r.coverage).toBe('partial');
    // Bare tool name only — never pack-qualified. A qualified name has no
    // entry in the dashboard's TOOL_CATEGORIES map (dashboard/types.ts) and
    // falls back to rendering itself as its own "category", producing
    // "MISSING semgrep:p/r2c-bug-scan — semgrep:p/r2c-bug-scan findings are
    // NOT in these numbers". See test/unit/dashboard/{snapshot,renderStatus,
    // renderHtml}.test.ts for the rendered sentence this shape keeps sane.
    expect(r.missing_tools).toEqual(['semgrep']);
    // The pack-level detail (which pack, and why) lives on tools_run's
    // reason instead — the field actually meant for free-text diagnostics.
    expect(r.tools_run.find((t) => t.name === 'semgrep')?.reason).toContain(PRIMARY_PACK);
  });

  it('reports both failures when the retry itself also fails (registry outage mid-scan)', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');

    let calls = 0;
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      calls += 1;
      if (calls === 1) {
        // Only the primary pack is reported dead on the first attempt.
        writeOutput(opts, configFailureJson(PRIMARY_PACK));
        return { outcome: 'failed' as const, exitCode: 7, stdout: '', stderr: '', truncated: false };
      }
      // The retry (secondary pack only) fails too — e.g. a registry outage
      // that started between the two calls. Must not be swallowed: the
      // survivor's own failure has to be reported, not silently dropped in
      // favour of the first attempt's already-known failure. Exit code is
      // deliberately 0/'completed' here (not 7, like the first call) so
      // this only passes when the retry's own errors[] is actually
      // consulted — a check that only re-inspects outcome/exitCode for the
      // retry would read this as a second clean scan.
      expect(opts.args).toContain(`--config=${SECONDARY_PACK}`);
      writeOutput(opts, configFailureJson(SECONDARY_PACK));
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    const tool = getTool('bug_hunt');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      findings_count_by_severity: Record<string, number>;
      missing_tools: string[];
      tools_run: { name: string; status: string; reason?: string }[];
      coverage?: string;
    };
    expect(calls).toBe(2);
    expect(r.ok).toBe(true);
    const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
    expect(total).toBe(0);
    expect(r.coverage).toBe('none');
    // missing_tools stays the bare tool name, once — not one entry per pack.
    expect(r.missing_tools).toEqual(['semgrep']);
    // Both packs must still be named in the diagnostic text, not just the
    // one caught on the first try.
    const reason = r.tools_run.find((t) => t.name === 'semgrep')?.reason ?? '';
    expect(reason).toContain(PRIMARY_PACK);
    expect(reason).toContain(SECONDARY_PACK);
  });

  it('never reports a clean result when every configured pack fails to download', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      writeOutput(opts, configFailureJson(PRIMARY_PACK, SECONDARY_PACK));
      return { outcome: 'failed' as const, exitCode: 7, stdout: '', stderr: '', truncated: false };
    });

    const tool = getTool('bug_hunt');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      findings_count_by_severity: Record<string, number>;
      missing_tools: string[];
      warnings: string[];
      coverage?: string;
    };
    expect(r.ok).toBe(true);
    const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
    expect(total).toBe(0);
    // The load-bearing assertion: zero findings from a run where nothing
    // could be scanned must NOT be indistinguishable from a clean bug hunt.
    expect(r.coverage).toBe('none');
    expect(r.missing_tools).toEqual(['semgrep']);
    expect(r.warnings.join(' ')).toMatch(/not a clean bill of health/i);
  });

  it('does not trust a clean exit code alone — errors[] naming every pack as failed is still a gap even at exit 0', async () => {
    // Guards against a future Semgrep that exits 0 with an empty result when
    // every --config failed, instead of today's non-zero exit. Nothing here
    // may depend on outcome/exitCode signalling failure.
    const project = tempProject();
    const plugin = makePlugin(project);
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      writeOutput(opts, configFailureJson(PRIMARY_PACK, SECONDARY_PACK));
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    const tool = getTool('bug_hunt');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      findings_count_by_severity: Record<string, number>;
      missing_tools: string[];
      coverage?: string;
    };
    expect(r.ok).toBe(true);
    const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
    expect(total).toBe(0);
    expect(r.coverage).toBe('none');
    expect(r.missing_tools).toEqual(['semgrep']);
  });

  it('propagates a cancelled retry as cancelled, not as a completed clean scan', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');

    let calls = 0;
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      calls += 1;
      if (calls === 1) {
        writeOutput(opts, configFailureJson(PRIMARY_PACK));
        return { outcome: 'failed' as const, exitCode: 7, stdout: '', stderr: '', truncated: false };
      }
      // The retry is cancelled before it ever writes a fresh --output —
      // outFile still holds attempt one's stale config-failure JSON. A fix
      // that re-reads it here would report the SAME pack's failure twice
      // and would also force outcome: 'completed' on a run that was
      // actually cancelled.
      return { outcome: 'cancelled' as const, exitCode: null, stdout: '', stderr: '', truncated: false };
    });

    const tool = getTool('bug_hunt');
    const r = (await tool.handler({ project_path: project }, plugin)) as
      | { ok: true; missing_tools: string[]; tools_run: { reason?: string }[] }
      | { ok: false; error: { code: string; message: string } };
    expect(calls).toBe(2);
    // scanToolFactory.ts special-cases a cancelled outcome as a domain
    // error, the same way any other cancelled scan is reported — not as a
    // completed ScanResult.
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe('cancelled');
    }
  });

  it('propagates a timed-out retry as failed, without duplicating the first attempt\'s failure', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');

    let calls = 0;
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      calls += 1;
      if (calls === 1) {
        writeOutput(opts, configFailureJson(PRIMARY_PACK));
        return { outcome: 'failed' as const, exitCode: 7, stdout: '', stderr: '', truncated: false };
      }
      // Timed out — again, deliberately does NOT touch outFile, so it still
      // holds attempt one's stale content if the fix reads it regardless.
      return { outcome: 'timed_out' as const, exitCode: null, stdout: '', stderr: '', truncated: false };
    });

    const tool = getTool('bug_hunt');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      status: string;
      findings_count_by_severity: Record<string, number>;
      missing_tools: string[];
      tools_run: { name: string; status: string; reason?: string }[];
      coverage?: string;
    };
    expect(calls).toBe(2);
    expect(r.ok).toBe(true);
    // 'failed', never 'completed' — a timed-out retry did not finish.
    expect(r.status).toBe('failed');
    const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
    expect(total).toBe(0);
    expect(r.coverage).toBe('none');
    expect(r.missing_tools).toEqual(['semgrep']);
    // The original (attempt-one) failure is named once — not duplicated by
    // a re-read of the stale report file. Counting "Failed to download..."
    // occurrences (one per distinct ConfigDownloadFailure), not PRIMARY_PACK
    // occurrences: describeConfigFailures already mentions a pack's name
    // twice for a SINGLE failure (once as the label, once inside its own
    // message's URL), so a substring count of the pack name is not the
    // right signal for "how many failures got concatenated in".
    const reason = r.tools_run.find((t) => t.name === 'semgrep')?.reason ?? '';
    const failureMessageCount = reason.split('Failed to download configuration from').length - 1;
    expect(failureMessageCount).toBe(1);
    expect(reason).toContain(PRIMARY_PACK);
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
