/**
 * `runScans` orchestrates the CI scan pipeline over the SAME tool handlers
 * the MCP server calls — see `runScans.ts`'s own doc comment. Every handler
 * is mocked at the `TOOLS` boundary (see the module doc comment on
 * `mockTool` below): this suite verifies ORCHESTRATION — order, refusal
 * handling, exception handling, where findings come from, temp-dir hygiene
 * — never scanning itself, so none of it needs Semgrep installed.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { evaluateGate } from '../../src/ci/gate.js';
import { runScans, SCAN_SEQUENCE } from '../../src/ci/runScans.js';
import { CI_EXIT } from '../../src/ci/types.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { TOOLS } from '../../src/tools/index.js';
import type { ToolModule } from '../../src/tools/index.js';
import type { Finding, ToolResult } from '../../src/types.js';
import { makeTempDir, cleanupTempDirs } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

/**
 * Vitest per-test timeout for the `runScans` block below, overriding the 10s
 * default in `vitest.config.ts`.
 *
 * Every tool handler in this file is mocked, so nothing here is doing real
 * scanner work — but `runScans` still creates and removes a real temp
 * directory per call, and the "removes its ephemeral temp directory" test
 * makes two full pipeline runs. Measured well under a second idle; measured
 * at 10.018s, and therefore FAILED as "Test timed out in 10000ms", on a
 * full-suite run with other work on the machine. An 18-millisecond overshoot
 * of a shared default is a report about the machine, not about `runScans`.
 */
const RUN_SCANS_SUITE_TIMEOUT_MS = 60_000;

/**
 * `runScans.ts`'s ephemeral directory lives under the SAME shared OS
 * `tmpdir()` every other process on the machine uses — including, in this
 * project's own suite, a real (unmocked) CLI subprocess invocation from
 * `test/e2e/ciCliFixture.test.ts` (headless-ci-cli, Task 5), which vitest
 * can legitimately schedule concurrently with THIS file: file-level
 * parallelism is vitest's default, so two different test files' real
 * `runScans()` calls can overlap in wall-clock time. A before/after diff of
 * the whole `dev-guardian-ci-*` namespace (this test's original approach)
 * is therefore not a reliable leak signal on its own: a directory belonging
 * to that OTHER, unrelated run can legitimately exist at this test's own
 * "after" snapshot purely by timing, and a set-equality assertion has no
 * way to tell "an entry we personally created is still here" apart from
 * "an unrelated concurrent process's entry happens to exist right now" —
 * confirmed as a real, reproducible flake (not a hypothetical) when Task 5
 * added that second real caller.
 *
 * The fix spies on `mkdtemp` itself — still calling through to the real
 * implementation, so `runScans`'s own behaviour is completely unchanged —
 * to record the EXACT path(s) THIS file's own calls create, and checks only
 * those. `vi.hoisted` is required because `vi.mock` factories run in an
 * isolated, hoisted scope that cannot close over a plain outer `let`.
 */
const { createdCiTempDirs } = vi.hoisted(() => ({ createdCiTempDirs: [] as string[] }));

vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs/promises')>();
  return {
    ...actual,
    mkdtemp: vi.fn(async (...args: Parameters<typeof actual.mkdtemp>) => {
      const dir = await actual.mkdtemp(...args);
      createdCiTempDirs.push(dir);
      return dir;
    }),
  };
});

/** Every name `runScans` can invoke, in the order `SCAN_SEQUENCE` documents. */
const ALL_NAMES = [
  'detect_stack',
  'security_scan_full',
  'license_compatibility',
  'map_attack_surface',
  'scan_dast',
  'validate_finding',
];

/** The order a run with NO base url takes — `scan_dast` dropped out. */
const ORDER_WITHOUT_DAST = [
  'detect_stack',
  'security_scan_full',
  'license_compatibility',
  'map_attack_surface',
  'validate_finding',
];

/** The full documented order, `scan_dast` included between map_attack_surface
 *  and validate_finding. */
const ORDER_WITH_DAST = [
  'detect_stack',
  'security_scan_full',
  'license_compatibility',
  'map_attack_surface',
  'scan_dast',
  'validate_finding',
];

function ok(payload: Record<string, unknown> = {}): ToolResult<Record<string, unknown>> {
  return { ok: true, ...payload };
}

/**
 * Replaces one registered tool's handler in place. This IS "mocking at the
 * TOOLS boundary": `runScans.ts` looks tools up by name in this exact array
 * (`TOOLS.find(t => t.name === name)`), so overwriting `.handler` here is
 * indistinguishable, from `runScans`'s point of view, from a real handler —
 * except it never touches a filesystem, a scanner binary, or the network.
 * `afterEach` below restores the real handler so tests stay independent of
 * each other and of run order within this file.
 */
const originalHandlers = new Map<string, ToolModule['handler']>();

function mockTool(name: string, impl: ToolModule['handler']): void {
  const tool = TOOLS.find((t) => t.name === name);
  if (!tool) throw new Error(`fixture error: '${name}' is not a registered tool`);
  if (!originalHandlers.has(name)) originalHandlers.set(name, tool.handler);
  tool.handler = impl;
}

beforeEach(() => {
  for (const name of ALL_NAMES) {
    mockTool(name, async () => ok());
  }
});

afterEach(() => {
  for (const [name, handler] of originalHandlers) {
    const tool = TOOLS.find((t) => t.name === name);
    if (tool) tool.handler = handler;
  }
  originalHandlers.clear();
});

function makeProjectDir(): string {
  return makeTempDir('guardian-ci-project-');
}

describe('runScans', () => {
  it('SCAN_SEQUENCE documents the full order, scan_dast included', () => {
    // Guards against SCAN_SEQUENCE itself being defined as the short,
    // dast-less sequence — buildSequence would then have nothing to add
    // scan_dast back to when a base url IS given.
    expect(SCAN_SEQUENCE).toEqual(ORDER_WITH_DAST);
  });

  it('runs the steps in the documented order', async () => {
    // Order is not cosmetic: map_attack_surface must precede scan_dast and
    // validate_finding, both of which refuse without a surface snapshot.
    const calls: string[] = [];
    for (const name of ALL_NAMES) {
      mockTool(name, async () => {
        calls.push(name);
        return ok();
      });
    }

    await runScans({ projectPath: makeProjectDir() });

    // Literal array, NOT a reference to SCAN_SEQUENCE — asserting against
    // the constant itself would pass even if the constant encoded the wrong
    // order, since the implementation and the assertion would be reading
    // the same (possibly wrong) value.
    expect(calls).toEqual(ORDER_WITHOUT_DAST);
  });

  it('includes scan_dast only when a base url is given, positioned between map_attack_surface and validate_finding', async () => {
    const calls: string[] = [];
    let dastInput: Record<string, unknown> | undefined;
    for (const name of ALL_NAMES) {
      mockTool(name, async (input) => {
        calls.push(name);
        if (name === 'scan_dast') dastInput = input;
        return ok();
      });
    }

    await runScans({
      projectPath: makeProjectDir(),
      baseUrl: 'https://example.test',
      authorizedTarget: true,
    });

    expect(calls).toEqual(ORDER_WITH_DAST);
    // A wrong-but-plausible implementation calls scan_dast in the right SLOT
    // but forgets to forward the arguments it needs to do anything real with
    // — catching that requires checking the input, not just the call order.
    expect(dastInput).toMatchObject({
      base_url: 'https://example.test',
      authorized_target: true,
    });
  });

  it('passes local_only to security_scan_full when asked, and only then', async () => {
    const inputs: Array<Record<string, unknown>> = [];
    mockTool('security_scan_full', async (input) => {
      inputs.push(input);
      return ok();
    });
    await runScans({ projectPath: makeProjectDir(), localOnly: true });
    await runScans({ projectPath: makeProjectDir() });
    expect(inputs[0]?.['local_only']).toBe(true);
    expect(inputs[1]?.['local_only']).toBeUndefined();
  });

  it("hands every step the reason the tree is not built (a pull request's, without --build-pr), and only when given", async () => {
    const seen: Array<string | undefined> = [];
    mockTool('security_scan_full', async (_input, plugin) => {
      seen.push(plugin.buildRefused);
      return ok();
    });
    await runScans({ projectPath: makeProjectDir(), buildRefused: "the tree is a pull request's" });
    await runScans({ projectPath: makeProjectDir() });
    expect(seen).toEqual(["the tree is a pull request's", undefined]);
  });

  // Follow-up X1: the files a step's scanner only partly parsed travel to the
  // gate — per missing name, so `--accept-partial-parse` can be matched
  // against exactly the gap they cause.
  it('carries each step\'s partly parsed files into partial_parses, per missing name', async () => {
    const partial = (file: string) => ({ file, type: 'PartialParsing', message: 'Syntax error' });
    mockTool('security_scan_full', async () =>
      ok({
        tools_run: [
          { name: 'semgrep', status: 'ok', reason: 'partial', partially_parsed: [partial('wp/a.php'), partial('b.js')] },
          { name: 'bandit', status: 'ok' },
        ],
        missing_tools: ['semgrep'],
      }),
    );
    mockTool('map_attack_surface', async () =>
      ok({
        tools_run: [{ name: 'semgrep', status: 'ok', partially_parsed: [partial('wp/a.php')] }],
        missing_tools: ['semgrep'],
        partially_parsed: [partial('wp/a.php')],
      }),
    );
    mockTool('scan_dast', async () =>
      ok({
        tools_run: [{ name: 'guardian-dast', status: 'ok' }],
        missing_tools: ['guardian-dast:partial-surface'],
        summary: { surface_gaps: { missing_tools: ['semgrep'], partially_parsed: [partial('wp/a.php')] } },
      }),
    );
    mockTool('license_compatibility', async () =>
      ok({
        // Not missing: a partial list on a run whose name is not a gap names no gap.
        tools_run: [{ name: 'trivy', status: 'ok', partially_parsed: [partial('x')] }],
        missing_tools: [],
      }),
    );

    const { steps } = await runScans({ projectPath: makeProjectDir(), baseUrl: 'https://example.test' });
    const of = (tool: string) => steps.find((s) => s.tool === tool);
    const pp = (file: string, type = 'PartialParsing') => ({ file, type });
    expect(of('security_scan_full')?.partial_parses).toEqual({ semgrep: [pp('wp/a.php'), pp('b.js')] });
    expect(of('map_attack_surface')?.partial_parses).toEqual({ semgrep: [pp('wp/a.php')] });
    expect(of('scan_dast')?.partial_parses).toEqual({ 'guardian-dast:partial-surface': [pp('wp/a.php')] });
    expect(of('license_compatibility')?.partial_parses).toBeUndefined();
    expect(of('detect_stack')?.partial_parses).toBeUndefined();
  });

  // A file whose taint analysis timed out travels to the gate with its own
  // type (review of the LLM pack, round 2, I-C). Since review 8 (finding 3)
  // the gate reports it as a note and never gates on it — a medium-sized
  // codebase never reached exit 0 — while a per-file Timeout still gates
  // unless the project's committed .guardian/scan.yml accepts it.
  it('a Fixpoint timeout reaches the gate with its type and is a note; a per-file Timeout gates unless scan.yml accepts it', async () => {
    const gateFor = async (type: string, acceptTimeouts: string[]) => {
      mockTool('security_scan_full', async () =>
        ok({
          tools_run: [{ name: 'semgrep', status: 'ok', reason: 'partial', partially_parsed: [{ file: 'sql/base.py', type, message: 'x' }] }],
          missing_tools: ['semgrep'],
        }),
      );
      const { steps } = await runScans({ projectPath: makeProjectDir() });
      const step = steps.find((s) => s.tool === 'security_scan_full');
      expect(step?.partial_parses).toEqual({ semgrep: [{ file: 'sql/base.py', type }] });
      const v = evaluateGate({
        findings: [],
        baseline: null,
        failOn: 'high',
        steps,
        droppedBaselineEntries: 0,
        acceptedPartialParses: ['sql/base.py'],
        acceptedTimeouts: acceptTimeouts,
      });
      return { exitCode: v.exitCode, coverage: v.coverage, accepted: v.acceptedGaps.length, notes: v.coverageNotes.length };
    };
    expect(await gateFor('Timeout', [])).toEqual({ exitCode: CI_EXIT.INCOMPLETE_SCAN, coverage: 'partial', accepted: 0, notes: 0 });
    expect(await gateFor('Timeout', ['sql/base.py'])).toEqual({ exitCode: CI_EXIT.PASS, coverage: 'partial', accepted: 1, notes: 0 });
    expect(await gateFor('Fixpoint timeout', [])).toEqual({ exitCode: CI_EXIT.PASS, coverage: 'partial', accepted: 0, notes: 1 });
  });

  it("returns the project's .guardian/scan.yml as the scans read it", async () => {
    const dir = makeProjectDir();
    mkdirSync(join(dir, '.guardian'), { recursive: true });
    writeFileSync(join(dir, '.guardian', 'scan.yml'), 'semgrep:\n  accept_timeouts:\n    - big.js\n');
    mockTool('security_scan_full', async () => ok({ tools_run: [], missing_tools: [] }));
    const { scanSettings } = await runScans({ projectPath: dir });
    expect(scanSettings.kind).toBe('loaded');
    expect(scanSettings.settings.semgrep.acceptTimeouts).toEqual(['big.js']);
  });

  // Round 3 (N-1): the plugin pack's own fixpoint timeouts stay on the run
  // for history, but they are not the scan's gap and never reach the gate.
  it("the plugin pack's own fixpoint timeouts never reach the gate: exit 0 alone, and an accepted parse gap beside them still passes", async () => {
    const pack = { file: 'hooks/bashGuard.ts', type: 'Fixpoint timeout (plugin pack)', message: 'x', functions: 1 };
    const gateOf = async (run: Record<string, unknown>, missing: string[], accept: string[]) => {
      mockTool('security_scan_full', async () => ok({ tools_run: [run], missing_tools: missing }));
      const { steps } = await runScans({ projectPath: makeProjectDir() });
      const step = steps.find((s) => s.tool === 'security_scan_full');
      const v = evaluateGate({ findings: [], baseline: null, failOn: 'high', steps, droppedBaselineEntries: 0, acceptedPartialParses: accept });
      return { partial_parses: step?.partial_parses, exitCode: v.exitCode, coverage: v.coverage };
    };
    expect(await gateOf({ name: 'semgrep', status: 'ok', reason: 'note', partially_parsed: [pack] }, [], [])).toEqual({
      partial_parses: undefined,
      exitCode: CI_EXIT.PASS,
      coverage: 'full',
    });
    const parse = { file: 'wp/a.php', type: 'PartialParsing', message: 'x' };
    const mixed = await gateOf({ name: 'semgrep', status: 'ok', reason: 'partial', partially_parsed: [parse, pack] }, ['semgrep'], ['wp/a.php']);
    expect(mixed).toEqual({ partial_parses: { semgrep: [{ file: 'wp/a.php', type: 'PartialParsing' }] }, exitCode: CI_EXIT.PASS, coverage: 'partial' });
  });

  it('never carries a DAST surface gap that is more than a partial parse', async () => {
    const partial = { file: 'wp/a.php', type: 'PartialParsing', message: 'x' };
    for (const surface_gaps of [
      // Its route recovery failed too: routes were lost to something no one accepted.
      { missing_tools: ['semgrep'], partially_parsed: [partial], failed_steps: [{ name: 'semgrep-metavar-recovery', status: 'failed' }] },
      // Another scanner missing from the surface.
      { missing_tools: ['semgrep', 'other'], partially_parsed: [partial] },
      // No file at all.
      { missing_tools: ['semgrep'], partially_parsed: [] },
    ]) {
      mockTool('scan_dast', async () =>
        ok({ tools_run: [{ name: 'guardian-dast', status: 'ok' }], missing_tools: ['guardian-dast:partial-surface'], summary: { surface_gaps } }),
      );
      const { steps } = await runScans({ projectPath: makeProjectDir(), baseUrl: 'https://example.test' });
      expect(steps.find((s) => s.tool === 'scan_dast')?.partial_parses).toBeUndefined();
    }
  });

  it('does NOT abort when a step refuses — it records and continues', async () => {
    // The wrong implementation stops at the first refusal and reports LESS
    // than one that continues and says what it missed — every step after
    // the refusal must still be called, not just "some" of them.
    const calls: string[] = [];
    for (const name of ALL_NAMES) {
      mockTool(name, async () => {
        calls.push(name);
        return ok();
      });
    }
    mockTool('map_attack_surface', async () => {
      calls.push('map_attack_surface');
      return { ok: false, error: { code: 'no_surface_snapshot', message: 'no snapshot yet' } };
    });

    const result = await runScans({
      projectPath: makeProjectDir(),
      baseUrl: 'https://example.test',
    });

    expect(calls).toEqual(ORDER_WITH_DAST);
    expect(result.steps.map((s) => s.tool)).toEqual(ORDER_WITH_DAST);

    const surfaceStep = result.steps.find((s) => s.tool === 'map_attack_surface');
    expect(surfaceStep?.ran).toBe(false);
    expect(surfaceStep?.reason).toContain('no snapshot yet');

    // Every OTHER step still ran clean.
    for (const step of result.steps) {
      if (step.tool === 'map_attack_surface') continue;
      expect(step.ran).toBe(true);
    }
  });

  it('records a step that throws as ran:false rather than crashing the run', async () => {
    const calls: string[] = [];
    for (const name of ALL_NAMES) {
      mockTool(name, async () => {
        calls.push(name);
        return ok();
      });
    }
    mockTool('security_scan_full', async () => {
      calls.push('security_scan_full');
      throw new Error('boom: semgrep process crashed');
    });

    // A wrong implementation with no try/catch around the handler call
    // would let this throw escape runScans() entirely, and this await
    // would reject instead of resolving.
    const result = await runScans({ projectPath: makeProjectDir() });

    expect(calls).toEqual(ORDER_WITHOUT_DAST);
    const step = result.steps.find((s) => s.tool === 'security_scan_full');
    expect(step?.ran).toBe(false);
    expect(step?.reason).toContain('boom: semgrep process crashed');

    // The rest of the pipeline still ran and is recorded.
    expect(result.steps.map((s) => s.tool)).toEqual(ORDER_WITHOUT_DAST);
  });

  it('records a step as ran:false, not a crash, when the named tool is not registered', async () => {
    // A typo'd name or a tool removed later must not take the whole run
    // down, and must not vanish silently either — it has to show up in
    // `steps` as a named, reasoned gap, same as any other refusal.
    const tool = TOOLS.find((t) => t.name === 'license_compatibility');
    if (!tool) throw new Error('fixture error: license_compatibility must be registered');
    const index = TOOLS.indexOf(tool);
    TOOLS.splice(index, 1);
    try {
      const result = await runScans({ projectPath: makeProjectDir() });

      expect(result.steps.map((s) => s.tool)).toEqual(ORDER_WITHOUT_DAST);
      const missing = result.steps.find((s) => s.tool === 'license_compatibility');
      expect(missing?.ran).toBe(false);
      expect(missing?.reason).toBeTruthy();

      // Steps after the gap still ran.
      const surfaceStep = result.steps.find((s) => s.tool === 'map_attack_surface');
      const validateStep = result.steps.find((s) => s.tool === 'validate_finding');
      expect(surfaceStep?.ran).toBe(true);
      expect(validateStep?.ran).toBe(true);
    } finally {
      TOOLS.splice(index, 0, tool);
    }
  });

  it('uses an ephemeral database that does not touch the project directory', async () => {
    const projectPath = makeProjectDir();

    await runScans({ projectPath });

    // The baseline file is written by the CLI, not this module — and
    // nothing else here should create .guardian/ under the SCANNED project
    // either. A wrong implementation that opens its database via
    // openDatabase({ projectPath }) (which resolves .guardian/guardian.db
    // under the given project root) would fail this.
    expect(existsSync(join(projectPath, '.guardian'))).toBe(false);
  });

  it('removes its ephemeral temp directory on exit, on both a clean run and a thrown step', async () => {
    const projectPath = makeProjectDir();
    createdCiTempDirs.length = 0;

    await runScans({ projectPath });
    expect(createdCiTempDirs).toHaveLength(1);
    expect(existsSync(createdCiTempDirs[0] ?? '')).toBe(false);

    mockTool('detect_stack', async () => {
      throw new Error('boom');
    });
    await runScans({ projectPath });
    expect(createdCiTempDirs).toHaveLength(2);
    expect(existsSync(createdCiTempDirs[1] ?? '')).toBe(false);
  });

  it('collects findings from every step that produced them', async () => {
    const projectPath = makeProjectDir();

    const sastFinding: Finding = {
      fingerprint: 'fp-sast-1',
      tool: 'semgrep',
      severity: 'high',
      category: 'security',
      title: 'SQL injection',
      file_path: 'src/db.ts',
      fix_available: false,
    };
    const dastFinding: Finding = {
      fingerprint: 'fp-dast-1',
      tool: 'guardian-dast',
      severity: 'medium',
      category: 'security',
      title: 'Missing CORS header',
      fix_available: false,
    };

    // Both mocks persist through the REAL storage layer handed to them via
    // `ctx`, mirroring what the real scan-tool factory / scan_dast handler
    // do. The point of this test: if runScans read findings out of the
    // RETURN VALUE instead of back out of storage, it would see none here,
    // since neither mock's return payload carries a `findings` field.
    mockTool('security_scan_full', async (_input, ctx) => {
      const scanId = 'scan-sast-1';
      ctx.storage.scans.insert({
        scan_id: scanId,
        scan_type: 'security_full',
        project_path: projectPath,
        tree_hash: 'th1',
      });
      ctx.storage.findings.bulkInsert([{ ...sastFinding, scan_id: scanId }]);
      ctx.storage.scans.finalize({
        scan_id: scanId,
        status: 'completed',
        tools_run: [{ name: 'semgrep', status: 'ok' }],
        missing_tools: [],
      });
      return ok();
    });
    mockTool('scan_dast', async (_input, ctx) => {
      const scanId = 'scan-dast-1';
      ctx.storage.scans.insert({
        scan_id: scanId,
        scan_type: 'dast',
        project_path: projectPath,
        tree_hash: 'th1',
      });
      ctx.storage.findings.bulkInsert([{ ...dastFinding, scan_id: scanId }]);
      ctx.storage.scans.finalize({
        scan_id: scanId,
        status: 'completed',
        tools_run: [{ name: 'guardian-dast', status: 'ok' }],
        missing_tools: [],
      });
      return ok();
    });

    const result = await runScans({ projectPath, baseUrl: 'https://example.test' });

    expect(result.findings.map((f) => f.fingerprint).sort()).toEqual(['fp-dast-1', 'fp-sast-1']);
  });

  it("gates on every unscoped row of the scanned project, whatever its status — never another path's, never a scoped one", async () => {
    // Task 24: the findings used to be every scan row in the database, up to
    // 50, whatever project each belonged to and scoped or not. They are this
    // project's unscoped rows now — and ANY status (fix round 1, I1): a
    // `failed` row often carries real findings (scan_iac fails the whole row
    // when one pass exits non-zero, yet keeps Trivy's results), and the gate's
    // rule is that a real regression outranks a coverage gap, never hides
    // behind it. The throwaway database has no older row to fall back on.
    const projectPath = resolveProjectPath(makeProjectDir()).path;
    const elsewhere = resolveProjectPath(makeProjectDir()).path;
    const finding = (fingerprint: string, severity: Finding['severity'] = 'high'): Finding => ({
      fingerprint, tool: 'semgrep', severity, category: 'security', title: fingerprint, fix_available: false,
    });

    mockTool('security_scan_full', async (_input, ctx) => {
      const persist = (
        scanId: string,
        project: string,
        fp: Finding,
        extra: { type?: 'sast' | 'iac'; meta?: Record<string, unknown>; failed?: boolean } = {},
      ): void => {
        ctx.storage.scans.insert({
          scan_id: scanId, scan_type: extra.type ?? 'sast', project_path: project, tree_hash: 't',
          ...(extra.meta !== undefined ? { meta: extra.meta } : {}),
        });
        ctx.storage.findings.bulkInsert([{ ...fp, scan_id: scanId }]);
        ctx.storage.scans.finalize({
          scan_id: scanId,
          status: extra.failed === true ? 'failed' : 'completed',
          tools_run: extra.failed === true
            ? [{ name: 'trivy-config', status: 'ok' }, { name: 'actionlint', status: 'failed' }]
            : [{ name: 'semgrep', status: 'ok' }],
          missing_tools: [],
        });
      };
      persist('other-project', elsewhere, finding('fp-elsewhere'));
      // scan_iac's shape: Trivy found a critical misconfiguration, actionlint
      // failed, so the row is `failed` — and the misconfiguration is real.
      persist('failed-iac', projectPath, { ...finding('fp-failed', 'critical'), tool: 'trivy' }, { type: 'iac', failed: true });
      persist('whole', projectPath, finding('fp-project'));
      // Last, so it is the NEWEST row: what keeps it out is that it is
      // scoped, not that something newer superseded it.
      persist('scoped', projectPath, finding('fp-scoped'), { meta: { scope: { kind: 'paths', paths: ['src'] } } });
      return ok();
    });

    const result = await runScans({ projectPath });

    expect(result.findings.map((f) => f.fingerprint).sort()).toEqual(['fp-failed', 'fp-project']);
  });

  // Review 12, finding 11: gitleaks reads history as -U0 hunks, and a private
  // key replaced in place had its BEGIN / END lines in none. Under a ref, the
  // files changed since it are read whole: scan_secrets scoped to their paths,
  // right after security_scan_full; its findings gate like the rest.
  it('with changedSince: scan_secrets reads the changed files whole (scope.paths), after security_scan_full, and its findings gate', async () => {
    const projectPath = resolveProjectPath(makeProjectDir()).path;
    const git = (...args: string[]): string => {
      const r = spawnSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', ...args], { cwd: projectPath, encoding: 'utf8' });
      if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`);
      return r.stdout.trim();
    };
    git('init', '-q');
    writeFileSync(join(projectPath, 'same.js'), '1\n');
    writeFileSync(join(projectPath, 'key.pem'), 'a\n');
    git('add', '-A');
    git('commit', '-qm', 'base');
    const commit = git('rev-parse', 'HEAD');
    writeFileSync(join(projectPath, 'key.pem'), 'b\n');
    // A NUL byte: git reads the file as binary, and `git log -p` prints no hunk of it.
    writeFileSync(join(projectPath, 'blob.js'), '\0\nc\n');
    git('add', '-A');
    git('commit', '-qm', 'pr');

    const order: string[] = [];
    const inputs: unknown[] = [];
    mockTool('security_scan_full', async () => {
      order.push('security_scan_full');
      return ok();
    });
    mockTool('license_compatibility', async () => {
      order.push('license_compatibility');
      return ok();
    });
    mockTool('scan_secrets', async (input, ctx) => {
      order.push('scan_secrets');
      inputs.push(input);
      ctx.storage.scans.insert({ scan_id: 'whole', scan_type: 'secrets', project_path: projectPath, tree_hash: 't', meta: { scope: { kind: 'paths' } } });
      const leak = { tool: 'gitleaks', severity: 'high' as const, category: 'security' as const, title: 'key', fix_available: false, scan_id: 'whole' };
      ctx.storage.findings.bulkInsert([
        { ...leak, fingerprint: 'fp-key', file_path: 'key.pem', line_start: 1, line_end: 6, snippet: 'rule=private-key' },
        // One line: whole in the hunk that added it, so the history pass judged
        // it (with what applies only to history) — not taken from here...
        { ...leak, fingerprint: 'fp-one-line', file_path: 'key.pem', line_start: 1, line_end: 1, snippet: 'rule=aws-access-token' },
        // ...unless no hunk held it.
        { ...leak, fingerprint: 'fp-binary', file_path: 'blob.js', line_start: 2, line_end: 2, snippet: 'rule=aws-access-token' },
      ]);
      ctx.storage.scans.finalize({ scan_id: 'whole', status: 'completed', tools_run: [{ name: 'gitleaks-working-tree', status: 'ok' }], missing_tools: [] });
      return ok({ tools_run: [{ name: 'gitleaks-working-tree', status: 'ok' }], missing_tools: [] });
    });

    const result = await runScans({ projectPath, changedSince: { ref: 'BASE', commit, prefix: '' } });
    expect(order).toEqual(['security_scan_full', 'scan_secrets', 'license_compatibility']);
    expect(inputs).toEqual([{ project_path: projectPath, force: true, scope: { paths: ['blob.js', 'key.pem'] } }]);
    expect(result.findings.map((f) => f.fingerprint).sort()).toEqual(['fp-binary', 'fp-key']);

    // Without a ref, no such step.
    inputs.length = 0;
    await runScans({ projectPath });
    expect(inputs).toEqual([]);
  });

  it('with changedSince and a commit git cannot diff: a failed scan_secrets step — a gap, never a pass', async () => {
    const projectPath = resolveProjectPath(makeProjectDir()).path;
    spawnSync('git', ['init', '-q'], { cwd: projectPath });
    const result = await runScans({ projectPath, changedSince: { ref: 'BASE', commit: 'f'.repeat(40), prefix: '' } });
    const step = result.steps.find((s) => s.tool === 'scan_secrets');
    expect(step).toMatchObject({ ran: false, reason: expect.stringMatching(/^the files changed since BASE could not be listed/) });
    const verdict = evaluateGate({ findings: [], baseline: null, failOn: 'high', steps: result.steps, droppedBaselineEntries: 0 });
    expect(verdict.exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
  });

  // The test-integrity step (mcp/src/testintegrity/): under a diff base the
  // change since it is read for weakened tests, and its findings gate like any
  // other — a focused `.only` blocks at --fail-on high. No diff base, no step.
  it('with diffBase: the change since it is read for weakened tests, and a focused test blocks the gate', async () => {
    const projectPath = resolveProjectPath(makeProjectDir()).path;
    const git = (...args: string[]): string => {
      const r = spawnSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', ...args], { cwd: projectPath, encoding: 'utf8' });
      if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`);
      return r.stdout.trim();
    };
    git('init', '-q');
    mkdirSync(join(projectPath, 'src'), { recursive: true });
    const lines = (...l: string[]): string => `${l.join('\n')}\n`;
    writeFileSync(join(projectPath, 'src', 'a.test.js'), lines("it('a', () => { expect(1).toBe(1); });", "it('b', () => { expect(2).toBe(2); });"));
    git('add', '-A');
    git('commit', '-qm', 'base');
    const commit = git('rev-parse', 'HEAD');
    writeFileSync(join(projectPath, 'src', 'a.test.js'), lines("it.only('a', () => { expect(1).toBe(1); });", "it.skip('b', () => { expect(2).toBe(2); });"));

    const result = await runScans({ projectPath, diffBase: { ref: 'BASE', commit, prefix: '' } });
    const step = result.steps.find((s) => s.tool === 'guardian-test-integrity');
    expect(step).toMatchObject({ ran: true, missing_tools: [] });
    expect(step?.tools_run[0]).toMatchObject({ name: 'guardian-test-integrity', status: 'ok' });
    const weakened = result.findings.filter((f) => f.tool === 'guardian-test-integrity');
    expect(weakened.map((f) => `${f.rule_id} ${f.file_path}:${f.line_start} ${f.severity}`).sort()).toEqual([
      'test-focused src/a.test.js:1 high',
      'test-skipped src/a.test.js:2 medium',
    ]);
    const verdict = evaluateGate({ findings: result.findings, baseline: null, failOn: 'high', steps: result.steps, droppedBaselineEntries: 0 });
    expect(verdict.exitCode).toBe(CI_EXIT.GATE_FAILED);
    expect(verdict.blocking.map((f) => f.rule_id)).toEqual(['test-focused']);

    // No diff base: no step, no finding of the check.
    const plain = await runScans({ projectPath });
    expect(plain.steps.some((s) => s.tool === 'guardian-test-integrity')).toBe(false);
    expect(plain.findings.some((f) => f.tool === 'guardian-test-integrity')).toBe(false);
  });
}, RUN_SCANS_SUITE_TIMEOUT_MS);
