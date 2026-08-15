/**
 * `runScans` orchestrates the CI scan pipeline over the SAME tool handlers
 * the MCP server calls — see `runScans.ts`'s own doc comment. Every handler
 * is mocked at the `TOOLS` boundary (see the module doc comment on
 * `mockTool` below): this suite verifies ORCHESTRATION — order, refusal
 * handling, exception handling, where findings come from, temp-dir hygiene
 * — never scanning itself, so none of it needs Semgrep installed.
 */
import { existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { runScans, SCAN_SEQUENCE } from '../../src/ci/runScans.js';
import { TOOLS } from '../../src/tools/index.js';
import type { ToolModule } from '../../src/tools/index.js';
import type { Finding, ToolResult } from '../../src/types.js';

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
  return mkdtempSync(join(tmpdir(), 'guardian-ci-project-'));
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
});
