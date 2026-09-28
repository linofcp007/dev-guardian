/**
 * The CI gate and the attack-surface steps (controller ruling on I3, item 3).
 *
 * "Not applicable is never a gap": a project with no file in any routes-pack
 * language (Terraform only, say) has nothing for Semgrep to map, and the CI
 * gate must not exit 2 because of `map_attack_surface` — nor because
 * `validate_finding` then found no snapshot. Only "route-language targets
 * exist, and Semgrep scanned none of them" is a gap.
 *
 * `map_attack_surface` and `validate_finding` run for real, through
 * `runScans` and `evaluateGate`; the three steps before them are mocked at
 * the TOOLS boundary as clean runs (as `ciRunScans.test.ts` does), so the
 * verdict can only move because of the surface.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { evaluateGate } from '../../src/ci/gate.js';
import { runScans } from '../../src/ci/runScans.js';
import { CI_EXIT } from '../../src/ci/types.js';
import { TOOLS, type ToolModule } from '../../src/tools/index.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

afterAll(cleanupTempDirs);
vi.setConfig({ testTimeout: 180_000 });

const SEMGREP_INSTALLED = await isInstalled('semgrep');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

const MOCKED = ['detect_stack', 'security_scan_full', 'license_compatibility'];
const originalHandlers = new Map<string, ToolModule['handler']>();

beforeEach(() => {
  for (const name of MOCKED) {
    const tool = TOOLS.find((t) => t.name === name);
    if (!tool) throw new Error(`fixture error: '${name}' is not registered`);
    originalHandlers.set(name, tool.handler);
    tool.handler = async () => ({ ok: true, tools_run: [{ name: `${name}-scanner`, status: 'ok' }], missing_tools: [] });
  }
});

afterEach(() => {
  for (const [name, handler] of originalHandlers) {
    const tool = TOOLS.find((t) => t.name === name);
    if (tool) tool.handler = handler;
  }
  originalHandlers.clear();
});

async function gate(projectPath: string) {
  const { findings, steps } = await runScans({ projectPath });
  return { steps, verdict: evaluateGate({ findings, baseline: null, failOn: 'high', steps, droppedBaselineEntries: 0 }) };
}

describe('CI gate × map_attack_surface: not applicable is never a gap', () => {
  it('a Terraform-only project: Semgrep skipped as not applicable, no surface gap, exit 0', async () => {
    const project = makeTempDir('ci-surface-tf-');
    writeFileSync(join(project, 'main.tf'), 'resource "null_resource" "x" {}\n', 'utf8');

    const { steps, verdict } = await gate(project);

    const surface = steps.find((s) => s.tool === 'map_attack_surface');
    expect(surface?.ran).toBe(true);
    expect(surface?.missing_tools).toEqual([]);
    expect(surface?.tools_run).toEqual([
      { name: 'semgrep', status: 'skipped', reason: expect.stringMatching(/^not applicable/) as unknown as string },
    ]);
    expect(steps.find((s) => s.tool === 'validate_finding')?.ran).toBe(true);
    expect(verdict.coverageGaps).toEqual([]);
    expect(verdict.exitCode).toBe(CI_EXIT.PASS);
  });

  // Follow-up 2: Semgrep's built-in default ignore (no .semgrepignore) skips
  // test/, tests/ and *_test.go. A Terraform module whose only Go code is its
  // Terratest suite has nothing Semgrep would scan — not applicable. At the
  // follow-up-1 head it counted 1 target, scanned 0, and exited 2 every run.
  it('a Terraform module with Terratest under test/: not applicable, no surface gap, exit 0', async () => {
    const project = makeTempDir('ci-surface-terratest-');
    writeFileSync(join(project, 'main.tf'), 'resource "null_resource" "x" {}\n', 'utf8');
    mkdirSync(join(project, 'test'));
    writeFileSync(
      join(project, 'test', 'module_test.go'),
      'package test\n\nimport "testing"\n\nfunc TestModule(t *testing.T) {}\n',
      'utf8',
    );

    const { steps, verdict } = await gate(project);

    const surface = steps.find((s) => s.tool === 'map_attack_surface');
    expect(surface?.missing_tools).toEqual([]);
    expect(surface?.tools_run[0]?.reason).toMatch(/^not applicable/);
    expect(steps.find((s) => s.tool === 'validate_finding')?.ran).toBe(true);
    expect(verdict.coverageGaps).toEqual([]);
    expect(verdict.exitCode).toBe(CI_EXIT.PASS);
  });

  it.skipIf(!SEMGREP_INSTALLED)(
    'a project with PHP files Semgrep scanned none of (.semgrepignore): a surface gap, exit 2',
    async () => {
      const project = makeTempDir('ci-surface-php-');
      mkdirSync(join(project, 'src'));
      writeFileSync(join(project, 'src', 'index.php'), "<?php\nregister_rest_route('app/v1', '/items', []);\n", 'utf8');
      writeFileSync(join(project, '.semgrepignore'), 'src/\n', 'utf8');

      const { steps, verdict } = await gate(project);

      const surface = steps.find((s) => s.tool === 'map_attack_surface');
      expect(surface?.missing_tools).toEqual(['semgrep']);
      expect(surface?.tools_run[0]).toMatchObject({ name: 'semgrep', status: 'skipped' });
      expect(surface?.tools_run[0]?.reason).toMatch(/scanned 0 of 1 file/);
      expect(verdict.coverageGaps.some((g) => g.startsWith('map_attack_surface: semgrep skipped'))).toBe(true);
      expect(verdict.exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
    },
  );

  it.runIf(REQUIRE_SEMGREP)('GUARDIAN_REQUIRE_SEMGREP=1 — the scanned-0 case must be exercised', () => {
    expect(SEMGREP_INSTALLED, 'GUARDIAN_REQUIRE_SEMGREP=1 but semgrep is not on PATH').toBe(true);
  });
});
