/**
 * compliance_check against REAL Semgrep: the tool resolves the shipped
 * `configs/semgrep/rgpd.yml`, runs it over the project, and stores what it
 * finds as compliance findings. complianceTools.test.ts pins the tool's
 * handling of each report shape with a scripted Semgrep; this file proves the
 * wiring end to end — the path, the flags, the parser — on a project written
 * to trip one rule of each half of the pack.
 *
 * Trivy is reported absent so the run does not depend on it (and the
 * coverage is `partial` for that reason alone, which is asserted too).
 *
 * SKIPPED, not silently passed, when Semgrep is absent;
 * `GUARDIAN_REQUIRE_SEMGREP=1` turns that absence into a hard failure.
 */

import { semgrepAvailable } from '../helpers/semgrep.js';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

vi.setConfig({ testTimeout: 180_000 });

vi.mock('../../src/tools/scanHelpers.js', async () => {
  const actual = await vi.importActual<typeof import('../../src/tools/scanHelpers.js')>('../../src/tools/scanHelpers.js');
  return {
    ...actual,
    scannerAvailable: vi.fn(async (name: string) => (name === 'trivy' ? null : actual.scannerAvailable(name))),
  };
});

import type { PluginContext } from '../../src/context.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/complianceCheck.js');
});

const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';
const AVAILABLE = semgrepAvailable();

function makePlugin(projectPath: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: { command: 'bash', args_prefix: [], needs_wsl_path_translate: false, label: 'fake' },
    scriptsDir: projectPath,
    progressNotifier: { send: () => {} },
  };
}

interface Result {
  ok: boolean;
  tools_run: { name: string; status: string; reason?: string }[];
  missing_tools: string[];
  coverage: string;
  top_findings: { rule_id?: string; category: string; subcategory?: string; file_path?: string; line_start?: number }[];
}

describe('compliance_check runs the RGPD pack (real Semgrep)', () => {
  it.runIf(REQUIRE_SEMGREP)('the toolchain must be usable when the flag is set', () => {
    expect(AVAILABLE).toBe(true);
  });

  it.skipIf(!AVAILABLE)('finds personal data in a log and a tracker loaded before consent', async () => {
    const project = makeTempDir('compliance-rgpd-');
    mkdirSync(join(project, 'src'));
    writeFileSync(
      join(project, 'src', 'login.js'),
      [
        'const logger = require("./logger");',
        'function login(user) {',
        '  logger.info("login", user.email);',
        '  logger.info("login", user.id);',
        '}',
        'module.exports = { login };',
        '',
      ].join('\n'),
      'utf8',
    );
    writeFileSync(
      join(project, 'index.html'),
      [
        '<!doctype html>',
        '<html lang="pt-PT"><head>',
        '<script async src="https://www.googletagmanager.com/gtag/js?id=G-TEST1234"></script>',
        '</head><body></body></html>',
        '',
      ].join('\n'),
      'utf8',
    );

    const tool = TOOLS.find((t) => t.name === 'compliance_check');
    if (tool === undefined) throw new Error('compliance_check is not registered');
    const r = (await tool.handler({ project_path: project }, makePlugin(project))) as unknown as Result;

    expect(r.ok).toBe(true);
    expect(r.tools_run).toContainEqual({ name: 'semgrep-rgpd', status: 'ok' });
    const rgpd = r.top_findings
      .filter((f) => (f.rule_id ?? '').includes('rgpd-'))
      .map((f) => [(f.rule_id ?? '').split('.').pop(), f.category, f.subcategory, f.file_path, f.line_start])
      .sort();
    expect(rgpd).toEqual([
      ['rgpd-pii-in-log-js', 'compliance', 'rgpd-pii-in-logs', 'src/login.js', 3],
      ['rgpd-tracker-ga4-without-consent', 'compliance', 'rgpd-tracker-without-consent', 'index.html', 3],
    ]);
    // Trivy was reported absent, so the licence half is a named gap.
    expect(r.missing_tools).toContain('trivy');
    expect(r.coverage).toBe('partial');
  });

  // Fix round 1, item 5, against the real binary: a Go-only project gives
  // `scanned: []` with the rules LOADED (`time.rules`), which must read as not
  // applicable — and never put `semgrep` in missing_tools.
  it.skipIf(!AVAILABLE)('reports a Go-only project as not applicable, not as a missing scanner', async () => {
    const project = makeTempDir('compliance-rgpd-go-');
    writeFileSync(join(project, 'main.go'), 'package main\n\nfunc main() {}\n', 'utf8');
    const tool = TOOLS.find((t) => t.name === 'compliance_check');
    if (tool === undefined) throw new Error('compliance_check is not registered');
    const r = (await tool.handler({ project_path: project }, makePlugin(project))) as unknown as Result;
    const run = r.tools_run.find((t) => t.name === 'semgrep-rgpd');
    expect(run?.status).toBe('skipped');
    expect(run?.reason).toMatch(/^not applicable/);
    expect(r.missing_tools).not.toContain('semgrep');
  });
});
