/**
 * `dev-guardian scan --diff-base <ref>`, as a REAL SUBPROCESS with the real
 * scanners: the change since the ref is read for weakened tests
 * (`mcp/src/testintegrity/`), and its findings gate through the SAME JSON
 * verdict dev-spec-driven's finish gate reads (`exit_code`,
 * `blocking_findings[].{rule_id, tool, file_path, line_start, severity}` —
 * keys only ever added, `unit/ci/verdictContract.test.ts`).
 *
 * The control: the same tree scanned WITHOUT a diff base passes — a
 * whole-project scan has no diff to read the weakening from — so the flag is
 * what makes the difference. `--baseline-ref` alone implies the same base.
 */

import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { CLEAN_JS, RULES, RUN_REAL, SCAN_TIMEOUT_MS, commitAll, newRepo, scanJson, write } from '../helpers/ciRefGate.js';
import { cleanupTempDirs } from '../helpers/tempDir.js';

vi.setConfig({ testTimeout: 3 * SCAN_TIMEOUT_MS, hookTimeout: 3 * SCAN_TIMEOUT_MS });

afterAll(cleanupTempDirs);

const TEST = "const add = require('./index');\n\ndescribe('add', () => {\n  it('adds', () => {\n    expect(add(1, 1)).toBe(2);\n  });\n  it('adds negatives', () => {\n    expect(add(-1, -1)).toBe(-2);\n  });\n});\n";

describe.skipIf(!RUN_REAL)('scan --diff-base: weakened tests in the change gate the scan (real scanners)', () => {
  let repo = '';
  let base = '';

  beforeAll(async () => {
    repo = await newRepo('ci-diff-base-');
    write(repo, '.semgrep.yml', RULES);
    write(repo, 'index.js', CLEAN_JS);
    write(repo, 'index.test.js', TEST);
    write(repo, '.guardian/baseline.json', `${JSON.stringify({ version: 1, generated_at: '2026-10-28T00:00:00.000Z', entries: [] }, null, 2)}\n`);
    base = await commitAll(repo, 'base');
    // The branch "makes the suite green": the failing test skipped, the other focused.
    write(repo, 'index.test.js', TEST.replace("it('adds'", "it.only('adds'").replace("it('adds negatives'", "it.skip('adds negatives'"));
    await commitAll(repo, 'make it green');
  });

  it('control — no diff base: the whole-project scan reads no change, and nothing of the check blocks', () => {
    const { report } = scanJson(repo);
    expect(report.blocking_findings.filter((f) => f.rule_id?.startsWith('test-'))).toEqual([]);
  });

  it('--diff-base <base>: the focused test is a blocking high finding, the skip a medium new one; exit 1', () => {
    const { status, report } = scanJson(repo, '--diff-base', base);
    expect(status).toBe(1);
    const blocking = report.blocking_findings.map((f) => `${f.rule_id ?? ''} ${(f.file_path ?? '').replace(/\\/g, '/')}`);
    expect(blocking).toEqual(['test-focused index.test.js']);
    const all = (report.new_findings as Array<{ tool?: string; rule_id?: string; severity?: string }>)
      .filter((f) => f.tool === 'guardian-test-integrity')
      .map((f) => `${f.rule_id ?? ''} ${f.severity ?? ''}`)
      .sort();
    expect(all).toEqual(['test-focused high', 'test-skipped medium']);
  });

  it('--baseline-ref <base> alone reads the same change', () => {
    const { status, report } = scanJson(repo, '--baseline-ref', base);
    expect(status).toBe(1);
    expect(report.blocking_findings.map((f) => f.rule_id)).toEqual(['test-focused']);
  });
});
