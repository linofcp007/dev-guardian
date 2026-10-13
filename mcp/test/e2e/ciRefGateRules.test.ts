/**
 * `dev-guardian scan --rules-ref`: a pull request that deletes the rule that
 * catches its new code and hides another file in a new `.guardianignore`
 * cannot gate itself — with `--rules-ref <base>` the base's rules and ignore
 * file apply. Real subprocess, real repositories, real Semgrep; split from
 * `ciRefGate.test.ts` (review 8, finding 6), whose header says the rest.
 */

import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { EVAL_JS, RULES, RUN_REAL, SCAN_TIMEOUT_MS, WEAKENED, blockingFiles, commitAll, newRepo, runCli, scanJson, write } from '../helpers/ciRefGate.js';
import { cleanupTempDirs } from '../helpers/tempDir.js';

vi.setConfig({ testTimeout: 3 * SCAN_TIMEOUT_MS, hookTimeout: 3 * SCAN_TIMEOUT_MS });

afterAll(cleanupTempDirs);

describe.skipIf(!RUN_REAL)('a pull request that deletes the rule that catches it, and hides a file (real scanners)', () => {
  let repo = '';
  let base = '';

  beforeAll(async () => {
    repo = await newRepo('ciref-rules-');
    write(repo, '.semgrep.yml', RULES);
    // A finding the base already accepted: it must keep matching the base's
    // baseline when the rule is read from the ref's copy.
    write(repo, 'index.js', EVAL_JS);
    const update = runCli(['baseline', 'update', '--project', repo, '--local-only']);
    expect(update.status === 0 || update.status === 2, `${update.stdout}\n${update.stderr}`).toBe(true);
    base = await commitAll(repo, 'base: one accepted finding, in the baseline');
    // The pull request: disarms the rule, adds an eval, hides another.
    write(repo, '.semgrep.yml', WEAKENED);
    write(repo, 'lib/new.js', EVAL_JS);
    write(repo, 'hidden/also.js', EVAL_JS);
    write(repo, '.guardianignore', 'hidden/\n');
    await commitAll(repo, 'pr');
  });

  it("control — with the base's baseline but the tree's rules, the pull request passes", () => {
    const { status, report } = scanJson(repo, '--baseline-ref', base);
    expect(report.blocking_findings).toEqual([]);
    expect(status).not.toBe(1);
    expect(report.rules_source).toEqual({ from: 'tree' });
  });

  it("--rules-ref <base>: the base's rule and ignore file apply — both new evals fail the gate, the accepted one still matches", () => {
    const { status, report } = scanJson(repo, '--baseline-ref', base, '--rules-ref', base);
    expect(status).toBe(1);
    expect(blockingFiles(report)).toEqual(['hidden/also.js', 'lib/new.js']);
    expect(report.blocking_findings.every((f) => f.rule_id === 'guardian-test-no-eval')).toBe(true);
    expect(report.rules_source).toMatchObject({ from: 'ref', ref: base, commit: base, copied: ['.semgrep.yml'] });
    expect(report.rules_source.tree_differences).toEqual([
      { path: '.guardianignore', change: 'added', applied: 'ref', read_by: ['guardian'] },
      { path: '.semgrep.yml', change: 'modified', applied: 'ref', read_by: ['semgrep'] },
    ]);
  });
});
