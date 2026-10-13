/**
 * `dev-guardian scan --reset-exclusions-from`: a pull request that hides its
 * eval in `src/.semgrepignore` and its secret in `.gitleaksignore` cannot
 * gate itself. Real subprocess, real repositories, real Semgrep and
 * gitleaks; split from `ciRefGate.test.ts` (review 8, finding 6), whose
 * header says the rest.
 */

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { CLEAN_JS, EVAL_JS, FAST_TIMEOUT_MS, GITLEAKS_INSTALLED, IN_CI, RULES, RUN_REAL, SCAN_TIMEOUT_MS, blockingFiles, commitAll, newRepo, runCli, scanJson, write } from '../helpers/ciRefGate.js';
import { cleanupTempDirs } from '../helpers/tempDir.js';

vi.setConfig({ testTimeout: 3 * SCAN_TIMEOUT_MS, hookTimeout: 3 * SCAN_TIMEOUT_MS });

afterAll(cleanupTempDirs);

/**
 * Review of round 1, R-1: `.semgrepignore` (at any depth) and
 * `.gitleaksignore` cannot be read from a ref by any scanner flag, so a pull
 * request adding them passed even with both ref flags — the only trace a line
 * of the job log. `--reset-exclusions-from` puts them back in the (disposable)
 * checkout before the scan.
 */
describe.skipIf(!RUN_REAL || !GITLEAKS_INSTALLED)('a pull request that hides its eval in src/.semgrepignore and its secret in .gitleaksignore (real scanners)', () => {
  let repo = '';
  let base = '';

  beforeAll(async () => {
    repo = await newRepo('ciref-reset-');
    write(repo, '.semgrep.yml', RULES);
    write(repo, 'index.js', CLEAN_JS);
    base = await commitAll(repo, 'base: clean');
    // The pull request: an eval, hidden by a nested .semgrepignore ...
    write(repo, 'src/evil.js', EVAL_JS);
    write(repo, 'src/.semgrepignore', 'evil.js\n');
    // ... and a committed key, hidden by its gitleaks fingerprint.
    write(repo, 'config.ini', `aws_access_key_id = ${['AKIA', 'IOSFODNN7', 'ABCDEFG'].join('')}\n`);
    const leak = await commitAll(repo, 'pr: eval and key');
    write(repo, '.gitleaksignore', `${leak}:config.ini:aws-access-token:1\n`);
    await commitAll(repo, 'pr: hide them');
  });

  it('control — with --baseline-ref and --rules-ref alone, both stay hidden and the gate passes', () => {
    const { status, report } = scanJson(repo, '--baseline-ref', base, '--rules-ref', base);
    expect(report.blocking_findings).toEqual([]);
    expect(status).not.toBe(1);
    // Named — the only trace there was.
    expect((report.rules_source.tree_differences ?? []).map((d) => d['path'])).toEqual(['.gitleaksignore', 'src/.semgrepignore']);
  });

  it('--reset-exclusions-from <base>: both files are gone before the scan, both findings come back, exit 1', () => {
    const { status, report } = scanJson(repo, '--baseline-ref', base, '--rules-ref', base, '--reset-exclusions-from', base);
    expect(status).toBe(1);
    expect(blockingFiles(report)).toEqual(['config.ini', 'src/evil.js']);
    expect((report as unknown as Record<string, unknown>)['exclusions_reset']).toEqual({
      ref: base,
      commit: base,
      restored: [],
      removed: ['.gitleaksignore', 'src/.semgrepignore'],
    });
    // The checkout is left reset: it is disposable.
    expect(existsSync(join(repo, '.gitleaksignore'))).toBe(false);
  });

  it('a checkout with changes is refused (exit 3), and nothing in it is touched', async () => {
    const dirty = await newRepo('ciref-reset-dirty-');
    write(dirty, 'index.js', CLEAN_JS);
    const at = await commitAll(dirty, 'base');
    write(dirty, '.semgrepignore', 'index.js\n');
    const r = runCli(['scan', '--project', dirty, '--reset-exclusions-from', at], FAST_TIMEOUT_MS, IN_CI);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/runs only in a clean checkout/);
    expect(existsSync(join(dirty, '.semgrepignore'))).toBe(true);
  });

  it('outside CI (no CI=true) it is refused with exit 3, and a clean checkout keeps its own exclusion files', async () => {
    const mine = await newRepo('ciref-reset-local-');
    write(mine, 'index.js', CLEAN_JS);
    const at = await commitAll(mine, 'base');
    write(mine, '.semgrepignore', 'index.js\n');
    await commitAll(mine, 'my own .semgrepignore');
    const r = runCli(['scan', '--project', mine, '--reset-exclusions-from', at], FAST_TIMEOUT_MS);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(
      /--reset-exclusions-from rewrites tracked files and runs only in CI \(CI=true\); outside CI, review the PR's exclusion-file changes instead/,
    );
    expect(r.stdout).toBe('');
    expect(existsSync(join(mine, '.semgrepignore'))).toBe(true);
  });
});
