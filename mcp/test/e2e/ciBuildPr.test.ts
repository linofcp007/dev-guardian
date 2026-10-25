/**
 * `dev-guardian scan --build-pr`'s usage rules, as a real subprocess (review of
 * 3.6.0, the .NET decision). Under `--baseline-ref` / `--rules-ref` the tree is
 * a pull request's, so the gate does not build it — the .NET analyzers are a
 * named gap (`test/integration/scanSastProjectRules.test.ts`, `gateGaps.test.ts`).
 * `--build-pr` builds it all the same: argv only, like `--start-command`, and
 * meaningless without a ref. None of these reaches a scanner.
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { type SpawnSyncReturns } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it, vi } from 'vitest';
import { spawnSyncCapped, timeoutAbove } from '../helpers/spawnCap.js';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const CLI = resolve(REPO_ROOT, 'cli', 'dev-guardian.mjs');
/** A usage error never reaches a scanner; this is a hang-breaker only. */
const FAST_TIMEOUT_MS = 45_000;

vi.setConfig({ testTimeout: timeoutAbove(FAST_TIMEOUT_MS) });

function runCli(args: string[]): SpawnSyncReturns<string> {
  return spawnSyncCapped(process.execPath, [CLI, ...args], { cwd: REPO_ROOT, encoding: 'utf8', timeout: FAST_TIMEOUT_MS });
}

function withProject<T>(fn: (dir: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-ci-build-pr-'));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
}

describe('dev-guardian scan --build-pr — usage', () => {
  it('without --baseline-ref or --rules-ref: exit 3, it says the tree is built as it is', () => {
    withProject((dir) => {
      const r = runCli(['scan', '--project', dir, '--build-pr']);
      expect(r.status, r.stderr).toBe(3);
      expect(r.stderr).toMatch(/--build-pr applies with --baseline-ref or --rules-ref/);
    });
  });

  it('a repository file declaring build_pr is refused, even with the flag on argv', () => {
    withProject((dir) => {
      mkdirSync(join(dir, '.guardian'), { recursive: true });
      writeFileSync(join(dir, '.guardian', 'ci.json'), `${JSON.stringify({ build_pr: true })}\n`);
      const r = runCli(['scan', '--project', dir, '--rules-ref', 'HEAD', '--build-pr']);
      expect(r.status, r.stderr).toBe(3);
      expect(r.stderr).toMatch(/\.guardian[\\/]ci\.json/);
      expect(r.stderr).toMatch(/"build_pr"/);
      expect(r.stderr).toMatch(/command line/);
    });
  });

  it('documents the flag in --help', () => {
    const r = runCli(['--help']);
    expect(r.stdout).toMatch(/--build-pr\s+With --baseline-ref or --rules-ref only/);
  });
});
