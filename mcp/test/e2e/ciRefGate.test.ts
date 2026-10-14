/**
 * `dev-guardian scan --baseline-ref / --rules-ref`, as a REAL SUBPROCESS
 * against real repositories and the real scanners: a pull request cannot
 * gate itself.
 *
 *   - It adds its own new finding to `.guardian/baseline.json` → with
 *     `--baseline-ref <base>` the gate reads the base commit's baseline and
 *     still fails.
 *   - It deletes the rule that catches its new code from `.semgrep.yml`, and
 *     hides another file in a new `.guardianignore` → with `--rules-ref
 *     <base>` the base's rules and ignore file apply, and the gate fails on
 *     both; the base's own finding still matches the base's baseline (the
 *     rule id read from the copy is the one a tree scan stores).
 *
 * Each attack is also run WITHOUT the flag, as the control that proves it
 * works: a gate that failed either way would prove nothing about the flag.
 * The rules attack is `ciRefGateRules.test.ts` and the exclusions one
 * (`--reset-exclusions-from`) `ciRefGateExclusions.test.ts`: one file each, so
 * their real scans run side by side (review 8, finding 6 — together they were
 * the suite's longest file, 244 s); the shared setup is `helpers/ciRefGate.ts`.
 *
 * Semgrep is required (the rules are Semgrep's); `--local-only` keeps it to
 * the project's rules. gitleaks or Trivy missing makes the passing controls
 * exit 2 rather than 0 — the assertions read the blocking findings, and the
 * failing runs' exit 1 outranks an incomplete scan.
 */

import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { CLEAN_JS, EVAL_JS, FAST_TIMEOUT_MS, RULES, RUN_REAL, SCAN_TIMEOUT_MS, blockingFiles, commitAll, newRepo, runCli, scanJson, write } from '../helpers/ciRefGate.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

vi.setConfig({ testTimeout: 3 * SCAN_TIMEOUT_MS, hookTimeout: 3 * SCAN_TIMEOUT_MS });

afterAll(cleanupTempDirs);

describe('scan --baseline-ref / --rules-ref — usage (no scanner reached)', () => {
  it.each([
    [['--baseline-ref'], /--baseline-ref requires a value/],
    [['--baseline-ref='], /--baseline-ref requires a value/],
    [['--rules-ref', ''], /--rules-ref requires a value/],
  ])('an empty or missing ref (an unset CI variable) is exit 3, never the tree\'s own copy: %j', (args, message) => {
    const r = runCli(['scan', ...args], FAST_TIMEOUT_MS);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(message);
  });

  it('a ref that names no commit is exit 3, naming it — before any scan', async () => {
    const repo = await newRepo('ciref-noref-');
    write(repo, 'index.js', CLEAN_JS);
    await commitAll(repo, 'base');
    const r = runCli(['scan', '--project', repo, '--baseline-ref', 'origin/never-fetched'], FAST_TIMEOUT_MS);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/--baseline-ref origin\/never-fetched: names no commit in this repository/);
    expect(r.stdout).toBe('');
  });

  // Review M-1: help used to be looked for in every argument, so a flag whose
  // VALUE read like help printed the usage and exited 0 — no scan, a pass.
  // The ref case runs on the default project, this checkout — which is no git
  // work tree when it is a `git archive` (the POSIX container run): either
  // refusal names `help` as the ref, which is what is under test.
  it.each([
    [['--baseline-ref', '--help'], /--baseline-ref takes a git ref, not an option/],
    [['--baseline-ref', 'help'], /--baseline-ref help: (names no commit|.* is not inside a git work tree)/],
    [['--fail-on', '-h'], /--fail-on must be one of/],
    [['--project', '--help'], /--project does not exist or is not a directory/],
  ])('a flag whose value reads like help is that flag\'s value, never a help request: %j → exit 3', (args, message) => {
    const r = runCli(['scan', ...args], FAST_TIMEOUT_MS);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(message);
    expect(r.stdout).not.toMatch(/--fail-on <severity>/);
  });

  it('help is still help anywhere a flag value is not expected', () => {
    const r = runCli(['scan', '--local-only', '--help'], FAST_TIMEOUT_MS);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/--baseline-ref <ref>/);
    // What --rules-ref reads from the ref names .guardian/scan.yml too (it does since 3.3.0).
    const rulesRef = r.stdout.slice(r.stdout.indexOf('--rules-ref <ref>'), r.stdout.indexOf('--reset-exclusions-from'));
    expect(rulesRef.replace(/\s+/g, ' ')).toMatch(/\.trivyignore, \.bandit and \.guardian\/scan\.yml from <ref>/);
  });

  it('a project outside git cannot take a ref: exit 3', () => {
    const plain = makeTempDir('ciref-plain-');
    const r = runCli(['scan', '--project', plain, '--rules-ref', 'HEAD'], FAST_TIMEOUT_MS);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/--rules-ref HEAD: .* is not inside a git work tree/);
  });
});

describe.skipIf(!RUN_REAL)('a pull request that adds its own finding to the baseline (real scanners)', () => {
  let repo = '';
  let base = '';

  beforeAll(async () => {
    repo = await newRepo('ciref-baseline-');
    write(repo, '.semgrep.yml', RULES);
    write(repo, 'index.js', CLEAN_JS);
    write(repo, '.guardian/baseline.json', `${JSON.stringify({ version: 1, generated_at: '2026-09-29T00:00:00.000Z', entries: [] }, null, 2)}\n`);
    base = await commitAll(repo, 'base: clean, empty baseline');
    // The pull request: new eval, and the baseline regenerated to adopt it.
    write(repo, 'lib/new.js', EVAL_JS);
    const update = runCli(['baseline', 'update', '--project', repo, '--local-only']);
    expect(update.status === 0 || update.status === 2, `${update.stdout}\n${update.stderr}`).toBe(true);
    await commitAll(repo, 'pr: adds eval and adopts it');
  });

  it("control — gated on the tree's own baseline, the pull request passes its own finding", () => {
    const { status, report } = scanJson(repo);
    expect(report.blocking_findings).toEqual([]);
    expect(status).not.toBe(1);
    expect(report.baseline_source).toEqual({ from: 'tree', path: '.guardian/baseline.json' });
  });

  it("--baseline-ref <base>: the base's baseline is read, the finding is new, the gate fails", () => {
    const { status, report } = scanJson(repo, '--baseline-ref', base);
    expect(status).toBe(1);
    expect(blockingFiles(report)).toEqual(['lib/new.js']);
    expect(report.baseline_absent).toBe(false);
    expect(report.baseline_source).toEqual({
      from: 'ref',
      path: '.guardian/baseline.json',
      ref: base,
      commit: base,
      present: true,
      tree_differs: true,
    });
  });
});
