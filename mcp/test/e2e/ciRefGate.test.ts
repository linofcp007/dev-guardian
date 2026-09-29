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
 *
 * Semgrep is required (the rules are Semgrep's); `--local-only` keeps it to
 * the project's rules. gitleaks or Trivy missing makes the passing controls
 * exit 2 rather than 0 — the assertions read the blocking findings, and the
 * failing runs' exit 1 outranks an incomplete scan.
 */

import { execa } from 'execa';
import { spawnSync, type SpawnSyncReturns } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

const here = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(here, '..', '..', '..');
const CLI = resolve(REPO_ROOT, 'cli', 'dev-guardian.mjs');

/** A hang-breaker for one real pipeline run on a loaded machine — see ciCliFixture.test.ts. */
const SCAN_TIMEOUT_MS = 600_000;
const FAST_TIMEOUT_MS = 45_000;
vi.setConfig({ testTimeout: 3 * SCAN_TIMEOUT_MS, hookTimeout: 3 * SCAN_TIMEOUT_MS });

afterAll(cleanupTempDirs);

const SEMGREP_INSTALLED = await isInstalled('semgrep');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';
const RUN_REAL = SEMGREP_INSTALLED || REQUIRE_SEMGREP;

const RULES = `rules:
  - id: guardian-test-no-eval
    languages: [javascript]
    severity: ERROR
    message: eval of input
    pattern: eval($X)
`;
const WEAKENED = `rules:
  - id: guardian-test-no-eval
    languages: [javascript]
    severity: ERROR
    message: eval of input
    pattern: guardian_nothing_matches_this($X)
`;
const CLEAN_JS = "'use strict';\nmodule.exports = (a, b) => a + b;\n";
const EVAL_JS = "'use strict';\nmodule.exports = (input) => eval(input);\n";

/** The environment of a run: this process's, with every CI marker removed (a developer's shell), plus `extra`. */
function envWith(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const key of ['CI', 'GITHUB_ACTIONS', 'GITLAB_CI', 'BITBUCKET_BUILD_NUMBER']) delete env[key];
  return { ...env, ...extra };
}
const IN_CI = envWith({ CI: 'true' });

function runCli(args: string[], timeout = SCAN_TIMEOUT_MS, env: NodeJS.ProcessEnv = envWith()): SpawnSyncReturns<string> {
  return spawnSync(process.execPath, [CLI, ...args], { cwd: REPO_ROOT, encoding: 'utf8', timeout, env });
}

async function git(cwd: string, ...args: string[]): Promise<string> {
  return (await execa('git', args, { cwd })).stdout;
}

function write(root: string, rel: string, text: string): void {
  const path = join(root, ...rel.split('/'));
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text);
}

async function newRepo(prefix: string): Promise<string> {
  const dir = makeTempDir(prefix);
  await git(dir, 'init', '-q');
  await git(dir, 'config', 'user.email', 'guardian-ci-ref@example.com');
  await git(dir, 'config', 'user.name', 'Guardian CI Ref');
  await git(dir, 'config', 'commit.gpgsign', 'false');
  await git(dir, 'config', 'core.autocrlf', 'false');
  write(dir, 'package.json', '{"name":"guardian-ci-ref","version":"1.0.0","private":true}\n');
  write(dir, '.gitignore', '**/.guardian/*\n!**/.guardian/baseline.json\n');
  return dir;
}

async function commitAll(dir: string, message: string): Promise<string> {
  await git(dir, 'add', '-A');
  await git(dir, 'commit', '-q', '-m', message);
  return (await git(dir, 'rev-parse', 'HEAD')).trim();
}

interface JsonReport {
  exit_code: number;
  blocking_findings: Array<{ title: string; file_path?: string; rule_id?: string }>;
  new_findings: unknown[];
  baseline_absent: boolean;
  baseline_source: Record<string, unknown>;
  rules_source: Record<string, unknown> & { tree_differences?: Array<Record<string, unknown>> };
}

function scanJson(project: string, ...extra: string[]): { status: number | null; report: JsonReport; stderr: string } {
  // In CI: --reset-exclusions-from runs only there, and the other flags do not care.
  const r = runCli(['scan', '--project', project, '--local-only', '--format', 'json', ...extra], SCAN_TIMEOUT_MS, IN_CI);
  let report: JsonReport;
  try {
    report = JSON.parse(r.stdout) as JsonReport;
  } catch {
    throw new Error(`no JSON report (exit ${String(r.status)}):\n${r.stdout}\n${r.stderr}`);
  }
  return { status: r.status, report, stderr: r.stderr };
}

const blockingFiles = (report: JsonReport): string[] =>
  report.blocking_findings.map((f) => (f.file_path ?? '').replace(/\\/g, '/')).sort();

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
  it.each([
    [['--baseline-ref', '--help'], /--baseline-ref takes a git ref, not an option/],
    [['--baseline-ref', 'help'], /--baseline-ref help: names no commit/],
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

const GITLEAKS_INSTALLED = await isInstalled('gitleaks');

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
