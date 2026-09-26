/**
 * `dev-guardian scan --accept-partial-parse <path>` end to end, as a REAL
 * SUBPROCESS over a real git repository scanned by real Semgrep, gitleaks
 * and Trivy (follow-up X1).
 *
 * The fixture is the WordPress controller the surface fixtures carry
 * (`apps/php-wordpress/rest-controller.php`): its `const NAMESPACE` is legal
 * PHP 7+ that Semgrep 1.176.1 can only partly parse — a warn-level
 * `PartialParsing`, measured. Before the shared judge's `partial` verdict,
 * that one warning made `scan_sast` a failed scanner and the gate exit 2 on
 * every WordPress project, with no way to say "we know, accept it".
 *
 * `--local-only` with the project's own `.semgrep.yml` (a copy of
 * `configs/semgrep/base.yml`, whose PHP rules parse the file): no registry
 * download, no telemetry, the same rules on every run.
 *
 * The matrix: not accepted → 2; accepted → 0 and printed "accepted", coverage
 * still `partial` (human, JSON, SARIF); an accepted path that is not the one
 * partly parsed → 2. The usage rules (argv only, relative, exact) need no
 * scanner and run first.
 */

import { execa } from 'execa';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { type SpawnSyncReturns, spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { isInstalled } from '../helpers/toolchain.js';

const here = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(here, '..', '..', '..');
const CLI = resolve(REPO_ROOT, 'cli', 'dev-guardian.mjs');
const WORDPRESS = resolve(REPO_ROOT, 'mcp', 'test', 'fixtures', 'surface', 'apps', 'php-wordpress', 'rest-controller.php');
const BASE_PACK = resolve(REPO_ROOT, 'configs', 'semgrep', 'base.yml');

/** A usage error never reaches a scanner; this is a hang-breaker only (see ciCliFixture.test.ts). */
const FAST_TIMEOUT_MS = 45_000;
/** Real pipeline runs; a hang-breaker only (see ciCliFixture.test.ts for why it is this large). */
const SCAN_TIMEOUT_MS = 600_000;

const TOOLCHAIN_AVAILABLE =
  (await isInstalled('semgrep')) && (await isInstalled('gitleaks')) && (await isInstalled('trivy'));
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

function runCli(args: string[], timeout = FAST_TIMEOUT_MS): SpawnSyncReturns<string> {
  return spawnSync(process.execPath, [CLI, ...args], { cwd: REPO_ROOT, encoding: 'utf8', timeout });
}

function rmDir(dir: string): void {
  try {
    rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  } catch {
    /* best-effort; a locked file must not mask the assertion */
  }
}

describe('dev-guardian scan --accept-partial-parse — usage (no real scanner reached)', () => {
  let dir: string;
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'guardian-ci-accept-usage-'));
  });
  afterAll(() => rmDir(dir));

  it.each([
    [['--accept-partial-parse'], /--accept-partial-parse requires a value/],
    [['--accept-partial-parse', ''], /--accept-partial-parse requires a value/],
    [['--accept-partial-parse='], /--accept-partial-parse requires a value/],
    [['--accept-partial-parse', '/etc/passwd'], /relative to --project/],
    [['--accept-partial-parse', 'C:\\x\\a.php'], /relative to --project/],
    [['--accept-partial-parse=../outside.php'], /'\.\.' cannot name a scanned file/],
    [['--accept-partial-parse', 'wp\\..\\..\\x.php'], /'\.\.' cannot name a scanned file/],
  ])('exits 3 on %j, naming the problem', (args, message) => {
    const r = runCli(['scan', '--project', dir, ...args]);
    expect(r.status, r.stderr).toBe(3);
    expect(r.stderr).toMatch(message);
    expect(existsSync(join(dir, '.guardian', 'reports'))).toBe(false);
  });

  it('refuses a repository file that declares accept_partial_parse — argv only, like --start-command', () => {
    const repo = mkdtempSync(join(tmpdir(), 'guardian-ci-accept-config-'));
    try {
      mkdirSync(join(repo, '.guardian'), { recursive: true });
      writeFileSync(join(repo, '.guardian', 'ci.json'), `${JSON.stringify({ accept_partial_parse: ['a.php'] })}\n`);
      // Even with the flag on argv: the file itself is the problem.
      const r = runCli(['scan', '--project', repo, '--accept-partial-parse', 'a.php']);
      expect(r.status, r.stderr).toBe(3);
      expect(r.stderr).toMatch(/\.guardian[\\/]ci\.json/);
      expect(r.stderr).toMatch(/accept_partial_parse/);
      expect(r.stderr).toMatch(/command line/);
      expect(existsSync(join(repo, '.guardian', 'reports'))).toBe(false);
    } finally {
      rmDir(repo);
    }
  });

  it('documents the flag in --help', () => {
    const r = runCli(['--help']);
    expect(r.stdout).toMatch(/--accept-partial-parse <path>/);
    expect(r.stdout).toMatch(/Matched\s+exactly/);
  });
});

describe('dev-guardian scan --accept-partial-parse — the gate matrix, real Semgrep over const NAMESPACE', () => {
  let project: string;
  let sarif: string;
  let notAccepted: SpawnSyncReturns<string>;
  let accepted: SpawnSyncReturns<string>;
  let acceptedJson: SpawnSyncReturns<string>;
  let otherPath: SpawnSyncReturns<string>;

  beforeAll(async () => {
    if (!TOOLCHAIN_AVAILABLE) return;
    project = mkdtempSync(join(tmpdir(), 'guardian-ci-accept-wp-'));
    mkdirSync(join(project, 'wp'));
    copyFileSync(WORDPRESS, join(project, 'wp', 'rest-controller.php'));
    copyFileSync(BASE_PACK, join(project, '.semgrep.yml'));
    await execa('git', ['init'], { cwd: project });
    await execa('git', ['config', 'user.email', 'guardian-ci-accept@example.com'], { cwd: project });
    await execa('git', ['config', 'user.name', 'Guardian CI Accept'], { cwd: project });
    await execa('git', ['add', '-A'], { cwd: project });
    await execa('git', ['commit', '-m', 'initial'], { cwd: project });
    sarif = join(project, 'out', 'results.sarif');
    const scan = (...extra: string[]) =>
      runCli(['scan', '--project', project, '--local-only', ...extra], SCAN_TIMEOUT_MS);
    notAccepted = scan();
    accepted = scan('--accept-partial-parse', 'wp/rest-controller.php', '--sarif', sarif);
    acceptedJson = scan('--accept-partial-parse', 'wp\\rest-controller.php', '--format', 'json');
    otherPath = scan('--accept-partial-parse', 'wp/other.php');
  }, 4 * SCAN_TIMEOUT_MS);

  afterAll(() => {
    if (project) rmDir(project);
  });

  const describeRun = (r: SpawnSyncReturns<string>): string =>
    `exit ${String(r.status)}\nstdout:\n${r.stdout}\nstderr:\n${r.stderr}`;

  it.skipIf(!TOOLCHAIN_AVAILABLE)('not accepted: exit 2, the gap names the file and the flag', () => {
    expect(notAccepted.status, describeRun(notAccepted)).toBe(2);
    expect(notAccepted.stdout).toMatch(/^coverage: partial$/m);
    expect(notAccepted.stdout).toMatch(
      /security_scan_full: semgrep ran with reduced coverage .*PartialParsing: wp\/rest-controller\.php.* not accepted: wp\/rest-controller\.php/,
    );
    expect(notAccepted.stdout).toMatch(/map_attack_surface: semgrep ran with reduced coverage .*not accepted: wp\/rest-controller\.php/);
  });

  it.skipIf(!TOOLCHAIN_AVAILABLE)('accepted: exit 0, printed as "accepted", coverage still partial in the report and the SARIF', () => {
    expect(accepted.status, describeRun(accepted)).toBe(0);
    expect(accepted.stdout).toMatch(/^dev-guardian CI: PASS \(exit code 0\)$/m);
    expect(accepted.stdout).toMatch(/^coverage: partial$/m);
    expect(accepted.stdout).not.toMatch(/coverage gaps/);
    expect(accepted.stdout).toMatch(/security_scan_full: semgrep only partly parsed wp\/rest-controller\.php — accepted/);
    expect(accepted.stdout).toMatch(/map_attack_surface: semgrep only partly parsed wp\/rest-controller\.php — accepted/);
    expect(accepted.stderr).toBe('');
    const doc = JSON.parse(readFileSync(sarif, 'utf8')) as { runs: Array<{ invocations: Array<{ executionSuccessful: boolean }> }> };
    expect(doc.runs[0]?.invocations[0]?.executionSuccessful).toBe(false);
  });

  it.skipIf(!TOOLCHAIN_AVAILABLE)('accepted, as JSON, with a Windows separator: exit 0, coverage partial, accepted_gaps', () => {
    expect(acceptedJson.status, describeRun(acceptedJson)).toBe(0);
    const o = JSON.parse(acceptedJson.stdout) as { exit_code: number; coverage: string; coverage_gaps: string[]; accepted_gaps: string[] };
    expect(o.exit_code).toBe(0);
    expect(o.coverage).toBe('partial');
    expect(o.coverage_gaps).toEqual([]);
    expect(o.accepted_gaps).toHaveLength(2);
  });

  it.skipIf(!TOOLCHAIN_AVAILABLE)('an accepted path that is not the one partly parsed: exit 2, and the acceptance is named unused', () => {
    expect(otherPath.status, describeRun(otherPath)).toBe(2);
    expect(otherPath.stdout).toMatch(/not accepted: wp\/rest-controller\.php/);
    expect(otherPath.stdout).toMatch(/--accept-partial-parse wp\/other\.php: no step reported it partly parsed/);
  });

  it.runIf(REQUIRE_SEMGREP)('GUARDIAN_REQUIRE_SEMGREP=1 — the matrix must have run', () => {
    expect(TOOLCHAIN_AVAILABLE, 'GUARDIAN_REQUIRE_SEMGREP=1 but semgrep/gitleaks/trivy are not all on PATH.').toBe(true);
  });
});
