/**
 * Review 11, finding 2: a baselined secret's identity, judged on what REAL
 * gitleaks reports for real commits — its columns, its redacted match, its
 * entropy (`ci/secretValues.ts`) — and the gate's one-to-one matching
 * (`ci/baseline.ts`).
 *
 * 3.4.0 numbered a file's secrets by line and let a `match_id` match take no
 * entry, and its value was the whole line:
 *
 *   - a new key added on line 1, above the baselined one, took the baselined
 *     one's occurrence and passed (exit 0) — so did removing the baselined
 *     key and putting a new one a line up;
 *   - a comment appended to the baselined key's line, or the same key moved
 *     to another line, was new (exit 1).
 *
 * Each case is a commit on top of the base (with a later committer date, as
 * a pull request's is), scanned like the CI history pass: `gitleaks detect
 * --redact` over the repository. A baseline written before 3.4.1 (keys
 * computed without values) still matches the unchanged secrets.
 *
 * The keys are generated (no credential-shaped literal in this file).
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { buildBaseline, newFindings } from '../../src/ci/baseline.js';
import { rememberSecretValues } from '../../src/ci/secretValues.js';
import { assignIdentities } from '../../src/fingerprint/findingIdentity.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { gitleaksParser } from '../../src/runners/scannerParsers/gitleaks.js';
import type { Finding } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

afterAll(cleanupTempDirs);
vi.setConfig({ testTimeout: 120_000 });

const GITLEAKS = await isInstalled('gitleaks');
if (!GITLEAKS && process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1') throw new Error('gitleaks is not on PATH');

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
/** An AWS-access-key-shaped value from a seed: `AKIA` + 16 of [A-Z2-7]. */
function key(seed: string): string {
  const digest = createHash('sha256').update(`review11-${seed}`).digest();
  return `${'AK'}${'IA'}${Array.from({ length: 16 }, (_, i) => B32[(digest[i] ?? 0) % 32]).join('')}`;
}
const K1 = key('k1');
const K2 = key('k2');
const K3 = key('k3');
const NEW = key('new');

const BASE_LINES = ['// config', `const AWS_KEY = "${K1}";`, `const B = "${K3}"; const C = "${K2}";`, 'module.exports = { AWS_KEY };'];

function git(dir: string, env: Record<string, string>, ...args: string[]): string {
  const r = spawnSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'core.autocrlf=false', '-c', 'commit.gpgsign=false', ...args], {
    cwd: dir,
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`);
  return r.stdout.trim();
}

function commit(dir: string, lines: readonly string[], message: string, date: string): void {
  writeFileSync(join(dir, 'config.js'), `${lines.join('\n')}\n`);
  git(dir, { GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date }, 'add', '-A');
  git(dir, { GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date }, 'commit', '-q', '-m', message);
}

/** The history pass as the CI gate's scan runs it, its findings keyed and their values read. */
async function scan(dir: string): Promise<Finding[]> {
  const reports = makeTempDir('secret-identity-reports-');
  const report = join(reports, 'secrets-history.json');
  const r = spawnSync('gitleaks', ['detect', '--no-banner', '--redact', '--report-format=json', `--report-path=${report}`, '-s', dir], {
    encoding: 'utf8',
  });
  if (r.status !== 0 && r.status !== 1) throw new Error(`gitleaks exited ${String(r.status)}: ${r.stderr}`);
  const findings = assignIdentities(gitleaksParser.parse(readFileSync(report, 'utf8'), { project_path: dir }).findings, { projectPath: dir });
  await rememberSecretValues(dir, findings, { reportDirs: [reports] });
  return findings;
}

function project(): string {
  const dir = resolveProjectPath(makeTempDir('secret-identity-')).path;
  mkdirSync(dir, { recursive: true });
  git(dir, {}, 'init', '-q');
  commit(dir, BASE_LINES, 'base', '2026-01-01T00:00:00Z');
  return dir;
}

/** What the pull request does to the base's lines (one commit, a later date). */
const SCENARIOS: Record<string, (lines: readonly string[]) => string[]> = {
  control: (l) => [...l, '// unrelated'],
  'insert-new-at-top': (l) => [`const NEW_KEY = "${NEW}";`, ...l],
  'replace-one-line-up': (l) => [`const AWS_KEY = "${NEW}";`, l[0] ?? '', ...l.slice(2)],
  'insert-above': (l) => [l[0] ?? '', `const NEW_KEY = "${NEW}";`, ...l.slice(1)],
  'replace-in-place': (l) => l.map((line, i) => (i === 1 ? line.replace(K1, NEW) : line)),
  'comment-appended': (l) => l.map((line, i) => (i === 1 ? `${line} // rotated? no` : line)),
  'move-same-value': (l) => [l[0] ?? '', l[2] ?? '', l[3] ?? '', `const AWS_KEY = "${K1}";`],
  whitespace: (l) => l.map((line, i) => (i === 1 ? `   ${line.replace(' = ', '=')}` : line)),
  'swap-two': (l) => l.map((line, i) => (i === 2 ? `const B = "${K2}"; const C = "${K3}";` : line)),
};

/** The scenarios whose pull request adds a secret: the gate must call it new. */
const ADDS_A_SECRET = new Set(['insert-new-at-top', 'replace-one-line-up', 'insert-above', 'replace-in-place']);

describe.skipIf(!GITLEAKS)('a baselined secret, judged on real gitleaks output (review 11, finding 2)', () => {
  for (const [name, change] of Object.entries(SCENARIOS)) {
    it(`${name}: ${ADDS_A_SECRET.has(name) ? 'the new secret is new' : 'nothing is new'}`, async () => {
      const dir = project();
      const baseline = buildBaseline(await scan(dir), null, '2026-01-02');
      commit(dir, change(BASE_LINES), `pr: ${name}`, '2026-01-03T00:00:00Z');
      const fresh = newFindings(await scan(dir), baseline);
      if (ADDS_A_SECRET.has(name)) {
        expect(fresh.length, JSON.stringify(fresh.map((f) => [f.file_path, f.line_start]))).toBeGreaterThan(0);
        // Every finding called new is one the pull request's commit introduced.
        for (const f of fresh) expect(f.snippet).not.toContain(git(dir, {}, 'rev-parse', 'HEAD~1'));
      } else {
        expect(fresh.map((f) => [f.file_path, f.line_start, f.snippet])).toEqual([]);
      }
    });
  }

  it('one commit second for the base and the pull request: one-to-one matching alone keeps the new key new', async () => {
    const dir = resolveProjectPath(makeTempDir('secret-identity-same-second-')).path;
    git(dir, {}, 'init', '-q');
    commit(dir, BASE_LINES, 'base', '2026-01-01T00:00:00Z');
    const baseline = buildBaseline(await scan(dir), null, '2026-01-02');
    commit(dir, SCENARIOS['insert-new-at-top']?.(BASE_LINES) ?? [], 'pr', '2026-01-01T00:00:00Z');
    expect(newFindings(await scan(dir), baseline).length).toBeGreaterThan(0);
  });

  it('a baseline written before 3.4.1 (no values) still matches the unchanged secrets', async () => {
    const dir = project();
    const reports = makeTempDir('secret-identity-old-');
    const report = join(reports, 'secrets-history.json');
    spawnSync('gitleaks', ['detect', '--no-banner', '--redact', '--report-format=json', `--report-path=${report}`, '-s', dir], { encoding: 'utf8' });
    const old = buildBaseline(
      assignIdentities(gitleaksParser.parse(readFileSync(report, 'utf8'), { project_path: dir }).findings, { projectPath: dir }),
      null,
      '2026-01-02',
    );
    commit(dir, SCENARIOS['control']?.(BASE_LINES) ?? [], 'unrelated', '2026-01-03T00:00:00Z');
    expect(newFindings(await scan(dir), old)).toEqual([]);
  });
});
