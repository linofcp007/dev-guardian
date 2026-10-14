/**
 * Review 12, findings 11 and 12: the CI gate's secrets under a ref, judged on
 * what REAL gitleaks reports, through `runScans` — `security_scan_full`
 * stubbed at the TOOLS boundary to run the real `scan_secrets` over the whole
 * project (as it does inside the real step), every other step a no-op, as in
 * `test/integration/ciRunScans.test.ts`.
 *
 *   - 11: gitleaks reads history as `-U0` hunks. A private key replaced in
 *     place, or added directly above a baselined one, left its BEGIN / END
 *     lines out of every hunk: the multi-line rule matched nothing and the
 *     gate passed (exit 0). Under a ref, `runScans` now reads every file
 *     changed since it whole (a `scan_secrets` step scoped to their paths).
 *   - 12: a file renamed with an edit on a baselined secret's line was read
 *     one column off — `git show -U0 <commit> -- <new path>` pairs no rename,
 *     so the edited line was not a hunk's first — and the secret was "new".
 *
 * The keys are generated, and the PEM markers built (no credential-shaped
 * literal in this file).
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';
import { buildBaseline, newFindings } from '../../src/ci/baseline.js';
import type { ResolvedRef } from '../../src/ci/refConfig.js';
import { renamesSince } from '../../src/ci/renames.js';
import { runScans } from '../../src/ci/runScans.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { TOOLS, type ToolModule } from '../../src/tools/index.js';
import type { Finding } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

afterAll(cleanupTempDirs);
vi.setConfig({ testTimeout: 180_000 });

const GITLEAKS = await isInstalled('gitleaks');

const dig = (seed: string): Buffer => createHash('sha256').update(`review12-${seed}`).digest();
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
/** An AWS-access-key-shaped value from a seed: `AKIA` + 16 of [A-Z2-7]. */
const aws = (seed: string): string => `${'AK'}${'IA'}${Array.from({ length: 16 }, (_, i) => B32[(dig(seed)[i] ?? 0) % 32]).join('')}`;
/** A PEM-shaped private key from a seed: its markers built, its body base64 of hashes. */
function pem(seed: string): string[] {
  const marker = (word: string): string => `${'-----'}${word} RSA PRIVATE ${'KEY-----'}`;
  const body = Buffer.concat(['a', 'b', 'c', 'd', 'e', 'f'].map((s) => dig(`${seed}${s}`))).toString('base64');
  const lines = [body.slice(0, 64), body.slice(64, 128), body.slice(128, 192), body.slice(192, 256)].filter((l) => l !== '');
  return [marker('BEGIN'), `MIIEowIBAAKCAQEA${lines[0]?.slice(16) ?? ''}`, ...lines.slice(1), marker('END')];
}
/**
 * A key whose last character occurs once in it. Cut one byte early, from
 * `"AKIA…`, it reads with the same entropy — so only where gitleaks' fragment
 * began says which cut is the key (`ci/secretValues.ts#secretFromLine`), and
 * a rename read without its pairing chose the wrong one.
 */
const K1 = Array.from({ length: 100 }, (_, i) => aws(`k${i}`)).find((k) => k.indexOf(k.slice(-1)) === k.length - 1) ?? '';
const NEW = aws('new');
const CONFIG = ['// config', `const AWS_KEY = "${K1}";`, 'module.exports = { AWS_KEY };', '// a', '// b', '// c'];

function git(dir: string, ...args: string[]): string {
  const date = '2026-01-01T00:00:00Z';
  const r = spawnSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'core.autocrlf=false', '-c', 'commit.gpgsign=false', ...args], {
    cwd: dir,
    encoding: 'utf8',
    env: { ...process.env, GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date },
  });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`);
  return r.stdout.trim();
}

function write(dir: string, path: string, lines: readonly string[]): void {
  writeFileSync(join(dir, path), `${lines.join('\n')}\n`);
}

/** A pull request's commit: a later committer date, as a pull request's is. */
function commitPr(dir: string): void {
  const date = '2026-01-03T00:00:00Z';
  for (const args of [['add', '-A'], ['commit', '-q', '-m', 'pr']]) {
    const r = spawnSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', ...args], {
      cwd: dir,
      encoding: 'utf8',
      env: { ...process.env, GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date },
    });
    if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`);
  }
}

const original = new Map<string, ToolModule['handler']>();
function stub(name: string, impl: ToolModule['handler']): void {
  const tool = TOOLS.find((t) => t.name === name);
  if (tool === undefined) throw new Error(`no tool ${name}`);
  if (!original.has(name)) original.set(name, tool.handler);
  tool.handler = impl;
}
afterEach(() => {
  for (const [name, handler] of original) {
    const tool = TOOLS.find((t) => t.name === name);
    if (tool !== undefined) tool.handler = handler;
  }
  original.clear();
});

/** `runScans` with only the secrets scan real; `changedSince` as the CLI passes it under `--baseline-ref`. */
async function gate(dir: string, changedSince?: ResolvedRef): Promise<Awaited<ReturnType<typeof runScans>>> {
  const secrets = TOOLS.find((t) => t.name === 'scan_secrets')?.handler;
  if (secrets === undefined) throw new Error('scan_secrets is not registered');
  for (const name of ['detect_stack', 'license_compatibility', 'map_attack_surface', 'validate_finding']) stub(name, async () => ({ ok: true }));
  stub('security_scan_full', async (_input, ctx) => secrets({ project_path: dir, force: true }, ctx));
  return runScans({ projectPath: dir, ...(changedSince !== undefined ? { changedSince } : {}) });
}

/**
 * The base (committed, baselined as `baseline update` does: no ref), then the
 * pull request `change`, judged under `--baseline-ref` at the base.
 */
async function judge(
  base: Record<string, string[]>,
  change: (dir: string) => void,
  /** Files the base commits next, from the first base commit's sha (a `.gitleaksignore` naming it). */
  then?: (first: string) => Record<string, string[]>,
): Promise<{ fresh: Finding[]; failed: string[] }> {
  const dir = resolveProjectPath(makeTempDir('secret-full-content-')).path;
  mkdirSync(dir, { recursive: true });
  git(dir, 'init', '-q');
  for (const [path, lines] of Object.entries(base)) write(dir, path, lines);
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '-m', 'base');
  if (then !== undefined) {
    for (const [path, lines] of Object.entries(then(git(dir, 'rev-parse', 'HEAD')))) write(dir, path, lines);
    git(dir, 'add', '-A');
    git(dir, 'commit', '-q', '-m', 'base, then');
  }
  const commit = git(dir, 'rev-parse', 'HEAD');
  const baseline = buildBaseline((await gate(dir)).findings, null, '2026-01-02');
  expect(baseline.entries.length, 'the base has its secret baselined').toBeGreaterThan(0);
  change(dir);
  commitPr(dir);
  const result = await gate(dir, { ref: 'BASE', commit, prefix: '' });
  const failed = result.steps.filter((s) => !s.ran || s.tools_run.some((t) => t.status === 'failed')).map((s) => `${s.tool}: ${s.reason ?? JSON.stringify(s.tools_run)}`);
  return { fresh: newFindings(result.findings, baseline, await renamesSince(dir, commit)), failed };
}

const where = (fresh: readonly Finding[]): unknown[] => fresh.map((f) => [f.rule_id, f.file_path, f.line_start, f.snippet]);

describe.skipIf(!GITLEAKS)('under a ref, the files a pull request changed are read whole for secrets (review 12, finding 11)', () => {
  const BASE = { 'key.pem': pem('p1'), 'a.js': ['console.log(1)'] };

  it('a private key replaced in place is new — its BEGIN / END lines are in no -U0 hunk', async () => {
    const { fresh, failed } = await judge(BASE, (dir) => write(dir, 'key.pem', pem('p2')));
    expect(failed).toEqual([]);
    expect(where(fresh)).toEqual([['private-key', 'key.pem', 1, expect.not.stringContaining(';commit=')]]);
  });

  it('a private key added directly above the baselined one is new — the baselined one is not', async () => {
    const { fresh } = await judge(BASE, (dir) => write(dir, 'key.pem', [...pem('p2'), ...pem('p1')]));
    expect(where(fresh)).toEqual([['private-key', 'key.pem', 1, expect.any(String)]]);
  });

  it('a comment after the baselined key, or an unrelated file: nothing is new, no step failed', async () => {
    for (const change of [(dir: string) => write(dir, 'key.pem', [...pem('p1'), '# rotated? no']), (dir: string) => write(dir, 'README.md', ['x'])]) {
      const { fresh, failed } = await judge(BASE, change);
      expect(where(fresh)).toEqual([]);
      expect(failed).toEqual([]);
    }
  });

  it('a pure rename (no line added): nothing is new, and no step failed on a history with nothing to read', async () => {
    const { fresh, failed } = await judge({ 'config.js': CONFIG }, (dir) => git(dir, 'mv', 'config.js', 'settings.js'));
    expect(where(fresh)).toEqual([]);
    expect(failed).toEqual([]);
  });

  // The full suite's ciRefGateExclusions control: the files pass reads only
  // `.gitleaksignore`'s file form, so a key accepted by its history
  // fingerprint came back as new whenever its file changed.
  it('a fixture key .gitleaksignore accepts by its commit: an edit beside it is not new, the key replaced in place is', async () => {
    const BASE_IGNORED = { 'fixture.pem': pem('f1'), 'config.js': CONFIG };
    const ignore = (first: string): Record<string, string[]> => ({ '.gitleaksignore': [`${first}:fixture.pem:private-key:1`] });
    const beside = await judge(BASE_IGNORED, (dir) => write(dir, 'fixture.pem', ['# test fixture, not a real key', ...pem('f1')]), ignore);
    expect(where(beside.fresh)).toEqual([]);
    const replaced = await judge(BASE_IGNORED, (dir) => write(dir, 'fixture.pem', pem('f2')), ignore);
    expect(where(replaced.fresh)).toEqual([['private-key', 'fixture.pem', 1, expect.not.stringContaining(';commit=')]]);
  });
});

describe.skipIf(!GITLEAKS)('a renamed file with an edit is read where gitleaks read it (review 12, finding 12)', () => {
  it('a comment appended to the baselined key\'s line in a renamed file: nothing is new', async () => {
    const { fresh } = await judge({ 'config.js': CONFIG }, (dir) => {
      git(dir, 'mv', 'config.js', 'settings.js');
      write(dir, 'settings.js', CONFIG.map((l, i) => (i === 1 ? `${l} // c` : l)));
    });
    expect(where(fresh)).toEqual([]);
  });

  it('the baselined key replaced in a renamed file: the new key is new', async () => {
    const { fresh } = await judge({ 'config.js': CONFIG }, (dir) => {
      git(dir, 'mv', 'config.js', 'settings.js');
      write(dir, 'settings.js', CONFIG.map((l) => l.replace(K1, NEW)));
    });
    expect(fresh.map((f) => [f.rule_id, f.file_path, f.line_start])).toContainEqual(['aws-access-token', 'settings.js', 2]);
  });
});
