/**
 * The secrets history pass and the working tree's `.gitattributes`, on the
 * git of the machine — judged on what REAL gitleaks and git report, through
 * `runScans` as the CLI gate runs it on a push (as in
 * `secretHistoryView.test.ts`).
 *
 * git applies the `.gitattributes` of the WORKING TREE to every commit's
 * diff, so a file the tree marks `binary` or `-diff` is in no hunk of
 * `git log -p`, and a key in it is read by no pass. From git 2.40 the pass
 * sets them aside with `GIT_ATTR_SOURCE`; an older git has no such variable,
 * and until this spec the pass only said so — the run ended `ok` with the
 * key unread (measured, git 2.39.5 and gitleaks 8.30.1, the test:docker
 * images: `.specs/secrets-history-old-git/measurements/`).
 *
 * Every test here states what is true on ANY git. On a git 2.40 or later
 * most already hold; the images of `npm run test:docker -- --toolchain` have
 * git 2.39.5, and that run — required before a release — is where the older
 * path is exercised for real.
 *
 * The keys are generated (no credential-shaped literal in this file).
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';
import { runScans } from '../../src/ci/runScans.js';
import { secretValueOf } from '../../src/ci/secretValues.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { TEXT_LIMIT_BYTES } from '../../src/runners/historyView.js';
import { TOOLS, type ToolModule } from '../../src/tools/index.js';
import type { Finding, ToolRun } from '../../src/types.js';
import { gitAtLeast } from '../helpers/gitVersion.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

afterAll(cleanupTempDirs);
vi.setConfig({ testTimeout: 180_000 });

const GITLEAKS = await isInstalled('gitleaks');
/** `--diff-merges=remerge`: without it no git shows a merge's own change, and the pass names that. */
const GIT_SHOWS_MERGES = gitAtLeast(2, 36);
/** What the pass said of itself on a git older than 2.40, before it could read past the tree's attributes. */
const TREE_ATTRIBUTES_LIMIT = /the working tree's \.gitattributes applied to every commit's change/;

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
/** An AWS-access-key-shaped value from a seed: `AKIA` + 16 of [A-Z2-7]. */
const aws = (seed: string): string => {
  const d = createHash('sha256').update(`history-old-git-${seed}`).digest();
  return `${'AK'}${'IA'}${Array.from({ length: 16 }, (_, i) => B32[(d[i] ?? 0) % 32]).join('')}`;
};
const keyLine = (seed: string): string => `const AWS_KEY = "${aws(seed)}";\n`;

function git(dir: string, ...args: string[]): string {
  const date = '2026-01-01T00:00:00Z';
  const r = spawnSync(
    'git',
    ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'core.autocrlf=false', '-c', 'commit.gpgsign=false', '-c', 'protocol.file.allow=always', ...args],
    { cwd: dir, encoding: 'utf8', env: { ...process.env, GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date } },
  );
  if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`);
  return r.stdout.trim();
}

function write(dir: string, path: string, text: string): void {
  writeFileSync(join(dir, path), text);
}

function commit(dir: string, message: string): string {
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '-m', message);
  return git(dir, 'rev-parse', 'HEAD');
}

/** A repository with one commit, on `main`. */
function repo(prefix = 'secret-history-old-git-'): string {
  const dir = resolveProjectPath(makeTempDir(prefix)).path;
  git(dir, 'init', '-q', '-b', 'main');
  write(dir, 'a.js', 'console.log(1)\n');
  commit(dir, 'base');
  return dir;
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

/** The gate on a push: `runScans` with only the secrets scan real, and no ref. */
async function push(dir: string): Promise<{ findings: Finding[]; reason: string; failed: string[]; pass: ToolRun | undefined }> {
  const secrets = TOOLS.find((t) => t.name === 'scan_secrets')?.handler;
  if (secrets === undefined) throw new Error('scan_secrets is not registered');
  for (const name of ['detect_stack', 'license_compatibility', 'map_attack_surface', 'validate_finding']) stub(name, async () => ({ ok: true }));
  stub('security_scan_full', async (_input, ctx) => secrets({ project_path: dir, force: true }, ctx));
  const result = await runScans({ projectPath: dir });
  const runs = result.steps.flatMap((s) => s.tools_run);
  const pass = runs.find((t) => t.name === 'gitleaks');
  const failed = result.steps.filter((s) => !s.ran || s.tools_run.some((t) => t.status === 'failed')).map((s) => `${s.tool}: ${s.reason ?? JSON.stringify(s.tools_run)}`);
  return { findings: result.findings, reason: pass?.reason ?? '', failed, pass };
}

const where = (findings: readonly Finding[]): unknown[] =>
  findings.map((f) => [f.rule_id, f.file_path, f.line_start, /;commit=([0-9a-f]+)/.exec(f.snippet ?? '')?.[1]?.slice(0, 12) ?? null]);

/** Every file under `dir`, relative, sorted — names only: git may refresh a file it already had. */
function filesUnder(dir: string, at = ''): string[] {
  return readdirSync(join(dir, at))
    .flatMap((name) => {
      const rel = at === '' ? name : `${at}/${name}`;
      return statSync(join(dir, rel)).isDirectory() ? filesUnder(dir, rel) : [rel];
    })
    .sort();
}

describe.skipIf(!GITLEAKS)('a push run: the working tree\'s .gitattributes hide nothing from the history pass, on any git', () => {
  it('T-01 a text file the tree marks `binary`, and one with a NUL byte marked so: each key is found at its commit, and the run names no attributes limit', async () => {
    const dir = repo();
    write(dir, '.gitattributes', 'secret.js binary\n');
    write(dir, 'secret.js', keyLine('binary'));
    const at = commit(dir, 'a key, marked binary').slice(0, 12);
    const { findings, reason, failed } = await push(dir);
    expect(failed).toEqual([]);
    expect(where(findings)).toEqual([['aws-access-token', 'secret.js', 1, at]]);
    expect(reason).not.toMatch(TREE_ATTRIBUTES_LIMIT);

    // The same attribute over a file git would call binary by its content too (the third measured case).
    const nul = repo();
    write(nul, '.gitattributes', 'secret.js binary\n');
    write(nul, 'secret.js', `// \0\n${keyLine('binary-with-nul')}`);
    const at2 = commit(nul, 'a NUL byte and a key, marked binary').slice(0, 12);
    const second = await push(nul);
    expect(second.failed).toEqual([]);
    expect(where(second.findings)).toEqual([['aws-access-token', 'secret.js', 2, at2]]);
    expect(second.reason).not.toMatch(TREE_ATTRIBUTES_LIMIT);
  });

  it('T-02 a file the tree marks `-diff`, and `* -diff` over a file with a NUL byte: both keys are found', async () => {
    const one = repo();
    write(one, '.gitattributes', 'secret.js -diff\n');
    write(one, 'secret.js', keyLine('minus-diff'));
    const at = commit(one, 'a key, marked -diff').slice(0, 12);
    const first = await push(one);
    expect(first.failed).toEqual([]);
    expect(where(first.findings)).toEqual([['aws-access-token', 'secret.js', 1, at]]);

    const two = repo();
    write(two, '.gitattributes', '* -diff\n');
    write(two, 'blob.js', `// \0\n${keyLine('star-minus-diff')}`);
    const at2 = commit(two, 'a NUL byte, every file -diff').slice(0, 12);
    const second = await push(two);
    expect(second.failed).toEqual([]);
    expect(where(second.findings)).toEqual([['aws-access-token', 'blob.js', 2, at2]]);
    expect(second.reason).not.toMatch(TREE_ATTRIBUTES_LIMIT);
  });

  it('T-03 a `.gitattributes` that exists only in the working tree (never committed) hides nothing either', async () => {
    const dir = repo();
    write(dir, 'secret.js', keyLine('uncommitted-attributes'));
    const at = commit(dir, 'a key').slice(0, 12);
    write(dir, '.gitattributes', 'secret.js binary\n');
    const { findings, failed } = await push(dir);
    expect(failed).toEqual([]);
    expect(where(findings)).toEqual([['aws-access-token', 'secret.js', 1, at]]);
  });

  it.skipIf(!GIT_SHOWS_MERGES)('T-04 a key only the merge commit adds, in a file the tree marks `binary`, is found at the merge', async () => {
    const dir = repo();
    git(dir, 'checkout', '-q', '-b', 'side');
    write(dir, 'b.txt', 'b\n');
    commit(dir, 'side');
    git(dir, 'checkout', '-q', 'main');
    write(dir, 'c.txt', 'c\n');
    commit(dir, 'main');
    spawnSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'core.autocrlf=false', 'merge', '-q', '--no-ff', '--no-commit', 'side'], { cwd: dir, encoding: 'utf8' });
    write(dir, '.gitattributes', 'evil.js binary\n');
    write(dir, 'evil.js', keyLine('evil-merge'));
    const at = commit(dir, 'merge, with a key of its own').slice(0, 12);
    const { findings, failed } = await push(dir);
    expect(failed).toEqual([]);
    expect(where(findings)).toEqual([['aws-access-token', 'evil.js', 1, at]]);
  });

  it('T-05 a project in a subdirectory of its repository: the finding has the path relative to the project', async () => {
    const root = repo();
    mkdirSync(join(root, 'app'));
    write(root, '.gitattributes', 'app/secret.js binary\n');
    write(root, 'app/secret.js', keyLine('subdirectory'));
    const at = commit(root, 'a key in app/, marked binary').slice(0, 12);
    const { findings, failed } = await push(join(root, 'app'));
    expect(failed).toEqual([]);
    expect(where(findings)).toEqual([['aws-access-token', 'secret.js', 1, at]]);
  });

  it('T-05 a project that is a submodule — its git directory names its work tree in core.worktree: its key is found', async () => {
    const lib = repo('secret-history-old-git-lib-');
    write(lib, '.gitattributes', 'inner.js -diff\n');
    write(lib, 'inner.js', keyLine('submodule'));
    const at = commit(lib, 'a key in the library, marked -diff').slice(0, 12);
    const sup = repo('secret-history-old-git-super-');
    git(sup, 'submodule', 'add', '-q', lib, 'vendor/lib');
    commit(sup, 'the library as a submodule');
    const project = join(sup, 'vendor', 'lib');
    expect(git(project, 'config', 'core.worktree')).not.toBe('');
    const { findings, failed } = await push(project);
    expect(failed).toEqual([]);
    expect(where(findings)).toEqual([['aws-access-token', 'inner.js', 1, at]]);
  });

  it('T-06 the project\'s .gitleaksignore and .gitleaks.toml are honoured and named, wherever gitleaks was started', async () => {
    // Two keys in two files the tree hides: one the project accepted by fingerprint, one it did not.
    const dir = repo();
    write(dir, '.gitattributes', '*.js binary\n');
    write(dir, 'accepted.js', keyLine('accepted'));
    write(dir, 'open.js', keyLine('open'));
    const sha = commit(dir, 'two keys, both marked binary');
    write(dir, '.gitleaksignore', `${sha}:accepted.js:aws-access-token:1\n`);
    commit(dir, 'accept one of them');
    const ignored = await push(dir);
    expect(ignored.failed).toEqual([]);
    expect(where(ignored.findings)).toEqual([['aws-access-token', 'open.js', 1, sha.slice(0, 12)]]);
    expect(ignored.pass?.honoured_config ?? []).toEqual(expect.arrayContaining([expect.stringContaining('.gitleaksignore')]));

    // The project's own configuration: an allowlist over one of the two paths.
    const conf = repo();
    write(conf, '.gitattributes', '*.js binary\n');
    write(conf, 'fixture.js', keyLine('allowlisted'));
    write(conf, 'open.js', keyLine('open-two'));
    write(conf, '.gitleaks.toml', '[extend]\nuseDefault = true\n\n[allowlist]\npaths = [\'\'\'fixture\\.js\'\'\']\n');
    const at = commit(conf, 'two keys, one path allowlisted by the project').slice(0, 12);
    const configured = await push(conf);
    expect(configured.failed).toEqual([]);
    expect(where(configured.findings)).toEqual([['aws-access-token', 'open.js', 1, at]]);
    expect(configured.pass?.honoured_config ?? []).toEqual(expect.arrayContaining([expect.stringContaining('.gitleaks.toml')]));
  });

  it('T-07 nothing is written: the repository and its git directory hold the files they held, and no scratch directory is left', async () => {
    const dir = repo();
    write(dir, '.gitattributes', 'secret.js binary\n');
    write(dir, 'secret.js', keyLine('nothing-written'));
    commit(dir, 'a key, marked binary');
    const scratch = makeTempDir('secret-history-old-git-tmp-');
    const before = { git: filesUnder(join(dir, '.git')), tree: filesUnder(dir).filter((f) => !f.startsWith('.git/')) };
    const names = ['TMPDIR', 'TEMP', 'TMP'] as const;
    const saved = names.map((n) => process.env[n]);
    for (const n of names) process.env[n] = scratch;
    try {
      const { findings, failed } = await push(dir);
      expect(failed).toEqual([]);
      expect(findings).toHaveLength(1);
    } finally {
      names.forEach((n, i) => {
        if (saved[i] === undefined) delete process.env[n];
        else process.env[n] = saved[i];
      });
    }
    // The scan's own reports and database go to .guardian/ in the project, as for every scan: nothing else is new.
    expect(git(dir, 'status', '--porcelain').split('\n').filter((l) => l !== '' && l !== '?? .guardian/')).toEqual([]);
    expect(filesUnder(join(dir, '.git'))).toEqual(before.git);
    expect(filesUnder(dir).filter((f) => !f.startsWith('.git/') && !f.startsWith('.guardian/'))).toEqual(before.tree);
    expect(readdirSync(scratch).filter((n) => n.startsWith('guardian-history-'))).toEqual([]);
  });

  it('T-08 what the REPOSITORY chose still applies: its info/attributes hides the file it names, and a path over 1 MiB is left to git and named', async () => {
    const dir = repo();
    write(dir, 'secret.js', keyLine('info-attributes'));
    commit(dir, 'a key');
    mkdirSync(join(dir, '.git', 'info'), { recursive: true });
    // One file, not every file: with nothing left to read the pass FAILS ("0 commits scanned"), which is another guard's.
    write(dir, '.git/info/attributes', 'secret.js -diff\n');
    const hidden = await push(dir);
    expect(hidden.failed).toEqual([]);
    expect(where(hidden.findings)).toEqual([]);

    const big = repo();
    write(big, 'big.js', 'a\n'.repeat(TEXT_LIMIT_BYTES / 2 + 1));
    commit(big, 'a file over 1 MiB');
    const large = await push(big);
    expect(large.failed).toEqual([]);
    expect(large.reason).toMatch(/1 path\(s\) holding a file over 1 MiB/);
  });

  it('T-09 the value of a key found in a file the tree hides is read by the gate, as for any other finding', async () => {
    const dir = repo();
    write(dir, '.gitattributes', 'secret.js binary\n');
    write(dir, 'secret.js', keyLine('value'));
    commit(dir, 'a key, marked binary');
    const { findings, failed } = await push(dir);
    expect(failed).toEqual([]);
    expect(findings).toHaveLength(1);
    const [finding] = findings;
    // The value is kept as this run's HMAC, never as text: that there is one says the commit's diff was read.
    expect(finding === undefined ? undefined : secretValueOf(finding)).toMatch(/^[0-9a-f]{32,}$/);
  });
});
