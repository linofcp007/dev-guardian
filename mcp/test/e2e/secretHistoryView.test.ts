/**
 * The secrets history pass on a PUSH — no `--baseline-ref` / `--rules-ref`,
 * so no full-content pass behind it (`ci/runScans.ts`) — judged on what REAL
 * gitleaks and git report, through `runScans` as the CLI gate runs it
 * (`security_scan_full` stubbed to the real `scan_secrets`, every other step
 * a no-op, as in `secretFullContentGitleaks.test.ts`).
 *
 * `git log -p` printed "Binary files differ" for a file with a NUL byte and
 * no diff at all for a merge commit, so a one-line key in either was read by
 * no pass and the gate passed with exit 0 (measured, gitleaks 8.30.1, git
 * 2.47.3 and 2.56.0). The pass now has git show both
 * (`runners/historyView.ts`): every file as text but at a path holding a
 * file over 1 MiB, and a two-parent merge's own change as a remerge-diff.
 *
 * The keys are generated (no credential-shaped literal in this file).
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';
import { runScans } from '../../src/ci/runScans.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { TEXT_LIMIT_BYTES, unspecifiedDiff } from '../../src/runners/historyView.js';
import { TOOLS, type ToolModule } from '../../src/tools/index.js';
import type { Finding } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

afterAll(cleanupTempDirs);
vi.setConfig({ testTimeout: 180_000 });

const GITLEAKS = await isInstalled('gitleaks');

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
/** An AWS-access-key-shaped value from a seed: `AKIA` + 16 of [A-Z2-7]. */
const aws = (seed: string): string => {
  const d = createHash('sha256').update(`history-view-${seed}`).digest();
  return `${'AK'}${'IA'}${Array.from({ length: 16 }, (_, i) => B32[(d[i] ?? 0) % 32]).join('')}`;
};

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

function write(dir: string, path: string, text: string): void {
  writeFileSync(join(dir, path), text);
}

function commit(dir: string, message: string): void {
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '-m', message);
}

/** A repository with one commit, on `main`. */
function repo(): string {
  const dir = resolveProjectPath(makeTempDir('secret-history-view-')).path;
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
async function push(dir: string): Promise<{ findings: Finding[]; reason: string; failed: string[] }> {
  const secrets = TOOLS.find((t) => t.name === 'scan_secrets')?.handler;
  if (secrets === undefined) throw new Error('scan_secrets is not registered');
  for (const name of ['detect_stack', 'license_compatibility', 'map_attack_surface', 'validate_finding']) stub(name, async () => ({ ok: true }));
  stub('security_scan_full', async (_input, ctx) => secrets({ project_path: dir, force: true }, ctx));
  const result = await runScans({ projectPath: dir });
  const runs = result.steps.flatMap((s) => s.tools_run);
  const history = runs.find((t) => t.name === 'gitleaks');
  const failed = result.steps.filter((s) => !s.ran || s.tools_run.some((t) => t.status === 'failed')).map((s) => `${s.tool}: ${s.reason ?? JSON.stringify(s.tools_run)}`);
  return { findings: result.findings, reason: history?.reason ?? '', failed };
}

const where = (findings: readonly Finding[]): unknown[] =>
  findings.map((f) => [f.rule_id, f.file_path, f.line_start, /;commit=([0-9a-f]+)/.exec(f.snippet ?? '')?.[1]?.slice(0, 12) ?? null]);

/**
 * `git merge --no-commit …refs`, which may stop at a conflict (exit 1) for
 * the caller to resolve — so not {@link git}, but with its settings: a merge
 * under the user's `core.autocrlf=true` rewrote the files it touched, and
 * the merge then had a change of its own.
 */
function merge(dir: string, ...refs: string[]): void {
  spawnSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'core.autocrlf=false', 'merge', '-q', '--no-commit', ...refs], { cwd: dir, encoding: 'utf8' });
}

/** A merge of a side branch, left uncommitted (`--no-commit`) for the caller to change and commit. */
function mergeSide(dir: string, side: (d: string) => void, main: (d: string) => void): void {
  git(dir, 'checkout', '-q', '-b', 'side');
  side(dir);
  commit(dir, 'side');
  git(dir, 'checkout', '-q', 'main');
  main(dir);
  commit(dir, 'main');
  merge(dir, '--no-ff', 'side');
}

describe.skipIf(!GITLEAKS)('a push run: the history pass reads what `git log -p` left out', () => {
  it('a key in a file git reads as binary by its content (a NUL byte) is found, at its commit', async () => {
    const dir = repo();
    write(dir, 'blob.js', `// \0\nconst AWS_KEY = "${aws('nul')}";\n`);
    commit(dir, 'nul');
    const at = git(dir, 'rev-parse', 'HEAD').slice(0, 12);
    const { findings, failed } = await push(dir);
    expect(failed).toEqual([]);
    expect(where(findings)).toEqual([['aws-access-token', 'blob.js', 2, at]]);
  });

  it('a NUL byte AND the tree marking the file binary: still found (the tree decides nothing since 3.6.1)', async () => {
    const dir = repo();
    write(dir, '.gitattributes', 'blob.js binary\n');
    write(dir, 'blob.js', `\0const AWS_KEY = "${aws('both')}";\n`);
    commit(dir, 'nul, marked binary');
    const { findings } = await push(dir);
    expect(where(findings)).toEqual([['aws-access-token', 'blob.js', 1, git(dir, 'rev-parse', 'HEAD').slice(0, 12)]]);
  });

  it('a key only the merge commit adds (an evil merge) is found, at the merge', async () => {
    const dir = repo();
    mergeSide(
      dir,
      (d) => write(d, 'b.txt', 'b\n'),
      (d) => write(d, 'c.txt', 'c\n'),
    );
    write(dir, 'evil.js', `const AWS_KEY = "${aws('evil')}";\n`);
    commit(dir, 'merge');
    const { findings, failed } = await push(dir);
    expect(failed).toEqual([]);
    expect(where(findings)).toEqual([['aws-access-token', 'evil.js', 1, git(dir, 'rev-parse', 'HEAD').slice(0, 12)]]);
  });

  // gitleaks' diff parser stops a file's header at remerge-diff's `remerge
  // CONFLICT` line and names the file `b/f.txt` (measured): named as git does.
  it('a key a conflicted merge resolves into its file is found, at the merge, under the file\'s own path', async () => {
    const dir = repo();
    write(dir, 'f.txt', 'a\nb\nc\n');
    commit(dir, 'f');
    mergeSide(
      dir,
      (d) => write(d, 'f.txt', 'a\nSIDE\nc\n'),
      (d) => write(d, 'f.txt', 'a\nMAIN\nc\n'),
    );
    write(dir, 'f.txt', `a\nkey = "${aws('conflict')}"\nc\n`);
    commit(dir, 'merge');
    const { findings } = await push(dir);
    expect(where(findings)).toEqual([['aws-access-token', 'f.txt', 2, git(dir, 'rev-parse', 'HEAD').slice(0, 12)]]);
  });

  // The control: a remerge-diff shows what the merge itself added, never the
  // side branch again — `--diff-merges=first-parent` re-read it under the
  // merge's commit, where a `.gitleaksignore` entry naming the side commit
  // no longer matched.
  it('a key a side branch added, merged cleanly: read once, at the side commit — and its .gitleaksignore entry still holds', async () => {
    const dir = repo();
    mergeSide(
      dir,
      (d) => write(d, 'side.env', `KEY = "${aws('side')}"\n`),
      (d) => write(d, 'm.txt', 'm\n'),
    );
    commit(dir, 'merge');
    const side = git(dir, 'rev-parse', 'side');
    const once = await push(dir);
    expect(where(once.findings)).toEqual([['aws-access-token', 'side.env', 1, side.slice(0, 12)]]);
    write(dir, '.gitleaksignore', `${side}:side.env:aws-access-token:1\n`);
    commit(dir, 'accept the fixture key');
    expect(where((await push(dir)).findings)).toEqual([]);
  });

  it("an octopus merge's own key is not read, and the run says so", async () => {
    const dir = repo();
    for (const b of ['x', 'y']) {
      git(dir, 'checkout', '-q', '-b', b, 'main');
      write(dir, `${b}.txt`, `${b}\n`);
      commit(dir, b);
    }
    git(dir, 'checkout', '-q', 'main');
    // A commit of main's own, or git fast-forwards to x and merges y alone: two parents.
    write(dir, 'm.txt', 'm\n');
    commit(dir, 'main');
    merge(dir, 'x', 'y');
    write(dir, 'octo.js', `const AWS_KEY = "${aws('octopus')}";\n`);
    commit(dir, 'octopus');
    const { findings, reason, failed } = await push(dir);
    expect(failed).toEqual([]);
    expect(where(findings)).toEqual([]);
    expect(reason).toContain("1 octopus merge(s)' own changes were not read");
  });

  it('a path holding a file over 1 MiB is left to git: binary by content is not read (named), text is', async () => {
    const dir = repo();
    const pad = `${'x'.repeat(79)}\n`.repeat(Math.ceil(TEXT_LIMIT_BYTES / 80) + 1);
    write(dir, 'big.txt', `${pad}const AWS_KEY = "${aws('big-text')}";\n`);
    write(dir, 'big nul.dat', `\0${pad}const AWS_KEY = "${aws('big-nul')}";\n`);
    write(dir, 'small.dat', `\0\nconst AWS_KEY = "${aws('small-nul')}";\n`);
    commit(dir, 'files');
    const { findings, reason } = await push(dir);
    expect(where(findings).map((w) => (w as unknown[])[1]).sort()).toEqual(['big.txt', 'small.dat']);
    expect(reason).toContain('2 path(s) holding a file over 1 MiB in some commit were read as git decides');
  });

  it('git writes nothing in the repository: the remerge-diffs go to a scratch object directory', async () => {
    const dir = repo();
    mergeSide(
      dir,
      (d) => write(d, 'b.txt', 'b\n'),
      (d) => write(d, 'c.txt', 'c\n'),
    );
    commit(dir, 'merge');
    const objects = join(dir, '.git', 'objects');
    const before = readdirSync(objects).sort();
    await push(dir);
    expect(readdirSync(objects).sort()).toEqual(before);
  });

  // Measured on node:22-trixie: with git's own temporary object directory
  // inside `.git/objects`, a read-only repository's history pass printed
  // "unable to create temporary object directory" and scanned 0 commits.
  it.skipIf(process.platform === 'win32' || process.getuid?.() === 0)('a repository the scan cannot write is read in full', async () => {
    const dir = repo();
    mergeSide(
      dir,
      (d) => write(d, 'b.txt', 'b\n'),
      (d) => write(d, 'c.txt', 'c\n'),
    );
    write(dir, 'evil.js', `const AWS_KEY = "${aws('read-only')}";\n`);
    commit(dir, 'merge');
    const objects = join(dir, '.git', 'objects');
    const lock = (mode: number): void => {
      for (const entry of readdirSync(objects)) if (existsSync(join(objects, entry))) chmodSync(join(objects, entry), mode);
      chmodSync(objects, mode);
    };
    lock(0o555);
    try {
      const { findings, failed } = await push(dir);
      expect(failed).toEqual([]);
      expect(where(findings).map((w) => (w as unknown[])[1])).toEqual(['evil.js']);
    } finally {
      lock(0o755);
    }
  });
});

describe('the attributes line leaving a large path to git (historyView.unspecifiedDiff)', () => {
  it.each([
    ['assets/model.bin', '/assets/model.bin !diff'],
    ['a*b?[c].dat', '/a\\*b\\?\\[c\\].dat !diff'],
    ['big nul.bin', '"/big nul.bin" !diff'],
    ['quote"d.bin', '"/quote\\"d.bin" !diff'],
    ['tab\there.bin', '"/tab\\011here.bin" !diff'],
    ['back\\slash *.bin', '"/back\\\\\\\\slash \\\\*.bin" !diff'],
  ])('%j -> %s', (path, line) => {
    expect(unspecifiedDiff(path)).toBe(line);
  });
});
