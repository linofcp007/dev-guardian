/**
 * `.guardianignore` — gitignore syntax, one matcher every scanner's results
 * go through, and the native exclusion flags derived from it.
 *
 * The matcher is checked two ways: named cases for each rule of the syntax,
 * and a differential run against `git check-ignore` itself over one tree, so
 * "gitignore syntax" is a measured claim rather than a paraphrase of the docs.
 */

import { execa } from 'execa';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, sep } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import {
  banditExcludeArgs,
  compileIgnore,
  GUARDIAN_IGNORE_FILE,
  loadProjectExclusions,
  semgrepExcludeArgs,
  trivySkipArgs,
} from '../../../src/platform/guardianIgnore.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

/** Real `git` processes: a file-level ceiling for a loaded full-suite run (see vitest.config.ts). */
vi.setConfig({ testTimeout: 60_000 });

afterAll(cleanupTempDirs);

function write(root: string, rel: string, content = 'x\n'): void {
  const abs = join(root, rel);
  mkdirSync(join(abs, '..'), { recursive: true });
  writeFileSync(abs, content);
}

describe('compileIgnore — gitignore syntax', () => {
  it('matches a bare name at any depth, a pattern with a slash only from the root', () => {
    const m = compileIgnore('fixtures\nmcp/test/data\n');
    expect(m.ignores('fixtures')).toBe(true);
    expect(m.ignores('a/b/fixtures/x.py')).toBe(true);
    expect(m.ignores('mcp/test/data/x.py')).toBe(true);
    expect(m.ignores('other/mcp/test/data/x.py')).toBe(false);
    expect(m.ignores('fixtures2/x.py')).toBe(false);
  });

  it('anchors a leading slash, and a trailing slash matches directories only', () => {
    const m = compileIgnore('/build\nlogs/\n');
    expect(m.ignores('build/out.js')).toBe(true);
    expect(m.ignores('src/build/out.js')).toBe(false);
    expect(m.ignores('logs/a.txt')).toBe(true);
    expect(m.ignores('src/logs/a.txt')).toBe(true);
    // `logs/` names a directory: a FILE called logs is not matched.
    expect(m.ignores('logs', false)).toBe(false);
    expect(m.ignores('logs', true)).toBe(true);
  });

  it('supports *, ?, [..] and the three ** forms', () => {
    const m = compileIgnore('*.min.js\nfile?.txt\n[ab].cfg\n**/gen/**\ndocs/**/*.md\n**/snap\n');
    expect(m.ignores('a/b/c.min.js')).toBe(true);
    expect(m.ignores('file1.txt')).toBe(true);
    expect(m.ignores('file12.txt')).toBe(false);
    expect(m.ignores('a.cfg')).toBe(true);
    expect(m.ignores('c.cfg')).toBe(false);
    expect(m.ignores('x/gen/y/z.ts')).toBe(true);
    expect(m.ignores('docs/a.md')).toBe(true);
    expect(m.ignores('docs/x/y/a.md')).toBe(true);
    expect(m.ignores('src/docs/a.md')).toBe(false);
    expect(m.ignores('snap')).toBe(true);
    expect(m.ignores('deep/er/snap/x')).toBe(true);
  });

  it('lets a later negation re-include a file — but never one inside an excluded directory', () => {
    const m = compileIgnore('*.log\n!keep.log\nvendor/\n!vendor/ours.py\n');
    expect(m.ignores('a.log')).toBe(true);
    expect(m.ignores('keep.log')).toBe(false);
    expect(m.ignores('sub/keep.log')).toBe(false);
    // git: "It is not possible to re-include a file if a parent directory of
    // that file is excluded."
    expect(m.ignores('vendor/ours.py')).toBe(true);
  });

  it('skips comments and blank lines, honours escapes, trims unescaped trailing spaces, reads CRLF', () => {
    const m = compileIgnore('# comment\r\n\r\n\\#hash\r\n\\!bang\r\ntrail   \r\nsp\\ \r\n');
    expect(m.patterns).toBe(4);
    expect(m.ignores('#hash')).toBe(true);
    expect(m.ignores('!bang')).toBe(true);
    expect(m.ignores('trail')).toBe(true);
    expect(m.ignores('sp ')).toBe(true);
    expect(m.ignores('comment')).toBe(false);
  });

  it('normalises the paths it is asked about', () => {
    const m = compileIgnore('mcp/test/fixtures/\n');
    expect(m.ignores('./mcp/test/fixtures/a.py')).toBe(true);
    expect(m.ignores('mcp\\test\\fixtures\\a.py')).toBe(true);
    expect(m.ignores('/abs/elsewhere/mcp/test/fixtures/a.py')).toBe(false);
  });

  it('agrees with `git check-ignore` on every path of a tree', async () => {
    const patterns = [
      'fixtures/',
      '/top.txt',
      '*.min.js',
      '!keep.min.js',
      'a/**/deep',
      'docs/*.md',
      '**/cache',
      'nested/dir/',
      '!nested/dir/back.txt',
      'q?.txt',
      '[xy].py',
      'x/**',
      '!x/kept.txt',
    ].join('\n');
    const paths = [
      'fixtures/a.py',
      'src/fixtures/b.py',
      'fixtures.py',
      'top.txt',
      'src/top.txt',
      'lib/app.min.js',
      'lib/keep.min.js',
      'a/b/c/deep',
      'a/deep/inner.txt',
      'docs/r.md',
      'docs/sub/r.md',
      'other/docs/r.md',
      'cache/x',
      'p/cache',
      'nested/dir/back.txt',
      'nested/dir/gone.txt',
      'q1.txt',
      'q12.txt',
      'x.py',
      'z.py',
      'x/kept.txt',
      'x/other.txt',
      'plain/file.ts',
    ];
    const root = makeTempDir('ignore-diff-');
    await execa('git', ['init', '-q'], { cwd: root });
    writeFileSync(join(root, '.gitignore'), `${patterns}\n`);
    for (const p of paths) write(root, p);

    const checked = await execa('git', ['check-ignore', '--no-index', '--stdin', '-z'], {
      cwd: root,
      input: paths.join('\0'),
      reject: false,
    });
    const gitIgnored = new Set(checked.stdout.split('\0').filter((s) => s.length > 0));
    const m = compileIgnore(patterns);
    const ours = new Set(paths.filter((p) => m.ignores(p)));
    expect([...ours].sort()).toEqual([...gitIgnored].sort());
    // A differential test over a set nobody excluded proves nothing.
    expect(gitIgnored.size).toBeGreaterThan(8);
    expect(paths.length - gitIgnored.size).toBeGreaterThan(5);
  });
});

describe('loadProjectExclusions', () => {
  it('is null when the project has no .guardianignore', async () => {
    expect(await loadProjectExclusions(makeTempDir('ignore-none-'))).toBeNull();
  });

  it('counts the files it excludes and names the top-most excluded paths', async () => {
    const root = makeTempDir('ignore-plan-');
    write(root, GUARDIAN_IGNORE_FILE, 'mcp/test/fixtures/\n*.snap\n');
    write(root, 'mcp/test/fixtures/a.py');
    write(root, 'mcp/test/fixtures/deep/b.py');
    write(root, 'mcp/src/app.ts');
    write(root, 'mcp/src/app.snap');
    write(root, 'node_modules/fixtures/c.py'); // never walked
    const ex = await loadProjectExclusions(root);
    if (ex === null || 'error' in ex) throw new Error('expected exclusions');
    expect(ex.patterns).toBe(2);
    expect(ex.excludedFileCount).toBe(3);
    expect(ex.excludedDirs).toEqual(['mcp/test/fixtures']);
    expect(ex.excludedFiles).toEqual(['mcp/src/app.snap']);
    expect(ex.ignores('mcp/test/fixtures/new.py')).toBe(true);
    expect(ex.ignores('mcp/src/app.ts')).toBe(false);
    expect(ex.hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("in a git work tree, lists git's files — never a crawl of what .gitignore already excludes", async () => {
    const root = makeTempDir('ignore-git-');
    await execa('git', ['init', '-q'], { cwd: root });
    write(root, '.gitignore', 'huge/\n');
    write(root, GUARDIAN_IGNORE_FILE, '*.log\n');
    write(root, 'huge/a.log');
    write(root, 'huge/b.log');
    write(root, 'app.log');
    write(root, 'app.ts');
    const ex = await loadProjectExclusions(root);
    if (ex === null || 'error' in ex) throw new Error('expected exclusions');
    expect(ex.excludedFiles).toEqual(['app.log']);
    expect(ex.excludedFileCount).toBe(1);
    expect(ex.keptFiles).toEqual(['.gitignore', GUARDIAN_IGNORE_FILE, 'app.ts']);
  });

  it('builds anchored native flags: Semgrep --exclude, Trivy --skip-dirs/--skip-files, Bandit -x', async () => {
    const root = makeTempDir('ignore-native-');
    write(root, GUARDIAN_IGNORE_FILE, 'mcp/test/fixtures/\nsecret.env\n');
    write(root, 'mcp/test/fixtures/a.py');
    write(root, 'secret.env');
    write(root, 'app.py');
    const ex = await loadProjectExclusions(root);
    if (ex === null || 'error' in ex) throw new Error('expected exclusions');
    expect(semgrepExcludeArgs(ex)).toEqual(['--exclude=/mcp/test/fixtures', '--exclude=/secret.env']);
    expect(trivySkipArgs(ex)).toEqual(['--skip-dirs', 'mcp/test/fixtures', '--skip-files', 'secret.env']);
    const bandit = banditExcludeArgs(ex, root);
    expect(bandit[0]).toBe('-x');
    const list = (bandit[1] ?? '').split(',');
    expect(list).toContain('.git');
    expect(list).toContain(`${join(root, 'mcp', 'test', 'fixtures')}${sep}`);
    expect(list).toContain(join(root, 'secret.env'));
  });

  it('never passes a native flag that an unanchored reading would widen onto a kept file', async () => {
    const root = makeTempDir('ignore-collide-');
    // `/data/` is anchored: only the top-level data/ is excluded. An old
    // Semgrep reading `data` unanchored would also drop x/data/keep.py.
    write(root, GUARDIAN_IGNORE_FILE, '/data/\n');
    write(root, 'data/a.py');
    write(root, 'x/data/keep.py');
    const ex = await loadProjectExclusions(root);
    if (ex === null || 'error' in ex) throw new Error('expected exclusions');
    expect(ex.excludedDirs).toEqual(['data']);
    expect(semgrepExcludeArgs(ex)).toEqual([]);
    expect(trivySkipArgs(ex)).toEqual(['--skip-dirs', 'data']);
    // The result filter still honours it exactly.
    expect(ex.ignores('data/new.py')).toBe(true);
    expect(ex.ignores('x/data/keep.py')).toBe(false);
  });
});
