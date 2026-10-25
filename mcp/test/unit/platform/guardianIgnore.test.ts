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
  submodulesNotIgnored,
  trivySkipArgs,
} from '../../../src/platform/guardianIgnore.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';
import { expectNearReference } from '../../helpers/timing.js';

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

  // Where 3.6.0's RegExp translation and git parted (measured with git
  // 2.51): a class matched `/` (`a[!b]c` excluded `a/c`), an unterminated
  // `[` was a literal one (git matches nothing), `***/` was a plain `*/`
  // (git: `**/`), `**\/` one directory (git: one or more), `[[:digit:]]` and
  // `\-` inside a class meant something else, and a reversed range (`[z-a]`)
  // threw from compileIgnore. Paths need not exist for `check-ignore --no-index`.
  it('agrees with `git check-ignore` on the edge cases of the syntax', async () => {
    const patterns = [
      'foo[bar',
      'a[!b]c',
      '***/x3',
      '[[:digit:]]x',
      'r[a\\-z]',
      'z[z-a]',
      'q[[:foo:]]',
      'm[/]n',
      '**\\/k',
      't[]]u',
      'w[!]]v',
      'h[[:alpha]',
      '**/**/**/deep',
      'a*a*a*b',
      'lib/*/gen',
      'c?t',
      'g/**',
      '!g/back',
    ].join('\n');
    const paths = [
      'foo[bar', 'a/c', 'axc', 'p/q/x3', 'x3', '1x', 'ax', 'r-', 'rm', 'zm', 'zz', 'qa', 'm/n', 'k', 'p/k', 'p/q/k',
      't]u', 'w]v', 'wav', 'h[', 'ha', 'h]', 'deep', 'x/y/deep', 'x/deep/in', 'aaab', 'ab', 'aXaYaZb', 'x/aaab',
      'aab', 'lib/x/gen', 'lib/x/y/gen', 'lib/gen', 'c/t', 'cat', 'g', 'g/x', 'g/back', 'g/x/y',
    ];
    const root = makeTempDir('ignore-diff-edge-');
    await execa('git', ['init', '-q'], { cwd: root });
    writeFileSync(join(root, '.gitignore'), `${patterns}\n`);
    const checked = await execa('git', ['check-ignore', '--no-index', '--stdin', '-z'], {
      cwd: root,
      input: paths.join('\0'),
      reject: false,
    });
    const gitIgnored = new Set(checked.stdout.split('\0').filter((s) => s.length > 0));
    const m = compileIgnore(patterns);
    expect(paths.filter((p) => m.ignores(p)).sort()).toEqual([...gitIgnored].sort());
    expect(gitIgnored.size).toBeGreaterThan(15);
    expect(paths.length - gitIgnored.size).toBeGreaterThan(15);
  });

  it('a trailing backslash, like an unterminated class, matches nothing (git aborts on both)', () => {
    const m = compileIgnore('e\\\nfoo[bar\n');
    expect(m.patterns).toBe(2);
    expect(m.ignores('e\\')).toBe(false);
    expect(m.ignores('e')).toBe(false);
    expect(m.ignores('foo[bar')).toBe(false);
  });
});

/**
 * Review 3.6.1, finding 1: each pattern was a RegExp (`**` + `/` became
 * `(?:.*\/)?`, `*` became `[^/]*`), and a `.semgrepignore` or
 * `.guardianignore` is the scanned repository's to write. Measured on 3.6.0:
 * `**` + `/` twelve times then `zz` took 123 ms to test one path twelve
 * directories deep, ~4x more for every two more (7 s at nineteen);
 * `a*` eight times then `b`, 122 ms against a 30-character name (7-300 s at
 * twelve stars) — on the server's only thread, on every Semgrep coverage
 * computation and before every scan's cache check.
 */
describe('compileIgnore — no pattern can make a test backtrack', () => {
  const deep = `${Array.from({ length: 12 }, (_, i) => `d${String(i)}`).join('/')}/file.js`;

  it('`**/` repeated costs what one `**/` does', () => {
    const hostile = compileIgnore(`${'**/'.repeat(12)}zz`);
    const reference = compileIgnore(`**/${'z'.repeat(35)}`);
    expectNearReference('**/ x12', () => hostile.ignores(deep), () => reference.ignores(deep), { maxRatio: 8 });
  });

  it('`*` repeated in one name costs what one `*` does', () => {
    const name = `x/${'a'.repeat(30)}`;
    const hostile = compileIgnore(`${'a*'.repeat(8)}b`);
    const reference = compileIgnore(`${'a'.repeat(15)}*b`);
    expectNearReference('a* x8', () => hostile.ignores(name), () => reference.ignores(name), { maxRatio: 8 });
  });

  // Matching costs at most pattern x path length; patterns crafted to use
  // all of it (a long run after a `*`, against a long name of that run) took
  // 47 ms a path at 64 KiB of them. Past a path's step budget it is "kept".
  const crafted = (n: number, run = 200): string =>
    Array.from({ length: n }, (_, i) => `*${'a'.repeat(run)}b${String(i)}*`).join('\n');

  it('a path whose test passes its step budget is kept, and counted — the same answer every time', () => {
    const m = compileIgnore(`${crafted(50)}\n*.log\n`);
    const long = `x/${'a'.repeat(250)}`;
    expect(m.ignores(long)).toBe(false);
    expect(m.ignores(long)).toBe(false);
    expect(m.overBudget).toBe(2);
    expect(m.ignores('x/app.log')).toBe(true);
    expect(m.overBudget).toBe(2);
  });

  it('crafted patterns cost what plain ones of the same count do', () => {
    const long = `x/${'a'.repeat(250)}`;
    const hostile = compileIgnore(crafted(50, 100));
    const reference = compileIgnore(Array.from({ length: 50 }, (_, i) => `*${'c'.repeat(100)}b${String(i)}*`).join('\n'));
    // The reference's `*` tries every position once (~250 steps a pattern);
    // the hostile one re-reads its run from each (~15 000) until the budget
    // stops it — ~60x the reference without one, under 1x with it.
    expectNearReference('crafted x50', () => hostile.ignores(long), () => reference.ignores(long), { maxRatio: 8 });
  });

  it('an ignore file past the caps is not applied at all, and says why', () => {
    const big = compileIgnore(`${'a\n'.repeat(40_000)}`);
    expect(big.refused).toMatch(/^it holds 80000 characters, more than the 65536/);
    expect(big.patterns).toBe(0);
    expect(big.ignores('a')).toBe(false);
    expect(compileIgnore(Array.from({ length: 2001 }, (_, i) => `p${String(i)}`).join('\n')).refused).toMatch(/more than the 2000 patterns/);
    expect(compileIgnore(`ok\n${'x'.repeat(4097)}\n`).refused).toMatch(/^line 2 holds 4097 characters/);
    expect(compileIgnore('a\n'.repeat(2000)).refused).toBeUndefined();
  });

  it('loadProjectExclusions names an ignore file it does not apply — never "nothing matched"', async () => {
    const root = makeTempDir('ignore-refused-');
    // A name longer than the run (the test only backtracks then), short enough for Windows.
    write(root, GUARDIAN_IGNORE_FILE, `${crafted(50, 60)}\n*.log\n`);
    write(root, `x/${'a'.repeat(120)}`);
    write(root, 'app.log');
    const budget = await loadProjectExclusions(root);
    expect(budget).toEqual({
      file: join(root, GUARDIAN_IGNORE_FILE),
      error: 'not applied: testing 1 path(s) against its 51 patterns took more steps than a path is allowed',
    });
    write(root, GUARDIAN_IGNORE_FILE, 'x'.repeat(70_000));
    const big = await loadProjectExclusions(root);
    expect(big !== null && 'error' in big ? big.error : '').toMatch(/^not applied: it holds 70000 characters/);
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

  it("anchors Semgrep's --exclude at the git root, where Semgrep anchors it, for a project in a subdirectory", async () => {
    // Measured, Semgrep 1.176.1, project at repo/sub: `--exclude=/fixtures`
    // excluded nothing, and `--exclude=/sub/lib` (meant for <project>/sub/lib)
    // excluded <project>/lib — a kept file — instead.
    const repoRoot = makeTempDir('ignore-sub-');
    await execa('git', ['init', '-q'], { cwd: repoRoot });
    const project = join(repoRoot, 'sub');
    write(project, GUARDIAN_IGNORE_FILE, 'fixtures/\n/sub/lib/\n');
    write(project, 'fixtures/x.py');
    write(project, 'sub/lib/y.py');
    write(project, 'lib/ok.py');
    const ex = await loadProjectExclusions(project);
    if (ex === null || 'error' in ex) throw new Error('expected exclusions');
    expect(ex.excludedDirs).toEqual(['fixtures', 'sub/lib']);
    expect(semgrepExcludeArgs(ex)).toEqual(['--exclude=/sub/fixtures', '--exclude=/sub/sub/lib']);
    // Trivy anchors at its own target, the project.
    expect(trivySkipArgs(ex)).toEqual(['--skip-dirs', 'fixtures', '--skip-dirs', 'sub/lib']);
  });

  it('withholds a native flag whose path holds glob syntax — `[id]` is a character class to every scanner', async () => {
    const root = makeTempDir('ignore-glob-');
    write(root, GUARDIAN_IGNORE_FILE, '*.test.js\n');
    write(root, 'pages/[id].test.js');
    write(root, 'pages/a.test.js');
    write(root, 'pages/i.js');
    const ex = await loadProjectExclusions(root);
    if (ex === null || 'error' in ex) throw new Error('expected exclusions');
    expect(ex.excludedFiles).toEqual(['pages/[id].test.js', 'pages/a.test.js']);
    expect(semgrepExcludeArgs(ex)).toEqual(['--exclude=/pages/a.test.js']);
    expect(trivySkipArgs(ex)).toEqual(['--skip-files', 'pages/a.test.js']);
    const bandit = (banditExcludeArgs(ex, root)[1] ?? '').split(',');
    expect(bandit).toContain(join(root, 'pages', 'a.test.js'));
    expect(bandit.some((b) => b.includes('[id]'))).toBe(false);
    // The result filter still honours it.
    expect(ex.ignores('pages/[id].test.js')).toBe(true);
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

/**
 * Round 4, item 6: an initialised submodule the project's `.guardianignore`
 * excludes is not the project's to scan — no "submodule contents not
 * scanned" gap. It used to be named whatever the ignore file said.
 */
describe('submodulesNotIgnored', () => {
  const project = (ignore: string | null): string => {
    const dir = makeTempDir('guardian-ignore-submodules-');
    if (ignore !== null) writeFileSync(join(dir, GUARDIAN_IGNORE_FILE), ignore);
    return dir;
  };

  it.each([['libs/core'], ['libs/'], ['libs/core/**'], ['/libs/core/']])('%s excludes the submodule libs/core', (pattern) => {
    expect(submodulesNotIgnored(project(`${pattern}\n`), ['libs/core', 'vendor/x'])).toEqual(['vendor/x']);
  });

  it('a pattern that excludes only some of its files leaves it a gap', () => {
    expect(submodulesNotIgnored(project('libs/core/*.js\n'), ['libs/core'])).toEqual(['libs/core']);
  });

  it('no .guardianignore excludes nothing', () => {
    expect(submodulesNotIgnored(project(null), ['libs/core'])).toEqual(['libs/core']);
  });
});
