/**
 * `ci/changedSince.ts` against a real git repository (review 11, finding 1):
 * which `semgrep.accept_timeouts` files are not, in the scanned tree, what
 * they were at the `--baseline-ref` / `--rules-ref` commit — so an accepted
 * timeout covers a file only as it was reviewed.
 */
import { spawnSync } from 'node:child_process';
import { appendFileSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { filesChangedFrom, filesChangedSince, scanSettingsCommit } from '../../../src/ci/changedSince.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

function repo(autocrlf = 'false'): { dir: string; git: (...args: string[]) => string } {
  const dir = makeTempDir('changed-since-');
  const git = (...args: string[]): string => {
    const r = spawnSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', `core.autocrlf=${autocrlf}`, ...args], {
      cwd: dir,
      encoding: 'utf8',
    });
    if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`);
    return r.stdout.trim();
  };
  git('init', '-q');
  // The repository's own setting, as a checkout's is: what git hash-object reads too.
  git('config', 'core.autocrlf', autocrlf);
  return { dir, git };
}

const BODY = 'module.exports = 1;\n';

describe('filesChangedSince', () => {
  it('unchanged, changed in a commit, changed and uncommitted, absent at the ref, deleted, and a literal [id].js', async () => {
    const { dir, git } = repo();
    mkdirSync(join(dir, 'src', 'pages'), { recursive: true });
    for (const f of ['same.js', 'committed.js', 'dirty.js', 'gone.js']) writeFileSync(join(dir, 'src', f), BODY);
    writeFileSync(join(dir, 'src', 'pages', '[id].js'), BODY);
    writeFileSync(join(dir, 'src', 'pages', 'i.js'), BODY); // what `[id].js` matches as a glob
    git('add', '-A');
    git('commit', '-qm', 'base');
    const base = git('rev-parse', 'HEAD');

    appendFileSync(join(dir, 'src', 'committed.js'), "require('child_process').exec('cat ' + process.argv[2]);\n");
    writeFileSync(join(dir, 'src', 'new.js'), BODY);
    git('add', '-A');
    git('commit', '-qm', 'pr');
    appendFileSync(join(dir, 'src', 'dirty.js'), '// uncommitted\n');
    writeFileSync(join(dir, 'src', 'untracked.js'), BODY);
    rmSync(join(dir, 'src', 'gone.js'));
    appendFileSync(join(dir, 'src', 'pages', 'i.js'), '// the glob would match me\n');

    const paths = ['src/same.js', 'src/committed.js', 'src/dirty.js', 'src/new.js', 'src/untracked.js', 'src/gone.js', 'src/pages/[id].js'];
    const r = await filesChangedSince(dir, base, paths);
    if ('error' in r) throw new Error(r.error);
    expect([...r.changed].sort()).toEqual(['src/committed.js', 'src/dirty.js', 'src/gone.js', 'src/new.js', 'src/untracked.js']);
  });

  it('a project in a subdirectory of its repository: paths relative to the project', async () => {
    const { dir, git } = repo();
    mkdirSync(join(dir, 'packages', 'api', 'src'), { recursive: true });
    writeFileSync(join(dir, 'packages', 'api', 'src', 'big.js'), BODY);
    writeFileSync(join(dir, 'packages', 'api', 'src', 'other.js'), BODY);
    git('add', '-A');
    git('commit', '-qm', 'base');
    const base = git('rev-parse', 'HEAD');
    appendFileSync(join(dir, 'packages', 'api', 'src', 'big.js'), '// pr\n');
    const r = await filesChangedSince(join(dir, 'packages', 'api'), base, ['src/big.js', 'src/other.js']);
    if ('error' in r) throw new Error(r.error);
    expect([...r.changed]).toEqual(['src/big.js']);
  });

  it.runIf(process.platform === 'win32')('a CRLF checkout of an unchanged file is unchanged', async () => {
    const { dir, git } = repo('true');
    writeFileSync(join(dir, 'a.js'), 'one\ntwo\n');
    git('add', '-A');
    git('commit', '-qm', 'base');
    const base = git('rev-parse', 'HEAD');
    writeFileSync(join(dir, 'a.js'), 'one\r\ntwo\r\n');
    const r = await filesChangedSince(dir, base, ['a.js']);
    if ('error' in r) throw new Error(r.error);
    expect([...r.changed]).toEqual([]);
  });

  it('a commit git does not know: an error, never "unchanged"', async () => {
    const { dir, git } = repo();
    writeFileSync(join(dir, 'a.js'), BODY);
    git('add', '-A');
    git('commit', '-qm', 'base');
    const r = await filesChangedSince(dir, 'f'.repeat(40), ['a.js']);
    expect('error' in r).toBe(true);
  });

  it('nothing listed: nothing to ask git', async () => {
    const r = await filesChangedSince(makeTempDir('changed-since-none-'), 'HEAD', []);
    expect(r).toEqual({ changed: new Set() });
  });

  // Review 12, finding 10: `git diff` trusts the index's flags, and a file
  // marked assume-unchanged or skip-worktree passed as unchanged with an
  // injection appended. The content is compared now.
  it('a file the index flags assume-unchanged or skip-worktree is judged by its content', async () => {
    const { dir, git } = repo();
    for (const f of ['assumed.js', 'skipped.js', 'flagged-same.js']) writeFileSync(join(dir, f), BODY);
    git('add', '-A');
    git('commit', '-qm', 'base');
    const base = git('rev-parse', 'HEAD');
    git('update-index', '--assume-unchanged', 'assumed.js', 'flagged-same.js');
    git('update-index', '--skip-worktree', 'skipped.js');
    appendFileSync(join(dir, 'assumed.js'), "require('child_process').exec('cat ' + process.argv[2]);\n");
    appendFileSync(join(dir, 'skipped.js'), "require('child_process').exec('cat ' + process.argv[2]);\n");
    // The control: git diff (what 3.4.0's first cut ran) sees neither change.
    expect(git('diff', '--name-only', base, '--')).toBe('');
    const r = await filesChangedSince(dir, base, ['assumed.js', 'skipped.js', 'flagged-same.js']);
    if ('error' in r) throw new Error(r.error);
    expect([...r.changed].sort()).toEqual(['assumed.js', 'skipped.js']);
  });
});

describe('scanSettingsCommit — what a run without a ref compares an accepted file with', () => {
  it('the last commit that changed .guardian/scan.yml', () => {
    const { dir, git } = repo();
    mkdirSync(join(dir, '.guardian'));
    writeFileSync(join(dir, '.guardian', 'scan.yml'), 'semgrep:\n  accept_timeouts:\n    - big.js\n');
    writeFileSync(join(dir, 'big.js'), BODY);
    git('add', '-A');
    git('commit', '-qm', 'accept');
    const accepted = git('rev-parse', 'HEAD');
    appendFileSync(join(dir, 'big.js'), '// later\n');
    git('commit', '-qam', 'later');
    return scanSettingsCommit(dir).then((r) => expect(r).toEqual({ commit: accepted }));
  });

  it('no commit holds it: an error (nothing reviewed it), never "unchanged"', async () => {
    const { dir, git } = repo();
    writeFileSync(join(dir, 'a.js'), BODY);
    git('add', '-A');
    git('commit', '-qm', 'base');
    mkdirSync(join(dir, '.guardian'));
    writeFileSync(join(dir, '.guardian', 'scan.yml'), 'semgrep:\n  accept_timeouts:\n    - a.js\n');
    const r = await scanSettingsCommit(dir);
    expect('error' in r && r.error).toMatch(/no commit holds \.guardian\/scan\.yml/);
  });

  it('not a git repository: nothing to compare with', async () => {
    expect(await scanSettingsCommit(makeTempDir('changed-since-nogit-'))).toEqual({ none: true });
  });
});

// Review 12, finding 11: the files the CI gate's full-content secrets pass reads whole.
describe('filesChangedFrom — the files a pull request changed', () => {
  it('added, modified, renamed in a commit or modified uncommitted; never deleted, untracked or unchanged; a skip-worktree flag hides no commit', async () => {
    const { dir, git } = repo();
    mkdirSync(join(dir, 'app', 'pages'), { recursive: true });
    for (const f of ['same.js', 'committed.js', 'dirty.js', 'gone.js', 'old-name.js', 'flagged.js']) writeFileSync(join(dir, 'app', f), `${f}\n${BODY}`);
    git('add', '-A');
    git('commit', '-qm', 'base');
    const base = git('rev-parse', 'HEAD');

    appendFileSync(join(dir, 'app', 'committed.js'), '// pr\n');
    appendFileSync(join(dir, 'app', 'flagged.js'), '// pr\n');
    writeFileSync(join(dir, 'app', 'pages', '[id].js'), BODY);
    git('mv', 'app/old-name.js', 'app/new-name.js');
    git('rm', '-q', 'app/gone.js');
    git('add', '-A');
    git('commit', '-qm', 'pr');
    git('update-index', '--skip-worktree', 'app/flagged.js');
    appendFileSync(join(dir, 'app', 'dirty.js'), '// uncommitted\n');
    writeFileSync(join(dir, 'app', 'untracked.js'), BODY);

    const r = await filesChangedFrom(join(dir, 'app'), base);
    if ('error' in r) throw new Error(r.error);
    expect(r.files).toEqual(['committed.js', 'dirty.js', 'flagged.js', 'new-name.js', 'pages/[id].js']);
  });

  it('a commit git does not know: an error, never "nothing changed"', async () => {
    const { dir, git } = repo();
    writeFileSync(join(dir, 'a.js'), BODY);
    git('add', '-A');
    git('commit', '-qm', 'base');
    expect(await filesChangedFrom(dir, 'f'.repeat(40))).toEqual({ error: expect.stringMatching(/\S/) });
  });
});
