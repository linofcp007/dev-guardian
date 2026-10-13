/**
 * `ci/renames.ts` against a real git repository (review 8, finding 6): which
 * files were renamed since the baseline was recorded — committed or staged.
 */
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { renamesSince } from '../../../src/ci/renames.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

function repo(): { dir: string; git: (...args: string[]) => string } {
  const dir = makeTempDir('renames-');
  const git = (...args: string[]): string => {
    const r = spawnSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'core.autocrlf=false', ...args], {
      cwd: dir,
      encoding: 'utf8',
    });
    if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`);
    return r.stdout.trim();
  };
  git('init', '-q');
  return { dir, git };
}

const BODY = Array.from({ length: 20 }, (_, i) => `const line${i} = ${i};`).join('\n') + '\n';

describe('renamesSince', () => {
  it('a file renamed since the commit that last wrote the baseline — committed, then one staged', async () => {
    const { dir, git } = repo();
    mkdirSync(join(dir, 'src'), { recursive: true });
    writeFileSync(join(dir, 'src', 'app.js'), BODY);
    writeFileSync(join(dir, 'src', 'util.js'), BODY.replace('line0', 'other0'));
    mkdirSync(join(dir, '.guardian'));
    writeFileSync(join(dir, '.guardian', 'baseline.json'), '{"version":1,"generated_at":"x","entries":[]}\n');
    git('add', '-A');
    git('commit', '-qm', 'baseline');
    mkdirSync(join(dir, 'lib'));
    git('mv', 'src/app.js', 'lib/app.js');
    git('commit', '-qm', 'move');
    git('mv', 'src/util.js', 'lib/util.js'); // staged, not committed

    const map = await renamesSince(dir, null);
    expect(map.get('lib/app.js')).toBe('src/app.js');
    expect(map.get('lib/util.js')).toBe('src/util.js');
  });

  it('from a ref: renames between that commit and now; a sub-project gets its own relative paths', async () => {
    const { dir, git } = repo();
    mkdirSync(join(dir, 'packages', 'api', 'src'), { recursive: true });
    writeFileSync(join(dir, 'packages', 'api', 'src', 'a.js'), BODY);
    git('add', '-A');
    git('commit', '-qm', 'one');
    const base = git('rev-parse', 'HEAD');
    git('mv', 'packages/api/src/a.js', 'packages/api/src/b.js');
    git('commit', '-qm', 'two');
    const map = await renamesSince(join(dir, 'packages', 'api'), base);
    expect([...map]).toEqual([['src/b.js', 'src/a.js']]);
  });

  it('nothing for a directory that is not a repository, or with no commits', async () => {
    expect((await renamesSince(makeTempDir('renames-none-'), null)).size).toBe(0);
    const { dir } = repo();
    expect((await renamesSince(dir, null)).size).toBe(0);
  });
});
