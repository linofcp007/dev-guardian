/**
 * `projectTreeState` — the project's place in its repository and the files
 * that differ from HEAD (create_fix_pr never verifies a target in one).
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { projectTreeState } from '../../../src/fixpr/treeState.js';
import { resolveProjectPath } from '../../../src/platform/projectPath.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

describe('projectTreeState', () => {
  it('never takes git\'s optional index lock (the user\'s git or IDE may hold it)', async () => {
    const calls: string[][] = [];
    const run = async (opts: { command: string; args?: string[] }) => {
      calls.push(opts.args ?? []);
      return { outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false };
    };
    await projectTreeState('/p', run as never);
    const status = calls.find((a) => a.includes('status'));
    expect(status).toBeDefined();
    expect(status?.indexOf('--no-optional-locks')).toBeLessThan(status?.indexOf('status') ?? -1);
    expect(status?.[0]).toBe('--no-optional-locks');
  });

  it('names modified, untracked and renamed files (both sides), repository-root relative, from a subdirectory', async () => {
    const repo = makeTempDir('treestate-');
    const git = (...args: string[]): void => {
      execFileSync('git', ['-C', repo, ...args], { stdio: 'ignore' });
    };
    git('init', '-q');
    git('config', 'core.autocrlf', 'false');
    mkdirSync(join(repo, 'app', 'src'), { recursive: true });
    writeFileSync(join(repo, 'app', 'src', 'a.js'), 'a\n');
    writeFileSync(join(repo, 'app', 'old.js'), 'o\n');
    writeFileSync(join(repo, 'app', 'clean.js'), 'c\n');
    git('add', '.');
    git('-c', 'user.email=t@example.com', '-c', 'user.name=T', 'commit', '-q', '-m', 'x');
    writeFileSync(join(repo, 'app', 'src', 'a.js'), 'changed\n');
    writeFileSync(join(repo, 'app', 'new.js'), 'n\n');
    renameSync(join(repo, 'app', 'old.js'), join(repo, 'app', 'moved.js'));
    git('add', '-A', 'app/old.js', 'app/moved.js');

    const state = await projectTreeState(resolveProjectPath(join(repo, 'app')).path);
    expect(state.ok).toBe(true);
    if (!state.ok) return;
    expect(state.prefix).toBe('app/');
    expect([...state.dirty].sort()).toEqual(['app/moved.js', 'app/new.js', 'app/old.js', 'app/src/a.js']);
  });

  it('fails, rather than answering "nothing changed", when git cannot tell', async () => {
    const run = async () => ({ outcome: 'failed', exitCode: 128, stdout: '', stderr: 'fatal: detected dubious ownership', truncated: false });
    const state = await projectTreeState('/p', run as never);
    expect(state.ok).toBe(false);
  });
});
