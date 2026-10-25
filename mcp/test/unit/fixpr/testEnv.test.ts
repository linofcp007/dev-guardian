/**
 * `prepareTestEnvironment` — the fix's tree and the base-commit tree get the
 * same install, and only an install that can never reach a pull request.
 */
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { prepareTestEnvironment } from '../../../src/fixpr/testEnv.js';
import { runProcess, type ProcessRunOptions, type ProcessRunResult } from '../../../src/runners/processRunner.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const NPM_TEST = { command: 'npm', args: ['test', '--silent'], origin: 'package.json scripts.test' };

function fakeRun(ignored: boolean, install: 'completed' | 'failed' = 'completed') {
  const calls: string[] = [];
  const run = async (opts: { command: string; args?: string[] }) => {
    calls.push([opts.command, ...(opts.args ?? [])].join(' '));
    const outcome = opts.command === 'git' ? (ignored ? 'completed' : 'failed') : install;
    return { outcome, exitCode: outcome === 'completed' ? 0 : 1, stdout: '', stderr: 'npm ERR! boom\n', truncated: false };
  };
  return { run: run as never, calls };
}

describe('prepareTestEnvironment', () => {
  it('runs npm ci --ignore-scripts when there is a lockfile and node_modules is git-ignored', async () => {
    const tree = makeTempDir('testenv-');
    writeFileSync(join(tree, 'package-lock.json'), '{}');
    const { run, calls } = fakeRun(true);
    expect(await prepareTestEnvironment({ treePath: tree, derived: NPM_TEST, run })).toEqual({ ok: true, command: 'npm ci --ignore-scripts' });
    expect(calls).toEqual([`git -C ${tree} check-ignore -q node_modules/`, 'npm ci --ignore-scripts']);
  });

  it('installs nothing without a lockfile (npm install would write one into the PR)', async () => {
    const { run, calls } = fakeRun(true);
    expect(await prepareTestEnvironment({ treePath: makeTempDir('testenv-'), derived: NPM_TEST, run })).toMatchObject({ ok: true, command: null });
    expect(calls).toEqual([]);
  });

  it('installs nothing when node_modules is not git-ignored (it would be committed)', async () => {
    const tree = makeTempDir('testenv-');
    writeFileSync(join(tree, 'package-lock.json'), '{}');
    const { run, calls } = fakeRun(false);
    expect((await prepareTestEnvironment({ treePath: tree, derived: NPM_TEST, run })).command).toBeNull();
    expect(calls).toHaveLength(1);
  });

  it('prepares nothing for a non-npm test command, or none', async () => {
    const { run, calls } = fakeRun(true);
    await prepareTestEnvironment({ treePath: makeTempDir('testenv-'), derived: { command: 'cargo', args: ['test'], origin: 'Cargo.toml' }, run });
    await prepareTestEnvironment({ treePath: makeTempDir('testenv-'), derived: null, run });
    expect(calls).toEqual([]);
  });

  it('reads the commonest .gitignore — `node_modules/`, a directory pattern — before node_modules exists', async () => {
    // `git check-ignore node_modules` answers "not ignored" for a directory
    // pattern while nothing is there: no `npm ci` ran in either tree, the
    // suite failed in both for want of its dependencies, and the fix's PR
    // said "already failing … not caused by this fix".
    for (const pattern of ['node_modules/', 'node_modules', '/node_modules/']) {
      const tree = makeTempDir('testenv-git-');
      execFileSync('git', ['init', '-q', tree]);
      writeFileSync(join(tree, '.gitignore'), `${pattern}\n`);
      writeFileSync(join(tree, 'package-lock.json'), '{}');
      const npm: string[] = [];
      const run = async (opts: ProcessRunOptions): Promise<ProcessRunResult> => {
        if (opts.command !== 'npm') return runProcess(opts);
        npm.push(opts.args?.join(' ') ?? '');
        return { outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false };
      };
      expect(await prepareTestEnvironment({ treePath: tree, derived: NPM_TEST, run }), pattern)
        .toEqual({ ok: true, command: 'npm ci --ignore-scripts' });
      expect(npm, pattern).toEqual(['ci --ignore-scripts']);
    }
  });

  it('says the tree is unprepared when its dependencies could not be installed', async () => {
    // Not git-ignored: the install would be committed.
    const tree = makeTempDir('testenv-');
    writeFileSync(join(tree, 'package-lock.json'), '{}');
    const notIgnored = await prepareTestEnvironment({ treePath: tree, derived: NPM_TEST, run: fakeRun(false).run });
    expect(notIgnored).toEqual({ ok: true, command: null, unprepared: expect.stringContaining('git-ignored') });
    // No lockfile, and dependencies to install: npm install would write one.
    const bare = makeTempDir('testenv-');
    writeFileSync(join(bare, 'package.json'), '{"devDependencies":{"mocha":"^10.0.0"}}');
    const noLock = await prepareTestEnvironment({ treePath: bare, derived: NPM_TEST, run: fakeRun(true).run });
    expect(noLock).toEqual({ ok: true, command: null, unprepared: expect.stringContaining('lockfile') });
    // Nothing to install: nothing is missing.
    const none = makeTempDir('testenv-');
    writeFileSync(join(none, 'package.json'), '{"name":"x","scripts":{"test":"node t.js"}}');
    expect(await prepareTestEnvironment({ treePath: none, derived: NPM_TEST, run: fakeRun(true).run })).toEqual({ ok: true, command: null });
  });

  it('names a failed install', async () => {
    const tree = makeTempDir('testenv-');
    writeFileSync(join(tree, 'package-lock.json'), '{}');
    const { run } = fakeRun(true, 'failed');
    const r = await prepareTestEnvironment({ treePath: tree, derived: NPM_TEST, run });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain('npm ERR! boom');
  });
});
