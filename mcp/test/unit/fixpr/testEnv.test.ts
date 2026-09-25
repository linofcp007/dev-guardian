/**
 * `prepareTestEnvironment` — the fix's tree and the base-commit tree get the
 * same install, and only an install that can never reach a pull request.
 */
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { prepareTestEnvironment } from '../../../src/fixpr/testEnv.js';
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
    expect(calls).toEqual([`git -C ${tree} check-ignore -q node_modules`, 'npm ci --ignore-scripts']);
  });

  it('installs nothing without a lockfile (npm install would write one into the PR)', async () => {
    const { run, calls } = fakeRun(true);
    expect(await prepareTestEnvironment({ treePath: makeTempDir('testenv-'), derived: NPM_TEST, run })).toEqual({ ok: true, command: null });
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

  it('names a failed install', async () => {
    const tree = makeTempDir('testenv-');
    writeFileSync(join(tree, 'package-lock.json'), '{}');
    const { run } = fakeRun(true, 'failed');
    const r = await prepareTestEnvironment({ treePath: tree, derived: NPM_TEST, run });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain('npm ERR! boom');
  });
});
