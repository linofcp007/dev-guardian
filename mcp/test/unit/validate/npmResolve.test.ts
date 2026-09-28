/**
 * Which version of an npm package some code loads — Node's lookup, read from
 * the lockfile beside the manifest, else from the installed tree. What lets
 * the dependency provider tell the vulnerable copy (`node_modules/x/
 * node_modules/lodash` 4.17.20) from the one the code resolves
 * (`node_modules/lodash` 4.17.21).
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { makeNpmResolver } from '../../../src/validate/npmResolve.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

function write(root: string, rel: string, content: unknown): void {
  const path = join(root, ...rel.split('/'));
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, typeof content === 'string' ? content : JSON.stringify(content), 'utf8');
}

describe('makeNpmResolver — package-lock.json v2/v3', () => {
  const root = makeTempDir('guardian-npm-resolve-');
  write(root, 'package-lock.json', {
    lockfileVersion: 3,
    packages: {
      '': { name: 'mono', workspaces: ['packages/*'] },
      'node_modules/lodash': { version: '4.17.21' },
      'node_modules/x': { version: '1.0.0' },
      'node_modules/x/node_modules/lodash': { version: '4.17.20' },
      'node_modules/api': { resolved: 'packages/api', link: true },
      'packages/api/node_modules/lodash': { version: '4.17.19' },
      'node_modules/@babel/core': { version: '7.22.0' },
    },
  });
  const resolve = makeNpmResolver(root);

  it('resolves the hoisted copy for code at the root, not a nested one', () => {
    expect(resolve('src/lib', '', 'lodash')).toEqual({ version: '4.17.21', source: 'package-lock.json' });
  });

  it('resolves a workspace’s own copy for code inside that workspace', () => {
    expect(resolve('packages/api/src', '', 'lodash')?.version).toBe('4.17.19');
  });

  it('handles a scoped name, and answers null for a package not installed where the code looks', () => {
    expect(resolve('src', '', '@babel/core')?.version).toBe('7.22.0');
    expect(resolve('src', '', 'left-pad')).toBeNull();
  });

  it('answers null for code outside the manifest’s directory', () => {
    expect(resolve('src', 'packages/api', 'lodash')).toBeNull();
  });
});

describe('makeNpmResolver — lockfile v1, the installed tree, nothing', () => {
  it('reads a v1 lockfile’s top-level dependencies', () => {
    const root = makeTempDir('guardian-npm-resolve-v1-');
    write(root, 'legacy/package-lock.json', {
      lockfileVersion: 1,
      dependencies: { lodash: { version: '4.17.15', dependencies: { minimist: { version: '0.0.8' } } } },
    });
    const resolve = makeNpmResolver(root);
    expect(resolve('legacy/lib', 'legacy', 'lodash')).toEqual({ version: '4.17.15', source: 'legacy/package-lock.json' });
    expect(resolve('legacy/lib', 'legacy', 'minimist')).toBeNull();
  });

  it('falls back to the installed package.json when there is no lockfile', () => {
    const root = makeTempDir('guardian-npm-resolve-installed-');
    write(root, 'app/node_modules/lodash/package.json', { name: 'lodash', version: '4.17.11' });
    const resolve = makeNpmResolver(root);
    expect(resolve('app/src', 'app', 'lodash'))
      .toEqual({ version: '4.17.11', source: 'app/node_modules/lodash/package.json' });
  });

  it('answers null with neither, and for a lockfile that is not JSON', () => {
    const bare = makeTempDir('guardian-npm-resolve-bare-');
    expect(makeNpmResolver(bare)('src', '', 'lodash')).toBeNull();
    const broken = makeTempDir('guardian-npm-resolve-broken-');
    write(broken, 'package-lock.json', '{ not json');
    expect(makeNpmResolver(broken)('src', '', 'lodash')).toBeNull();
  });
});
