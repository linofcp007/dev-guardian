import { describe, expect, it } from 'vitest';

import { compareVersions, isPrerelease, resolveVersion } from '../../../src/pkgvet/versions.js';

describe('compareVersions', () => {
  it('orders numerically, padding missing components with zero', () => {
    expect(compareVersions('1.10.0', '1.9.9')).toBeGreaterThan(0);
    expect(compareVersions('1.2', '1.2.0')).toBe(0);
    expect(compareVersions('v2.0.0', '1.99')).toBeGreaterThan(0);
  });
  it('puts a prerelease before its release', () => {
    expect(compareVersions('1.0.0-beta.1', '1.0.0')).toBeLessThan(0);
    expect(compareVersions('2.0.0rc1', '2.0.0')).toBeLessThan(0);
  });
});

describe('isPrerelease', () => {
  it('recognizes semver and PEP 440 prereleases', () => {
    expect(isPrerelease('1.0.0-alpha')).toBe(true);
    expect(isPrerelease('2.0.0rc1')).toBe(true);
    expect(isPrerelease('2.0.0.dev3')).toBe(true);
    expect(isPrerelease('1.0.0')).toBe(false);
    expect(isPrerelease('1.0.post1')).toBe(false);
  });
});

const NPM_VERSIONS = ['1.0.0', '1.2.3', '1.9.0', '2.0.0-beta.1', '2.0.0', '2.1.4', '3.0.0'];

describe('resolveVersion — npm', () => {
  const ctx = { versions: NPM_VERSIONS, latest: '2.1.4', tags: { latest: '2.1.4', next: '3.0.0' } };

  it('no range: the latest dist-tag', () => {
    expect(resolveVersion('npm', undefined, ctx)).toBe('2.1.4');
  });
  it('a dist-tag name resolves through the tags', () => {
    expect(resolveVersion('npm', 'next', ctx)).toBe('3.0.0');
  });
  it('an exact version resolves to itself', () => {
    expect(resolveVersion('npm', '1.2.3', ctx)).toBe('1.2.3');
  });
  it('caret, tilde, x-ranges and comparators pick the highest match', () => {
    expect(resolveVersion('npm', '^1.0.0', ctx)).toBe('1.9.0');
    expect(resolveVersion('npm', '~1.2.0', ctx)).toBe('1.2.3');
    expect(resolveVersion('npm', '1.x', ctx)).toBe('1.9.0');
    expect(resolveVersion('npm', '>=2 <3', ctx)).toBe('2.1.4');
    expect(resolveVersion('npm', '^1 || ^3', ctx)).toBe('3.0.0');
    expect(resolveVersion('npm', '1.0.0 - 1.5.0', ctx)).toBe('1.2.3');
    expect(resolveVersion('npm', '*', ctx)).toBe('2.1.4');
  });
  it('prefers the latest tag when it satisfies the range, as npm does', () => {
    expect(resolveVersion('npm', '>=1', ctx)).toBe('2.1.4');
  });
  it('never picks a prerelease for a range', () => {
    expect(resolveVersion('npm', '>=2.0.0-0 <2.0.1', { versions: ['2.0.0-beta.1'], latest: undefined, tags: {} })).toBeUndefined();
  });
  it('caret on 0.x is minor-locked', () => {
    expect(resolveVersion('npm', '^0.2.0', { versions: ['0.2.1', '0.3.0'], latest: '0.3.0', tags: {} })).toBe('0.2.1');
  });
  it('returns undefined when nothing matches or the range cannot be parsed', () => {
    expect(resolveVersion('npm', '^9', ctx)).toBeUndefined();
    expect(resolveVersion('npm', 'not a range!', ctx)).toBeUndefined();
  });
});

describe('resolveVersion — PyPI', () => {
  const ctx = { versions: ['1.0', '1.4.2', '1.4.9', '1.5.0', '2.0.0rc1', '2.0.0'], latest: '2.0.0', tags: {} };
  it('no specifier: latest', () => {
    expect(resolveVersion('pypi', undefined, ctx)).toBe('2.0.0');
  });
  it('== pins, including the wildcard form', () => {
    expect(resolveVersion('pypi', '==1.4.2', ctx)).toBe('1.4.2');
    expect(resolveVersion('pypi', '==1.4.*', ctx)).toBe('1.4.9');
  });
  it('comma-separated specifiers are ANDed', () => {
    expect(resolveVersion('pypi', '>=1.0,<2', ctx)).toBe('1.5.0');
    expect(resolveVersion('pypi', '>=1.0,!=1.5.0,<2', ctx)).toBe('1.4.9');
  });
  it('~= is a compatible release', () => {
    expect(resolveVersion('pypi', '~=1.4.2', ctx)).toBe('1.4.9');
    expect(resolveVersion('pypi', '~=1.4', ctx)).toBe('1.5.0');
  });
});

describe('resolveVersion — Composer', () => {
  const ctx = { versions: ['v1.0.0', '1.2.0', '2.0.0', '2.3.1', '3.0.0-RC1', 'dev-main'], latest: undefined, tags: {} };
  it('no constraint: the highest stable', () => {
    expect(resolveVersion('packagist', undefined, ctx)).toBe('2.3.1');
  });
  it('^, ~ (composer semantics), wildcards and ||', () => {
    expect(resolveVersion('packagist', '^1.0', ctx)).toBe('1.2.0');
    expect(resolveVersion('packagist', '~1.0', ctx)).toBe('1.2.0');
    expect(resolveVersion('packagist', '2.*', ctx)).toBe('2.3.1');
    expect(resolveVersion('packagist', '^1.0 || ^2.0', ctx)).toBe('2.3.1');
    expect(resolveVersion('packagist', '>=1.0 <2.0', ctx)).toBe('1.2.0');
  });
  it('a dev branch constraint is not resolved', () => {
    expect(resolveVersion('packagist', 'dev-main', ctx)).toBeUndefined();
  });
});

describe('resolveVersion — NuGet', () => {
  const ctx = { versions: ['12.0.1', '13.0.1', '13.0.3', '14.0.0-beta'], latest: undefined, tags: {} };
  it('no version: highest stable', () => {
    expect(resolveVersion('nuget', undefined, ctx)).toBe('13.0.3');
  });
  it('a plain version is exact; interval notation is supported', () => {
    expect(resolveVersion('nuget', '13.0.1', ctx)).toBe('13.0.1');
    expect(resolveVersion('nuget', '[12.0,13.0.2)', ctx)).toBe('13.0.1');
    expect(resolveVersion('nuget', '[13.0.3]', ctx)).toBe('13.0.3');
  });
});
