/**
 * `comparePhpVersions` / `versionInRange` — WordPress plugin versions are not
 * semver (`1.2`, `1.2.3.4`, `-beta`, `2.0-RC1` all appear in the wild), so
 * matching against the Wordfence feed's `affected_versions` ranges needs
 * PHP's own `version_compare()` ordering, not a semver library. Verified
 * against `wordfence/wordfence-cli`'s `wordfence/util/versioning.py`
 * (`compare_php_versions`), which itself mirrors PHP's documented order:
 * `dev < alpha = a < beta = b < RC = rc < (no suffix) < pl = p`.
 */

import { describe, expect, it } from 'vitest';
import { comparePhpVersions, versionInRange, type WordfenceVersionRange } from '../../../src/wordpress/vulnFeed.js';

describe('comparePhpVersions', () => {
  it('treats missing trailing components as zero', () => {
    expect(comparePhpVersions('1.2', '1.2.0')).toBe(0);
    expect(comparePhpVersions('1.2.0.0', '1.2')).toBe(0);
  });

  it('orders numerically, not lexically', () => {
    expect(comparePhpVersions('1.9', '1.10')).toBe(-1);
    expect(comparePhpVersions('1.10', '1.9')).toBe(1);
  });

  it('a plain release outranks a pre-release of the same numbers', () => {
    expect(comparePhpVersions('1.0.0', '1.0.0-beta')).toBe(1);
    expect(comparePhpVersions('1.0.0-beta', '1.0.0')).toBe(-1);
  });

  it('orders pre-release tiers dev < alpha < beta < RC < release', () => {
    expect(comparePhpVersions('1.0-dev', '1.0-alpha')).toBe(-1);
    expect(comparePhpVersions('1.0-alpha', '1.0-beta')).toBe(-1);
    expect(comparePhpVersions('1.0-beta', '1.0-RC1')).toBe(-1);
    expect(comparePhpVersions('1.0-rc1', '1.0')).toBe(-1);
  });

  it('treats alpha/a, beta/b and RC/rc as equal ranks', () => {
    expect(comparePhpVersions('1.0-alpha', '1.0-a')).toBe(0);
    expect(comparePhpVersions('1.0-beta1', '1.0-b1')).toBe(0);
    expect(comparePhpVersions('1.0-RC1', '1.0-rc1')).toBe(0);
  });

  it('a patch level (pl/p) outranks the plain release', () => {
    expect(comparePhpVersions('1.0.0', '1.0.0-pl1')).toBe(-1);
    expect(comparePhpVersions('1.0.0pl1', '1.0.0p1')).toBe(0);
  });

  it('handles a 4-component version against a 3-component one', () => {
    expect(comparePhpVersions('1.2.3.4', '1.2.3')).toBe(1);
    expect(comparePhpVersions('1.2.3', '1.2.3.1')).toBe(-1);
  });

  it('is equal for two identical versions', () => {
    expect(comparePhpVersions('5.3.1', '5.3.1')).toBe(0);
  });

  it('treats underscores and plus signs as delimiters, like PHP does', () => {
    expect(comparePhpVersions('1.2_3', '1.2.3')).toBe(0);
    expect(comparePhpVersions('1.2+3', '1.2.3')).toBe(0);
  });
});

describe('versionInRange', () => {
  const range = (over: Partial<WordfenceVersionRange> = {}): WordfenceVersionRange => ({
    from_version: '0',
    from_inclusive: true,
    to_version: '*',
    to_inclusive: true,
    ...over,
  });

  it('an unbounded range ("*" on both ends) includes anything', () => {
    expect(versionInRange('1.0', range({ from_version: '*', to_version: '*' }))).toBe(true);
    expect(versionInRange('99.0', range({ from_version: '*', to_version: '*' }))).toBe(true);
  });

  it('excludes a version below an inclusive lower bound', () => {
    const r = range({ from_version: '2.0', from_inclusive: true, to_version: '3.0', to_inclusive: true });
    expect(versionInRange('1.9', r)).toBe(false);
    expect(versionInRange('2.0', r)).toBe(true);
  });

  it('excludes the upper bound itself when it is exclusive', () => {
    const r = range({ from_version: '1.0', from_inclusive: true, to_version: '2.0', to_inclusive: false });
    expect(versionInRange('2.0', r)).toBe(false);
    expect(versionInRange('1.9.9', r)).toBe(true);
  });

  it('includes the upper bound when it is inclusive', () => {
    const r = range({ from_version: '1.0', from_inclusive: true, to_version: '2.0', to_inclusive: true });
    expect(versionInRange('2.0', r)).toBe(true);
  });

  it('a version strictly inside an exclusive/exclusive range is included', () => {
    const r = range({ from_version: '1.0', from_inclusive: false, to_version: '2.0', to_inclusive: false });
    expect(versionInRange('1.0', r)).toBe(false);
    expect(versionInRange('1.5', r)).toBe(true);
    expect(versionInRange('2.0', r)).toBe(false);
  });

  it('a pre-release installed version is correctly placed relative to a release boundary', () => {
    // "< 2.0" must exclude "2.0-beta"? No: 2.0-beta < 2.0, so it IS included.
    const r = range({ from_version: '1.0', from_inclusive: true, to_version: '2.0', to_inclusive: false });
    expect(versionInRange('2.0-beta', r)).toBe(true);
  });
});
