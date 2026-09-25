import { describe, expect, it } from 'vitest';
import {
  compareVersions,
  isCleanVersion,
  minCleanVersionAbove,
} from '../../../src/deps/versionCompare.js';

describe('isCleanVersion', () => {
  it('accepts dotted-number versions, optionally v-prefixed', () => {
    expect(isCleanVersion('1.2.3')).toBe(true);
    expect(isCleanVersion('v1.2.3')).toBe(true);
    expect(isCleanVersion('1')).toBe(true);
    expect(isCleanVersion('1.2')).toBe(true);
  });

  it('rejects ranges, lists and free text', () => {
    expect(isCleanVersion('>=4.17.11')).toBe(false);
    expect(isCleanVersion('4.17.12, 5.0.0')).toBe(false);
    expect(isCleanVersion(undefined)).toBe(false);
    expect(isCleanVersion('')).toBe(false);
  });
});

describe('compareVersions', () => {
  it('compares numerically, not lexically (1.10.0 > 1.2.0)', () => {
    expect(compareVersions('1.10.0', '1.2.0')).toBeGreaterThan(0);
    expect(compareVersions('1.2.0', '1.10.0')).toBeLessThan(0);
    expect(compareVersions('1.2.3', '1.2.3')).toBe(0);
  });
});

describe('minCleanVersionAbove — the CRITICAL downgrade guard (fix round 1, item 1)', () => {
  it("picks the smallest candidate ABOVE installed — never pip-audit's fix_versions[0] when that is an older branch's backport", () => {
    // Reproduced from the review: installed 2.0.1, pip-audit reports fixes
    // for three maintained branches — 1.11.27 (an OLDER line's backport),
    // 2.2.9 (the fix for the 2.x line actually installed) and 3.0.1.
    const target = minCleanVersionAbove('2.0.1', ['1.11.27', '2.2.9', '3.0.1']);
    expect(target).toBe('2.2.9');
  });

  it('excludes every candidate at or below the installed version', () => {
    expect(minCleanVersionAbove('2.0.1', ['1.11.27', '1.9.0'])).toBeUndefined();
    expect(minCleanVersionAbove('2.0.1', ['2.0.1'])).toBeUndefined(); // equal = not a fix
  });

  it('ignores messy (non-clean) candidates rather than crashing or misordering them', () => {
    expect(minCleanVersionAbove('3.10.1', ['>=4.17.11', '4.17.19'])).toBe('4.17.19');
  });

  it('returns undefined when installed itself is not a clean version', () => {
    expect(minCleanVersionAbove('not-a-version', ['4.17.19'])).toBeUndefined();
  });

  it('returns undefined for an empty candidate list', () => {
    expect(minCleanVersionAbove('1.0.0', [])).toBeUndefined();
  });
});
