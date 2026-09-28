import { describe, expect, it } from 'vitest';
import {
  compareVersions,
  compareVersionsLoose,
  isCleanVersion,
  isLooseVersion,
  minCleanVersionAbove,
  minCleanVersionAboveLoose,
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

// ------------------------------------------------------------ fix round 3, item N2

describe('isLooseVersion', () => {
  it('accepts everything isCleanVersion does, plus a pre-release suffix', () => {
    expect(isLooseVersion('1.2.3')).toBe(true);
    expect(isLooseVersion('2.0.0-beta.1')).toBe(true);
    expect(isLooseVersion('v1.0.0-rc.2')).toBe(true);
  });

  it('still rejects ranges, lists and free text', () => {
    expect(isLooseVersion('>=4.17.11')).toBe(false);
    expect(isLooseVersion(undefined)).toBe(false);
  });
});

describe('compareVersionsLoose', () => {
  it('a pre-release is below the same core with no suffix', () => {
    expect(compareVersionsLoose('2.0.0-beta.1', '2.0.0')).toBeLessThan(0);
    expect(compareVersionsLoose('2.0.0', '2.0.0-beta.1')).toBeGreaterThan(0);
  });

  it('a pre-release core below a later release core is below it regardless of the suffix', () => {
    // The coordinator's own example: 2.0.0-beta.1 < 2.0.1.
    expect(compareVersionsLoose('2.0.0-beta.1', '2.0.1')).toBeLessThan(0);
  });

  it('compares pre-release identifiers segment by segment, numeric segments numerically', () => {
    expect(compareVersionsLoose('2.0.0-beta.2', '2.0.0-beta.10')).toBeLessThan(0); // not lexical
    expect(compareVersionsLoose('2.0.0-alpha', '2.0.0-beta')).toBeLessThan(0);
  });
});

describe('minCleanVersionAboveLoose — never mislabel a pre-release install as already_fixed (item N2)', () => {
  it('recognises a clean fix as above a pre-release install via loose core comparison', () => {
    // Reproduced from the review: installed 2.0.0-beta.1, a clean fix of
    // 2.0.1 is genuinely above it — `minCleanVersionAbove` (strict) rejects
    // the pre-release install outright and returns undefined, which the
    // caller used to read as "already fixed". It is not: the fix is real.
    expect(minCleanVersionAboveLoose('2.0.0-beta.1', ['2.0.1'])).toBe('2.0.1');
  });

  it('still excludes a candidate at or below a pre-release install, but the release of the SAME core is above its own pre-release', () => {
    expect(minCleanVersionAboveLoose('2.0.0-beta.1', ['2.0.0', '1.9.0'])).toBe('2.0.0');
    // The final release of the same core IS above its own pre-release —
    // 2.0.1 > 2.0.1-beta.1, per semver's own pre-release precedence rule.
    expect(minCleanVersionAboveLoose('2.0.1-beta.1', ['2.0.1'])).toBe('2.0.1');
    // But the pre-release's own core is not above the SAME candidate a
    // second time (equal-or-below is still excluded).
    expect(minCleanVersionAboveLoose('2.0.1', ['2.0.1'])).toBeUndefined();
  });

  it('never proposes a pre-release CANDIDATE as the fix, even above a clean install', () => {
    expect(minCleanVersionAboveLoose('1.0.0', ['1.1.0-rc.1', '1.1.0'])).toBe('1.1.0');
  });

  it('returns undefined when installed is not even loosely a version', () => {
    expect(minCleanVersionAboveLoose('>=4.17.11', ['4.17.19'])).toBeUndefined();
  });
});
