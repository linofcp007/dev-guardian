import { describe, expect, it } from 'vitest';
import { compareSemver, meetsFloor } from '../../../src/platform/semverCompare.js';

describe('compareSemver', () => {
  it('returns negative when a < b on major', () => {
    expect(compareSemver('1.0.0', '2.0.0')).toBeLessThan(0);
  });
  it('returns positive when a > b on minor', () => {
    expect(compareSemver('1.5.0', '1.2.99')).toBeGreaterThan(0);
  });
  it('returns zero on equal versions', () => {
    expect(compareSemver('3.4.5', '3.4.5')).toBe(0);
  });
  it('tolerates `v` prefix', () => {
    expect(compareSemver('v1.2.3', '1.2.3')).toBe(0);
  });
  it('treats missing patch as 0', () => {
    expect(compareSemver('1.2', '1.2.0')).toBe(0);
  });
  it('ignores pre-release tags', () => {
    expect(compareSemver('1.2.3-rc1', '1.2.3')).toBe(0);
  });
  it('returns null on garbage', () => {
    expect(compareSemver('not-a-version', '1.0.0')).toBeNull();
  });
});

describe('meetsFloor', () => {
  it('returns true for equal versions', () => {
    expect(meetsFloor('1.0.0', '1.0.0')).toBe(true);
  });
  it('returns true for installed > floor', () => {
    expect(meetsFloor('2.0.0', '1.0.0')).toBe(true);
  });
  it('returns false for installed < floor', () => {
    expect(meetsFloor('0.9.0', '1.0.0')).toBe(false);
  });
  it('returns null when either side is unparseable', () => {
    expect(meetsFloor('unknown', '1.0.0')).toBeNull();
  });
});
