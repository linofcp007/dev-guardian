/**
 * `discardCaptured` — the one way the raw values gitleaks captured are let go
 * of, on the verified path and the cancelled one alike.
 */

import { describe, expect, it } from 'vitest';

import { discardCaptured } from '../../../../src/secrets/verify/index.js';

describe('discardCaptured', () => {
  it('nulls every captured array in place (a caller may still hold one) and empties the map', () => {
    const values: Array<string | null> = ['raw-one', null, 'raw-two'];
    const other: Array<string | null> = ['raw-three'];
    const map = new Map<object, Array<string | null>>([
      [{}, values],
      [{}, other],
    ]);
    discardCaptured(map);
    expect(values).toEqual([null, null, null]);
    expect(other).toEqual([null]);
    expect(map.size).toBe(0);
  });

  it('accepts nothing captured', () => {
    expect(() => discardCaptured(undefined)).not.toThrow();
    expect(() => discardCaptured(null)).not.toThrow();
  });
});
