import { describe, expect, it } from 'vitest';
import { hashConfigValue, stableStringify } from '../../../src/agentaudit/hash.js';

describe('stableStringify', () => {
  it('sorts object keys recursively so key order never changes the output', () => {
    const a = stableStringify({ b: 1, a: { d: 2, c: 3 } });
    const b = stableStringify({ a: { c: 3, d: 2 }, b: 1 });
    expect(a).toBe(b);
  });

  it('preserves array order (arrays are not sorted)', () => {
    expect(stableStringify(['b', 'a'])).toBe(stableStringify(['b', 'a']));
    expect(stableStringify(['b', 'a'])).not.toBe(stableStringify(['a', 'b']));
  });
});

describe('hashConfigValue', () => {
  it('is deterministic and independent of key order', () => {
    const h1 = hashConfigValue({ command: 'npx', args: ['-y', 'pkg'] });
    const h2 = hashConfigValue({ args: ['-y', 'pkg'], command: 'npx' });
    expect(h1).toBe(h2);
  });

  it('changes when the value changes', () => {
    const h1 = hashConfigValue({ command: 'npx', args: ['-y', 'pkg'] });
    const h2 = hashConfigValue({ command: 'npx', args: ['-y', 'pkg@1.0.0'] });
    expect(h1).not.toBe(h2);
  });

  it('returns a hex sha256 string', () => {
    const h = hashConfigValue({ x: 1 });
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });
});
