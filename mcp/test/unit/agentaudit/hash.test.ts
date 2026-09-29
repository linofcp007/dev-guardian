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

/**
 * Fix round 5 (Part A, I-1): the serialiser recursed — a value 6000 arrays
 * deep (~12 KB) threw `RangeError: Maximum call stack size exceeded` and
 * took a whole audit down. It is iterative now, and must keep producing the
 * EXACT string the recursive form produced: agent_config_hashes (shipped in
 * 2.0) stores hashes of it, and a different string would read as a changed
 * entry.
 */
describe('stableStringify: iterative, byte-identical to the recursive form', () => {
  function reference(value: unknown): string {
    const sortKeys = (v: unknown): unknown => {
      if (Array.isArray(v)) return v.map(sortKeys);
      if (v !== null && typeof v === 'object') {
        const out: Record<string, unknown> = {};
        for (const k of Object.keys(v as Record<string, unknown>).sort()) out[k] = sortKeys((v as Record<string, unknown>)[k]);
        return out;
      }
      return v;
    };
    return JSON.stringify(sortKeys(value));
  }

  it.each([
    ['a config entry', { command: 'npx', args: ['-y', 'pkg@1.2.3'], env: { B: '2', A: '1' }, type: 'stdio' }],
    ['nesting, arrays and every JSON scalar', { z: [1, 2.5, -0, 1e21, true, false, null, 'é"\n '], a: { c: [], b: {} } }],
    ['unicode keys in code-unit order', { é: 1, e: 2, E: 3, '\u{1F600}': 4, '': 5 }],
    ['what JSON.stringify drops or nulls', { u: undefined, f: () => 1, arr: [undefined, () => 1, NaN, Infinity] }],
    ['a schema', { type: 'object', properties: { path: { type: 'string', enum: ['a', 'b'], default: 'a' } }, required: ['path'] }],
  ])('%s', (_what, value) => {
    expect(stableStringify(value)).toBe(reference(value));
  });

  it('serialises a value 6000 arrays deep without overflowing the stack', () => {
    const deep: unknown = JSON.parse(`${'['.repeat(6000)}${']'.repeat(6000)}`);
    expect(() => hashConfigValue({ v: deep })).not.toThrow();
    expect(stableStringify({ v: deep })).toBe(`{"v":${'['.repeat(6000)}${']'.repeat(6000)}}`);
  });
});
