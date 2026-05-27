import { describe, expect, it } from 'vitest';
import { detectOs } from '../../../src/platform/osDetect.js';

describe('detectOs', () => {
  it('maps process.platform to a DetectedOs value', () => {
    const result = detectOs();
    expect(['linux', 'darwin', 'win32', 'unsupported']).toContain(result);
  });

  it('returns the same value as process.platform for supported OSes', () => {
    const expected = ['linux', 'darwin', 'win32'].includes(process.platform)
      ? process.platform
      : 'unsupported';
    expect(detectOs()).toBe(expected);
  });
});
