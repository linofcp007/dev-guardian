import { describe, expect, it } from 'vitest';
import {
  firstWindowsAvailable,
  windowsCandidates,
  WINDOWS_CANDIDATES_ORDER,
} from '../../../src/platform/pkgManagerDetect.js';

describe('pkgManagerDetect (Windows)', () => {
  it('probes candidates in the documented order', async () => {
    const calls: string[] = [];
    const result = await windowsCandidates({
      resolveBinary: async (name) => {
        calls.push(name);
        return null;
      },
    });
    expect(calls).toEqual([...WINDOWS_CANDIDATES_ORDER]);
    expect(result.every((c) => c.available === false)).toBe(true);
  });

  it('marks a candidate available when the resolver returns a path', async () => {
    const result = await windowsCandidates({
      resolveBinary: async (name) =>
        name === 'scoop' ? 'C:\\Users\\you\\scoop\\shims\\scoop.cmd' : null,
    });
    const scoop = result.find((c) => c.name === 'scoop');
    expect(scoop?.available).toBe(true);
    expect(scoop?.command_path).toMatch(/scoop\.cmd$/);
  });

  it('firstWindowsAvailable returns the highest-priority resolved manager', async () => {
    const result = await firstWindowsAvailable({
      resolveBinary: async (name) =>
        name === 'choco' || name === 'scoop' ? `/fake/${name}` : null,
    });
    expect(result?.name).toBe('scoop');
  });

  it('firstWindowsAvailable returns null when nothing is reachable', async () => {
    expect(await firstWindowsAvailable({ resolveBinary: async () => null })).toBeNull();
  });
});
