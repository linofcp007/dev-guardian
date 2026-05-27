import { describe, expect, it } from 'vitest';
import { computeFingerprint } from '../../../src/fingerprint/findingFingerprint.js';

describe('computeFingerprint', () => {
  it('is deterministic across runs', () => {
    const input = {
      tool: 'semgrep',
      rule_id: 'rule.x',
      file_path: 'src/app.ts',
      line_start: 10,
      line_end: 12,
      snippet: 'eval(input)',
    };
    expect(computeFingerprint(input)).toBe(computeFingerprint(input));
  });

  it('returns the same fingerprint for Windows-native and POSIX paths of the same file', () => {
    const base = {
      tool: 'semgrep',
      rule_id: 'rule.x',
      line_start: 10,
      line_end: 12,
      snippet: 'eval(input)',
    };
    const win = computeFingerprint({ ...base, file_path: 'C:\\proj\\src\\app.ts' });
    const posix = computeFingerprint({ ...base, file_path: '/proj/src/app.ts' });
    expect(win).toBe(posix);
  });

  it('is case-insensitive on the tool name', () => {
    const a = computeFingerprint({ tool: 'semgrep' });
    const b = computeFingerprint({ tool: 'SEMGREP' });
    expect(a).toBe(b);
  });

  it('changes when the line range changes', () => {
    const a = computeFingerprint({ tool: 'semgrep', file_path: 'a.ts', line_start: 1, line_end: 2 });
    const b = computeFingerprint({ tool: 'semgrep', file_path: 'a.ts', line_start: 1, line_end: 3 });
    expect(a).not.toBe(b);
  });

  it('changes when snippet bytes differ inside the 1 KB window', () => {
    const a = computeFingerprint({ tool: 'semgrep', file_path: 'a.ts', snippet: 'x' });
    const b = computeFingerprint({ tool: 'semgrep', file_path: 'a.ts', snippet: 'y' });
    expect(a).not.toBe(b);
  });

  it('is stable to snippet bytes beyond the 1 KB cap', () => {
    const filler = 'a'.repeat(1024);
    const a = computeFingerprint({ tool: 'semgrep', file_path: 'a.ts', snippet: filler });
    const b = computeFingerprint({
      tool: 'semgrep',
      file_path: 'a.ts',
      snippet: filler + 'extra-bytes-ignored',
    });
    expect(a).toBe(b);
  });

  it('handles missing rule_id / snippet without throwing', () => {
    const fp = computeFingerprint({ tool: 'gitleaks', file_path: 'src/secret.ts', line_start: 1 });
    expect(fp).toMatch(/^[0-9a-f]{64}$/);
  });
});
