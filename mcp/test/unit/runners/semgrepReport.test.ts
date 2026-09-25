/**
 * Global Constraint 3 for one Semgrep run: exit 0/1 is necessary, never
 * sufficient. The report must exist, parse, have scanned something when there
 * were targets, and carry no `errors`.
 */

import { describe, expect, it } from 'vitest';
import { checkSemgrepReport } from '../../../src/runners/semgrepReport.js';

const report = (over: Record<string, unknown> = {}): string =>
  JSON.stringify({ results: [], errors: [], paths: { scanned: ['a.py'] }, ...over });

describe('checkSemgrepReport', () => {
  it('accepts exit 0 with files scanned and no errors', () => {
    expect(checkSemgrepReport({ raw: report(), exitCode: 0, outcome: 'completed', targets: 1 })).toEqual({
      ok: true,
      scanned: 1,
    });
  });

  it('accepts exit 1 (findings) the same way', () => {
    const r = checkSemgrepReport({ raw: report(), exitCode: 1, outcome: 'failed', targets: 1 });
    expect(r.ok).toBe(true);
  });

  it('fails exit 7 (registry unreachable, bad config) — never "findings"', () => {
    const raw = report({
      paths: { scanned: [] },
      errors: [{ type: 'SemgrepError', level: 'error', message: 'Failed to download configuration from https://semgrep.dev/c/auto' }],
    });
    const r = checkSemgrepReport({ raw, exitCode: 7, outcome: 'failed', targets: 3 });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/exit 7/);
    expect(r.reason).toMatch(/Failed to download configuration/);
  });

  it('fails exit 0 that scanned nothing although targets were given', () => {
    const r = checkSemgrepReport({
      raw: report({ paths: { scanned: [] } }),
      exitCode: 0,
      outcome: 'completed',
      targets: 2,
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/scanned 0 of 2/);
  });

  it('fails exit 0 with a non-empty errors array', () => {
    const raw = report({
      errors: [{ type: ['PartialParsing', []], level: 'warn', message: 'Syntax error at line broken.py:1' }],
    });
    const r = checkSemgrepReport({ raw, exitCode: 0, outcome: 'completed', targets: 1 });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/1 Semgrep error/);
    expect(r.reason).toMatch(/Syntax error/);
  });

  it('fails when no report was written, or it is not JSON', () => {
    expect(checkSemgrepReport({ raw: null, exitCode: 0, outcome: 'completed', targets: 1 }).ok).toBe(false);
    expect(checkSemgrepReport({ raw: '{nope', exitCode: 0, outcome: 'completed', targets: 1 }).ok).toBe(false);
  });

  it('fails a run that was cancelled or timed out whatever the report says', () => {
    const r = checkSemgrepReport({ raw: report(), exitCode: null, outcome: 'timed_out', targets: 1 });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/timed_out/);
  });
});
