/**
 * What a selftest prints (`src/selftest/report.ts`): a line a person can act
 * on for every control that did not detect, and the sentence that keeps the
 * hook checks honest — they prove the detectors answer, not that the host
 * runs them.
 */

import { describe, expect, it } from 'vitest';
import { HOOKS_NOTE, nextStepFor, renderJson, renderTable, type SelftestReport } from '../../../src/selftest/report.js';
import type { ControlResult, SelftestRun } from '../../../src/selftest/store.js';
import { countVerdicts } from '../../../src/selftest/verdict.js';

const CONTROLS: ControlResult[] = [
  { id: 'gitleaks', scanner: 'gitleaks', scanner_version: '8.30.1', verdict: 'detected' },
  { id: 'hooks:bash-block', scanner: 'hooks', scanner_version: '3.9.0', verdict: 'disabled_by_user', reason: 'switched off by the user: GUARDIAN_HOOKS=off' },
  { id: 'hooks:settings-guard', scanner: 'hooks', scanner_version: '3.9.0', verdict: 'silent', reason: 'the dispatcher ran and did not deny it' },
  { id: 'semgrep:bugfix-py', scanner: 'semgrep', scanner_version: '1.182.0', verdict: 'silent', reason: 'ran to the end, read the canary and did not report it' },
  { id: 'semgrep:base', scanner: 'semgrep', scanner_version: '1.182.0', verdict: 'unverified', reason: 'did not finish in 180 s' },
  { id: 'trivy:deps', scanner: 'trivy', scanner_version: null, verdict: 'missing', reason: 'trivy is not installed' },
];

function report(controls: ControlResult[] = CONTROLS): SelftestReport {
  const withNext = controls.map((c) => {
    const next = nextStepFor(c, { installCommand: 'scoop install trivy', ...(c.id === 'semgrep:bugfix-py' ? { pack: 'bugfix-py.yml' } : {}) });
    return next !== undefined ? { ...c, next } : c;
  });
  const run: SelftestRun = {
    schema: 1,
    ran_at: '2026-11-13T10:00:00.000Z',
    plugin_version: '3.9.0',
    platform: 'win32-x64',
    controls: withNext,
    no_canary: ['bandit', 'phpcs'],
    summary: { ...countVerdicts(withNext.map((c) => c.verdict)), no_canary: 2 },
    exit_code: 1,
    hooks_note: HOOKS_NOTE,
  };
  return { run, saved: { saved: true, dir: 'the data directory' } };
}

describe('the selftest report', () => {
  it('T-09 gives every control its scanner version, and every silent, unverified and missing control what to check next', () => {
    for (const c of CONTROLS) {
      const next = nextStepFor(c, { installCommand: 'scoop install trivy' });
      if (c.verdict === 'silent' || c.verdict === 'unverified' || c.verdict === 'missing') {
        expect(next, c.id).toEqual(expect.any(String));
        expect((next ?? '').length, c.id).toBeGreaterThan(20);
      } else {
        expect(next, c.id).toBeUndefined();
      }
    }
    // A missing scanner is told how it is installed; a silent pack is named.
    expect(nextStepFor(CONTROLS[5] as ControlResult, { installCommand: 'scoop install trivy' })).toContain('scoop install trivy');
    expect(nextStepFor(CONTROLS[3] as ControlResult, { pack: 'bugfix-py.yml' })).toContain('bugfix-py.yml');

    const table = renderTable(report());
    const lines = table.split('\n');
    for (const c of report().run.controls) {
      const line = lines.find((l) => l.trimStart().startsWith(`${c.id} `));
      expect(line, c.id).toBeDefined();
      expect(line, c.id).toContain(c.verdict);
      expect(line, c.id).toContain(c.scanner_version ?? '-');
      if (c.next !== undefined) expect(table, c.id).toContain(`next: ${c.next}`);
    }
    // Installed scanners with no canary are listed apart, never as a verified control.
    expect(table).toMatch(/no canary.*bandit, phpcs/);
    expect(lines.some((l) => l.trimStart().startsWith('bandit '))).toBe(false);
  });

  it('T-14 the table and the JSON both say that the hook checks do not prove the host runs the hooks', () => {
    expect(HOOKS_NOTE).toMatch(/do not prove that the host\s+runs it/);
    expect(renderTable(report())).toContain(HOOKS_NOTE);
    const json = JSON.parse(renderJson(report())) as { schema: number; hooks_note: string; controls: unknown[] };
    expect(json.schema).toBe(1);
    expect(json.hooks_note).toBe(HOOKS_NOTE);
    expect(json.controls).toHaveLength(CONTROLS.length);
    // One document: nothing before or after it.
    expect(renderJson(report()).trim().startsWith('{')).toBe(true);
    expect(renderJson(report()).trim().endsWith('}')).toBe(true);
  });
});
