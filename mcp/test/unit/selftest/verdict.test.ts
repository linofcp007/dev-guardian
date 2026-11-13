/**
 * The selftest's verdict is a pure function of what was observed
 * (`src/selftest/verdict.ts`), and the observation space is small enough to
 * walk whole: every combination is judged here, not a sample of them.
 *
 * What these hold: a control is `detected` or `silent` only when its run
 * ended well — a run that failed, timed out, was partial or never ran can say
 * neither —, and the command's exit code is 1 exactly when something is
 * silent.
 */

import { describe, expect, it } from 'vitest';
import { RUN_ENDS, VERDICTS, exitCodeFor, judgeControl, type Observation, type Verdict } from '../../../src/selftest/verdict.js';

/** Every observation there is: 2 × 5 × 3 × 2 × 2. */
function everyObservation(): Observation[] {
  const out: Observation[] = [];
  for (const installed of [true, false]) {
    for (const ended of RUN_ENDS) {
      for (const canaryRead of [true, false, null]) {
        for (const canaryReported of [true, false]) {
          for (const softenedBy of [undefined, 'GUARDIAN_HOOKS=off']) {
            out.push({ installed, ended, canaryRead, canaryReported, ...(softenedBy !== undefined ? { softenedBy } : {}) });
          }
        }
      }
    }
  }
  return out;
}

/** Every list of verdicts with each verdict present 0, 1 or 2 times: 3^6. */
function everyVerdictList(): Verdict[][] {
  let lists: Verdict[][] = [[]];
  for (const v of VERDICTS) {
    lists = lists.flatMap((list) => [list, [...list, v], [...list, v, v]]);
  }
  return lists;
}

describe('judgeControl', () => {
  it('T-04 gives every observation one verdict, and says detected or silent only of a run that ended ok', () => {
    const all = everyObservation();
    expect(all).toHaveLength(120);
    for (const o of all) {
      const verdict = judgeControl(o);
      expect(VERDICTS, JSON.stringify(o)).toContain(verdict);
      expect(verdict, JSON.stringify(o)).not.toBe('no_canary');
      if (verdict === 'detected') {
        expect(o, 'detected needs the canary reported by a run that ended ok').toMatchObject({ installed: true, ended: 'ok', canaryReported: true });
      }
      if (verdict === 'silent') {
        expect(o, 'silent needs a run that ended ok, read the canary and did not report it').toMatchObject({
          installed: true,
          ended: 'ok',
          canaryRead: true,
          canaryReported: false,
        });
      }
      if (o.ended !== 'ok') expect(['detected', 'silent'], JSON.stringify(o)).not.toContain(verdict);
      if (!o.installed) expect(verdict, JSON.stringify(o)).toBe('missing');
    }
  });

  it('T-04 each verdict it gives is reached by the observation that defines it', () => {
    const ran = { installed: true, ended: 'ok' } as const;
    expect(judgeControl({ ...ran, canaryRead: true, canaryReported: true })).toBe('detected');
    expect(judgeControl({ ...ran, canaryRead: true, canaryReported: false })).toBe('silent');
    // Reported by a scanner that does not say what it read: still detected.
    expect(judgeControl({ ...ran, canaryRead: null, canaryReported: true })).toBe('detected');
    // Not reported, and never read (an ignored path) or not known to be read: not a silent control.
    expect(judgeControl({ ...ran, canaryRead: false, canaryReported: false })).toBe('unverified');
    expect(judgeControl({ ...ran, canaryRead: null, canaryReported: false })).toBe('unverified');
    for (const ended of ['partial', 'failed', 'timeout', 'not_run'] as const) {
      // Even a canary a broken run managed to report is not a detection.
      expect(judgeControl({ installed: true, ended, canaryRead: true, canaryReported: true }), ended).toBe('unverified');
      expect(judgeControl({ installed: true, ended, canaryRead: true, canaryReported: false }), ended).toBe('unverified');
    }
    expect(judgeControl({ installed: false, ended: 'not_run', canaryRead: null, canaryReported: false })).toBe('missing');
    // A guard the user switched off is their decision, whatever it answered — never silent.
    expect(judgeControl({ ...ran, canaryRead: true, canaryReported: false, softenedBy: 'GUARDIAN_HOOKS=off' })).toBe('disabled_by_user');
  });
});

describe('exitCodeFor', () => {
  it('T-12 is 1 if and only if a control is silent, 2 if and only if none is and one is unverified or missing, 0 otherwise', () => {
    const lists = everyVerdictList();
    expect(lists).toHaveLength(729);
    for (const list of lists) {
      const code = exitCodeFor(list);
      const silent = list.includes('silent');
      const open = list.includes('unverified') || list.includes('missing');
      expect(code === 1, list.join(',')).toBe(silent);
      expect(code === 2, list.join(',')).toBe(!silent && open);
      expect(code === 0, list.join(',')).toBe(!silent && !open);
    }
  });

  it('T-12 no_canary and disabled_by_user never change it', () => {
    for (const list of everyVerdictList()) {
      const without = list.filter((v) => v !== 'no_canary' && v !== 'disabled_by_user');
      expect(exitCodeFor(list), list.join(',')).toBe(exitCodeFor(without));
    }
    expect(exitCodeFor(['no_canary', 'disabled_by_user', 'detected'])).toBe(0);
    expect(exitCodeFor([])).toBe(0);
  });
});
