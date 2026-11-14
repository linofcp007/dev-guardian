/**
 * `test/helpers/fixPrFixtureDrift.ts` — the message a live-data `create_fix_pr`
 * test fails with when the vulnerability database moved under its fixture.
 */

import { describe, expect, it } from 'vitest';
import { expectNoFixtureDrift, fixtureDriftExplanation, type FixGroupOutcome } from '../../helpers/fixPrFixtureDrift.js';

/** What `create_fix_pr` answered for lodash 4.17.20 on 2026-11-14 (real Trivy). */
const DRIFTED: FixGroupOutcome = {
  outcome: 'not_verified',
  commands: ['npm install lodash@4.18.0 --ignore-scripts --package-lock-only'],
  scan: {
    still_present: [],
    new_findings: [
      { severity: 'medium', title: 'lodash: Lodash: Prototype pollution allows deletion of built-in prototype properties via array path bypass' },
    ],
  },
};

describe('fixtureDriftExplanation', () => {
  it('T-03 a not_verified group with new findings is explained: the finding, the command, and that it is the fixture', () => {
    const why = fixtureDriftExplanation(DRIFTED);
    expect(why).toContain('medium: lodash: Lodash: Prototype pollution allows deletion of built-in prototype properties via array path bypass');
    expect(why).toContain('npm install lodash@4.18.0 --ignore-scripts --package-lock-only');
    expect(why).toMatch(/the fixture has drifted, not create_fix_pr/);
    expect(() => expectNoFixtureDrift(DRIFTED)).toThrow(/the fixture has drifted, not create_fix_pr/);
  });

  it('T-03 every new finding is named, none dropped', () => {
    const two: FixGroupOutcome = {
      ...DRIFTED,
      scan: { still_present: [], new_findings: [{ severity: 'high', title: 'first' }, { severity: 'low', title: 'second' }] },
    };
    const why = fixtureDriftExplanation(two);
    expect(why).toContain('2 finding(s)');
    expect(why).toContain('high: first');
    expect(why).toContain('low: second');
  });

  it('T-03 anything else is not drift: a created pull request, targets still present, no scan, no group', () => {
    const created: FixGroupOutcome = { outcome: 'pr_created', commands: ['npm install lodash@4.18.1'], scan: { still_present: [], new_findings: [] } };
    const stillPresent: FixGroupOutcome = { outcome: 'not_verified', commands: ['npm install lodash@4.18.1'], scan: { still_present: ['a'.repeat(64)], new_findings: [] } };
    for (const group of [created, stillPresent, { outcome: 'not_verified' }, { outcome: 'not_verified', scan: null }, undefined]) {
      expect(fixtureDriftExplanation(group)).toBeNull();
      expect(() => expectNoFixtureDrift(group)).not.toThrow();
    }
    // A pull request that WAS opened is never called drift, whatever its scan lists.
    expect(fixtureDriftExplanation({ ...DRIFTED, outcome: 'pr_created' })).toBeNull();
  });
});
