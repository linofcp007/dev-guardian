/**
 * Unit tests for the ablation report's coverage semantics.
 *
 * The defect these exist for was never a wrong measurement -- every clause the
 * harness ablated got the right verdict. It was the SUMMARY: a pack whose
 * rules included some with no ablatable clause reported `52/52 live, 0 DEAD`,
 * and 52/52 reads as "the whole pack was checked". A rule with a bare
 * `pattern:` has nothing to remove, so it appeared in no list at all -- not
 * even under `skipped`.
 *
 * So what is asserted here is what the reader can conclude from the page:
 * the headline names how much of the pack it covers, every rule is on it, and
 * a rule that fires on nothing is impossible to miss.
 *
 * The axis-3 block below is the same class of assertion for the same class of
 * defect. Axis 3 once printed `+2` on a corpus whose two identical scans
 * disagreed by 5, which reads as a finding and was not one. So the page has to
 * carry the floor, the number of files nobody could measure, and the fact that
 * the comparison is scoped to one rule -- and a delta inside the floor has to
 * come out as `INCONCLUSIVE` rather than as either verdict.
 */

import { describe, expect, it } from 'vitest';
import { renderPackReport, renderSummary } from './report.js';
import type { ClauseVerdict, PackReport, RuleVerdict } from './harness.js';
import type { Finding } from './semgrep.js';

function ruleVerdict(over: Partial<RuleVerdict> & { ruleId: string }): RuleVerdict {
  return {
    enumeratedClauses: 3,
    ablatedClauses: 3,
    noClausesReason: undefined,
    hitsFindings: 4,
    firesOnHits: 'PASS',
    realFindings: null,
    ...over,
  };
}

const CLAUSELESS: RuleVerdict = ruleVerdict({
  ruleId: 'pack-race-condition-static-random',
  enumeratedClauses: 0,
  ablatedClauses: 0,
  noClausesReason: 'a bare `pattern` with no `patterns:` group and no `pattern-either:`',
  hitsFindings: 3,
});

function report(over: Partial<PackReport> = {}): PackReport {
  const rules = over.rules ?? [ruleVerdict({ ruleId: 'pack-one' }), CLAUSELESS];
  return {
    pack: 'pack',
    configPath: '/repo/configs/semgrep/pack.yml',
    configSha256: 'abc123',
    ruleCount: rules.length,
    rulesWithClauses: rules.filter((r) => r.enumeratedClauses > 0).length,
    rules,
    clauseCount: rules.reduce((n, r) => n + r.ablatedClauses, 0),
    skipped: [],
    collapsed: [],
    fixtureCorpus: '/repo/mcp/test/fixtures/pack',
    hitsCorpus: 'hits/',
    decoyCorpus: [],
    baselineDecoys: null,
    realCorpus: null,
    baselineFixtures: 7,
    baselineHits: 7,
    baselineReal: null,
    baselineRealComparable: null,
    realExcludedFiles: null,
    realNoiseFloor: null,
    realNoisyRules: [],
    realUnscopedAborts: null,
    verdicts: [],
    pairs: [],
    seconds: 1,
    ...over,
  };
}

function clauseVerdict(over: Partial<ClauseVerdict> & { ruleId: string }): ClauseVerdict {
  const { ruleId, ...rest } = over;
  return {
    clause: {
      ruleId,
      kind: 'pattern-not-inside',
      path: 'rules[0].patterns[1]',
      body: '{"pattern-not-inside":"if ($X) { ... }"}',
      hash: 'aaaabbbbcccc',
      occurrence: 1,
      occurrences: 1,
      address: [],
    },
    live: 'PASS',
    movedIn: ['fixtures'],
    fixtureDelta: -1,
    keepsTruePositives: 'PASS',
    revealedInHits: [],
    noAddedNoise: 'PASS',
    realDelta: 0,
    addedByClause: [],
    realFloor: 0,
    realExcludedFiles: 0,
    error: undefined,
    seconds: 1,
    ...rest,
  };
}

function finding(over: Partial<Finding> = {}): Finding {
  return { ruleId: 'pack-one', file: 'a/b.cs', line: 1, col: 1, endLine: 2, endCol: 2, ...over };
}

describe('renderPackReport coverage', () => {
  it('names how many RULES the clause count covers, not just the clauses', () => {
    const text = renderPackReport(report());
    expect(text).toMatch(/coverage\s+3 clause\(s\) across 1 of 2 rules/);
    expect(text).toMatch(/1 rule\(s\) have no ablatable clauses/);
    // The shape the old report had, and the reason this test exists.
    expect(text).not.toMatch(/^axis 1 live\s+3\/3 pass$/m);
  });

  it('shows the measured count against the declared one when they differ', () => {
    // Under `--filter`, and whenever a clause is collapsed or skipped, fewer
    // clauses are measured than the pack declares. A bare "3 clauses" would
    // read as the whole pack again.
    const rules = [
      ruleVerdict({ ruleId: 'pack-one', enumeratedClauses: 9, ablatedClauses: 3 }),
      CLAUSELESS,
    ];
    const text = renderPackReport(report({ rules }));
    expect(text).toMatch(/coverage\s+3 of 9 clause\(s\) across 1 of 2 rules/);
  });

  it('lists every rule, clauseless ones included, with the reason attached', () => {
    const text = renderPackReport(report());
    expect(text).toMatch(/RULE COVERAGE \(2\)/);
    expect(text).toContain('pack-one');
    expect(text).toContain('pack-race-condition-static-random');
    expect(text).toContain('no ablatable clauses');
    expect(text).toContain('a bare `pattern` with no `patterns:` group');
  });

  it('leaves a clauseless rule out of the axis 1-3 denominators', () => {
    // Rounding it in would report a pass the harness never measured; leaving
    // it out silently is what produced the misleading headline. It is named
    // in its own line instead.
    const text = renderPackReport(report());
    expect(text).toMatch(/axis 1 live\s+3\/3 clauses pass/);
    expect(text).toMatch(/axes 1-3 are properties of a CLAUSE/);
  });

  it('flags a rule that fires on nothing, clauses or no clauses', () => {
    const silent = ruleVerdict({
      ruleId: 'pack-ported-by-analogy',
      enumeratedClauses: 0,
      ablatedClauses: 0,
      noClausesReason: 'a bare `pattern`',
      hitsFindings: 0,
      firesOnHits: 'FAIL',
    });
    const text = renderPackReport(report({ rules: [ruleVerdict({ ruleId: 'pack-one' }), silent] }));
    expect(text).toMatch(/axis 0 fires on hits\/\s+1\/2 rules fire, 1 FIRING ON NOTHING/);
    expect(text).toContain('FIRES ON NOTHING');
    expect(text).toMatch(/1 rule\(s\) FIRE ON NOTHING in hits\//);
    expect(text).toContain('pack-ported-by-analogy');
    // No clause was flagged, so the old "nothing to act on" line must not be
    // the last word on the page.
    expect(text).not.toContain('Nothing to act on.');
  });

  it('reports axis 0 as N/A rather than a pass when there is no hits corpus', () => {
    const rules = [
      ruleVerdict({ ruleId: 'r1', hitsFindings: 0, firesOnHits: 'N/A' }),
      ruleVerdict({ ruleId: 'r2', hitsFindings: 0, firesOnHits: 'N/A' }),
    ];
    const text = renderPackReport(report({ rules }));
    expect(text).toMatch(/axis 0 fires on hits\/\s+N\/A -- this pack has no hits\/ fixture corpus/);
    expect(text).toContain('hits n/a');
  });
});

/**
 * The corpus lines a pack gets when its fixtures predate the `hits/` +
 * `misses/` convention -- which is every one of `routes.yml`'s, so this is the
 * shape of the only registration in the repo that uses them.
 *
 * Both assertions are about a number that is NOT zero and must not read as a
 * failure. The decoy tree produces eight baseline findings, four of them
 * routes, and each is documented as undecidable rather than untried; a report
 * that hid the number would let a fifth appear unnoticed, and a report that
 * gated on zero would be a standing red line nobody reads.
 */
describe('renderPackReport corpora that are not named hits/ and misses/', () => {
  it('names the hits corpus it actually measured, not the convention', () => {
    const text = renderPackReport(report({ hitsCorpus: 'the fixture root', baselineHits: 403 }));
    expect(text).toContain('403 in the fixture root');
  });

  it('prints the decoy baseline as a pinned number rather than a target of zero', () => {
    const text = renderPackReport(
      report({ decoyCorpus: ['frameworks/fp'], baselineDecoys: 8, hitsCorpus: 'the fixture root' }),
    );
    expect(text).toMatch(/decoy corpus\s+frameworks\/fp\s+\(8 baseline findings, excluded from hits/);
    expect(text).toContain('a pinned number, not a target of zero');
  });

  it('says on the rule line when the real corpus never reached a rule at all', () => {
    // Axis 3 compares the ablated rule's OWN findings, so a rule with no
    // baseline on the corpus passes by comparing nothing to nothing. That is
    // 62 of `routes.yml`'s 64 rules against `mcp/src`, and it must not print
    // the same as a rule the corpus genuinely exercised.
    const rules = [
      ruleVerdict({ ruleId: 'guardian-import-esm', realFindings: 824 }),
      ruleVerdict({ ruleId: 'guardian-route-rails', realFindings: 0 }),
    ];
    const text = renderPackReport(report({ rules, realCorpus: 'mcp/src' }));
    expect(text).toContain('guardian-import-esm  real 824');
    expect(text).toContain('guardian-route-rails  real 0 -- axis 3 vacuous here');
  });

  it('says nothing about real-code counts when the pack has no corpus', () => {
    const text = renderPackReport(report());
    expect(text).not.toContain('axis 3 vacuous here');
  });
});

describe('renderPackReport axis 3', () => {
  const withCorpus = (over: Partial<PackReport> = {}): PackReport =>
    report({
      realCorpus: 'C# corpus (GUARDIAN_CS_SRC)',
      baselineReal: 798,
      baselineRealComparable: 793,
      realExcludedFiles: 10,
      realNoiseFloor: 0,
      realNoisyRules: [],
      realUnscopedAborts: 0,
      ...over,
    });

  it('prints the noise floor and the excluded files, not just the totals', () => {
    // `paths.scanned` reads full on a run that abandoned rules on its slowest
    // files, so these two numbers are the only place the reader learns that
    // the count is not over the whole corpus.
    const text = renderPackReport(withCorpus());
    expect(text).toMatch(/real corpus\s+C# corpus .+798 baseline findings, 793 comparable/);
    expect(text).toMatch(/excluded files\s+10/);
    expect(text).toMatch(/noise floor\s+0/);
    expect(text).toContain('axis 3 can resolve a per-rule delta of 1 or more');
  });

  it('says axis 3 is scoped to the ablated rule, where the reader will see it', () => {
    const text = renderPackReport(withCorpus());
    expect(text).toContain("axis 3 compares the ABLATED RULE'S OWN findings");
  });

  it('names the rules whose two control scans disagreed', () => {
    const text = renderPackReport(
      withCorpus({ realNoiseFloor: 5, realNoisyRules: [{ ruleId: 'pack-one', drift: 5 }] }),
    );
    expect(text).toContain('two scans of the identical pack DISAGREED');
    expect(text).toMatch(/NOISY\s+pack-one -- control scans differ by 5/);
    expect(text).toContain('axis 3 can resolve a per-rule delta of 6 or more');
  });

  it('reports a delta under the floor as INCONCLUSIVE, never as a pass', () => {
    // The whole point of the floor: `+2` against an error of +-5 is worse than
    // no verdict, so it must not read like one in either direction.
    const v = clauseVerdict({
      ruleId: 'pack-one',
      noAddedNoise: 'INCONCLUSIVE',
      addedByClause: [finding(), finding({ line: 9 })],
      realDelta: -2,
      realFloor: 5,
    });
    const text = renderPackReport(withCorpus({ verdicts: [v], realNoiseFloor: 5 }));
    expect(text).toMatch(/axis 3 no rise in real-code count\s+2\/3 clauses pass, 0 RAISING the count, 1 INCONCLUSIVE/);
    expect(text).toContain('1 of them INCONCLUSIVE, which is not a finding');
    expect(text).toContain('axis 3  INCONCLUSIVE -- 2 finding(s) moved');
    expect(text).not.toContain('Nothing to act on.');
  });

  it('attributes a real FAIL to the ablated rule by name', () => {
    const v = clauseVerdict({
      ruleId: 'pack-one',
      noAddedNoise: 'FAIL',
      addedByClause: [finding(), finding({ line: 9 })],
      realDelta: -2,
      realFloor: 0,
      realExcludedFiles: 10,
    });
    const text = renderPackReport(withCorpus({ verdicts: [v] }));
    expect(text).toContain("axis 3  RAISES pack-one's real-code count by 2");
    expect(text).toContain('10 file(s) excluded as not finished by every scan');
  });

  it('still prints N/A -- never a silent skip -- with no corpus', () => {
    const v = clauseVerdict({
      ruleId: 'pack-one',
      noAddedNoise: 'N/A',
      realDelta: null,
      realFloor: null,
      realExcludedFiles: null,
      live: 'FAIL',
      movedIn: [],
    });
    const text = renderPackReport(report({ verdicts: [v] }));
    expect(text).toMatch(/axis 3 no rise in real-code count\s+N\/A -- no real-code corpus for this pack/);
    expect(text).toContain('axis 3  N/A -- this pack has no real-code corpus registered');
    expect(text).not.toContain('noise floor');
  });
});

describe('renderSummary', () => {
  it('carries rule coverage and silent rules into the cross-pack table', () => {
    const text = renderSummary([report({ pack: 'alpha' })]);
    expect(text).toContain('pack         rules covered silent clauses');
    expect(text).toMatch(/alpha\s+2\s+1\s+0\s+3/);
  });

  it('prints n/a for silent rules when the pack has no hits corpus', () => {
    const rules = [ruleVerdict({ ruleId: 'r1', hitsFindings: 0, firesOnHits: 'N/A' })];
    const text = renderSummary([report({ pack: 'beta', rules })]);
    expect(text).toMatch(/beta\s+1\s+1\s+n\/a/);
  });
});
