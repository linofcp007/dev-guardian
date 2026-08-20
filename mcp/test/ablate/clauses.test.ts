/**
 * Unit tests for the ablation harness's pure half.
 *
 * The harness itself is deliberately NOT a vitest test -- a full run is
 * minutes of Semgrep per pack and the report is the product. What IS testable
 * in milliseconds is everything that decides WHICH clause gets removed and
 * WHAT the file looks like afterwards, and that is the half where a bug is
 * invisible: a harness that silently removes the wrong node still prints a
 * confident verdict for the node it named.
 *
 * The two properties worth the most here are the two that cost a previous
 * ablation effort its results:
 *
 *  - clause identity survives an edit that moves every line (a comment
 *    inserted at the top of the file), because identity is body text;
 *  - removing a `pattern-either` BRANCH is a different operation from
 *    removing the `pattern-not` next to it, and neither leaves a `- {}`
 *    behind.
 */

import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parse } from 'yaml';
import { AblationError, ablate, ablateAll, clauseLabel, enumerateClauses, roundTrip } from './clauses.js';
import { REPO_ROOT } from './packs.js';

const SAMPLE = `rules:
  - id: sample-one
    patterns:
      - pattern: $A[$I]
      - pattern-either:
          - pattern-inside: for (...; $I <= $A.length; ...) ...
          - pattern-inside: while ($I <= $A.length) ...
      - pattern-not-inside: $A[$I] = ...
      - metavariable-regex:
          metavariable: $I
          regex: ^i$
    message: sample
    severity: WARNING
    languages: [javascript]

  - id: sample-two
    patterns:
      - pattern: $S.match($ARG)[$I]
      - pattern-not:
          patterns:
            - pattern: $S.match($ARG)[$I]
            - metavariable-comparison:
                metavariable: $ARG
                comparison: "'?.[' not in str($ARG)"
    metadata:
      # A metadata key that LOOKS like a clause. It is prose, not logic.
      pattern-inside: not a clause
    message: sample two
    severity: ERROR
    languages: [javascript]

  - id: sample-three
    patterns:
      - pattern: foo($X)
      - pattern-either:
          - pattern-not-regex: bar
    message: sample three
    severity: INFO
    languages: [javascript]
`;

function bodies(source: string): string[] {
  return enumerateClauses(source).clauses.map((c) => c.body);
}

describe('enumerateClauses', () => {
  it('finds every clause kind the packs use, and nothing else', () => {
    const inventory = enumerateClauses(SAMPLE);
    expect(inventory.ruleIds).toEqual(['sample-one', 'sample-two', 'sample-three']);
    expect(inventory.clauses.map((c) => `${c.ruleId} ${c.kind}`)).toEqual([
      'sample-one pattern-either-branch',
      'sample-one pattern-inside',
      'sample-one pattern-either-branch',
      'sample-one pattern-inside',
      'sample-one pattern-not-inside',
      'sample-one metavariable-regex',
      'sample-two pattern-not',
      'sample-two metavariable-comparison',
      // The BRANCH of sample-three's single-armed pattern-either is skipped
      // (see below), but the clause inside that branch is still ablatable on
      // its own -- removing it collapses the whole either, which is a real
      // experiment and a different one.
      'sample-three pattern-not-regex',
    ]);
  });

  it('never reads a metadata key as a clause', () => {
    // `sample-two` has `metadata.pattern-inside`. It must not appear.
    const two = enumerateClauses(SAMPLE).clauses.filter((c) => c.ruleId === 'sample-two');
    expect(two.map((c) => c.kind)).toEqual(['pattern-not', 'metavariable-comparison']);
  });

  it('refuses to ablate the sole branch of a pattern-either', () => {
    const { skipped } = enumerateClauses(SAMPLE);
    expect(skipped).toHaveLength(1);
    const only = skipped[0];
    if (only === undefined) throw new Error('expected one skipped clause');
    expect(only.ruleId).toBe('sample-three');
    expect(only.reason).toMatch(/empty the disjunction/);
  });

  it('numbers verbatim-identical clauses inside one rule', () => {
    const repeated = `rules:
  - id: r
    patterns:
      - pattern: f($X)
      - pattern-not-inside: g($X)
      - pattern-not-inside: g($X)
    message: m
    severity: INFO
    languages: [javascript]
`;
    const clauses = enumerateClauses(repeated).clauses;
    const first = clauses[0];
    const second = clauses[1];
    if (first === undefined || second === undefined) throw new Error('expected two clauses');
    expect([first.occurrence, second.occurrence]).toEqual([1, 2]);
    expect([first.occurrences, second.occurrences]).toEqual([2, 2]);
    expect(second.hash).toBe(first.hash);
    expect(clauseLabel(first)).toMatch(/#1\/2/);
    // The structural path is what still tells them apart on the page.
    expect(second.path).not.toBe(first.path);
  });

  it('identifies clauses by body, so an inserted comment moves nothing', () => {
    // The failure that discarded a previous ablation run: a comment edited
    // mid-run shifted every line, and line-numbered verdicts became
    // unattributable.
    const shifted = `# a comment nobody thought was load-bearing\n#\n#\n${SAMPLE}`;
    const before = enumerateClauses(SAMPLE).clauses;
    const after = enumerateClauses(shifted).clauses;
    expect(after.map((c) => c.hash)).toEqual(before.map((c) => c.hash));
    expect(after.map((c) => c.body)).toEqual(before.map((c) => c.body));
  });
});

function clauseByBody(source: string, needle: string) {
  const found = enumerateClauses(source).clauses.find((c) => c.body.includes(needle));
  if (found === undefined) throw new Error(`no clause matching ${needle}`);
  return found;
}

describe('ablate', () => {
  it('removes the named clause and leaves every other one intact', () => {
    const target = clauseByBody(SAMPLE, '$A[$I] = ...');
    const after = ablate(SAMPLE, target);
    expect(bodies(after)).toEqual(bodies(SAMPLE).filter((b) => b !== target.body));
  });

  it('prunes the one-key map a removed clause leaves inside a sequence', () => {
    // `- pattern-not-inside: X` is a sequence item holding a one-key map.
    // Deleting the key would leave `- {}`, which Semgrep rejects outright.
    const target = clauseByBody(SAMPLE, '$A[$I] = ...');
    const after = ablate(SAMPLE, target);
    expect(after).not.toMatch(/\{\}/);
    const parsed: unknown = parse(after);
    const doc = parsed as { rules: { patterns?: unknown[] }[] };
    for (const item of doc.rules[0]?.patterns ?? []) {
      expect(Object.keys(item as Record<string, unknown>).length).toBeGreaterThan(0);
    }
  });

  it('removing a pattern-either branch is not removing the clause beside it', () => {
    const branch = enumerateClauses(SAMPLE).clauses.find(
      (c) => c.kind === 'pattern-either-branch' && c.body.includes('while'),
    );
    const sibling = clauseByBody(SAMPLE, '$A[$I] = ...');
    if (branch === undefined) throw new Error('no branch clause');
    expect(ablate(SAMPLE, branch)).not.toBe(ablate(SAMPLE, sibling));
    // The branch removal leaves the `pattern-either` with one arm...
    const afterBranch: unknown = parse(ablate(SAMPLE, branch));
    const rule = (afterBranch as { rules: { patterns: Record<string, unknown>[] }[] }).rules[0];
    const either = rule?.patterns.find((p) => 'pattern-either' in p)?.['pattern-either'];
    expect(Array.isArray(either) ? either.length : -1).toBe(1);
    // ...and does not touch the `pattern-not-inside`.
    expect(rule?.patterns.some((p) => 'pattern-not-inside' in p)).toBe(true);
  });

  it('reaches a clause nested two levels inside a pattern-not', () => {
    // The enclosing `pattern-not` body CONTAINS this text too -- it is the
    // clause's parent -- so select on the kind, not on the substring alone.
    const target = enumerateClauses(SAMPLE).clauses.find(
      (c) => c.kind === 'metavariable-comparison',
    );
    if (target === undefined) throw new Error('no metavariable-comparison clause');
    expect(target.ruleId).toBe('sample-two');
    const after: unknown = parse(ablate(SAMPLE, target));
    const rule = (after as { rules: { id: string; patterns: Record<string, unknown>[] }[] }).rules[1];
    const not = rule?.patterns.find((p) => 'pattern-not' in p)?.['pattern-not'];
    const inner = (not as { patterns?: unknown[] } | undefined)?.patterns ?? [];
    // The wrapping `pattern-not` survives; only its inner clause is gone.
    expect(inner).toHaveLength(1);
  });

  it('refuses an ablation that would leave a rule with no pattern', () => {
    const onlyClause = `rules:
  - id: r
    pattern-either:
      - pattern-inside: f($X)
      - pattern-inside: g($X)
    message: m
    severity: INFO
    languages: [javascript]
`;
    // Both branches are removable individually; removing the inner
    // `pattern-inside` of a branch collapses to the same thing. Forcing the
    // rule empty is only reachable through a hand-built address, so assert
    // the guard directly on a rule whose only entry point is the clause.
    const solo = `rules:
  - id: r
    patterns:
      - pattern-inside: f($X)
    message: m
    severity: INFO
    languages: [javascript]
`;
    const target = clauseByBody(solo, 'f($X)');
    expect(() => ablate(solo, target)).toThrow(AblationError);
    expect(enumerateClauses(onlyClause).clauses.length).toBe(4);
  });
});

describe('ablateAll', () => {
  const THREE = `rules:
  - id: r
    patterns:
      - pattern: f($X)
      - pattern-not-inside: a($X)
      - pattern-not-inside: b($X)
      - pattern-not-inside: c($X)
    message: m
    severity: INFO
    languages: [javascript]
`;

  function pick(source: string, needle: string) {
    const c = enumerateClauses(source).clauses.find((x) => x.body.includes(needle));
    if (c === undefined) throw new Error(`no clause ${needle}`);
    return c;
  }

  it('removes both clauses, whichever order they are given in', () => {
    // The hazard: addresses are POSITIONS. Removing `patterns[1]` first
    // renumbers `patterns[3]`, so a naive implementation removes `b` and then
    // whatever slid into slot 3 -- silently ablating a clause it did not name
    // while reporting the one it did.
    const a = pick(THREE, 'a($X)');
    const c = pick(THREE, 'c($X)');
    const forwards = ablateAll(THREE, [a, c]);
    const backwards = ablateAll(THREE, [c, a]);
    expect(forwards).toBe(backwards);
    expect(bodies(forwards)).toEqual(['pattern-not-inside: "b($X)"']);
  });

  it('removes three at once without disturbing the positive term', () => {
    const all = enumerateClauses(THREE).clauses;
    const stripped = ablateAll(THREE, all);
    expect(bodies(stripped)).toEqual([]);
    const parsed = parse(stripped) as { rules: { patterns: Record<string, unknown>[] }[] };
    expect(parsed.rules[0]?.patterns).toEqual([{ pattern: 'f($X)' }]);
  });

  it('refuses a pair where one clause encloses the other', () => {
    // Removing a `pattern-not` and the `metavariable-comparison` inside it is
    // just removing the `pattern-not`, which the single-clause pass already
    // measured. Reporting it as a redundant pair would be a false positive.
    const outer = pick(SAMPLE, "'?.[' not in str($ARG)"); // the pattern-not
    const inner = enumerateClauses(SAMPLE).clauses.find(
      (x) => x.kind === 'metavariable-comparison',
    );
    if (inner === undefined) throw new Error('no inner clause');
    expect(outer.kind).toBe('pattern-not');
    expect(() => ablateAll(SAMPLE, [outer, inner])).toThrow(/encloses/);
    expect(() => ablateAll(SAMPLE, [inner, outer])).toThrow(/encloses/);
  });

  it('matches single-clause ablation when given one clause', () => {
    const a = pick(THREE, 'a($X)');
    expect(ablateAll(THREE, [a])).toBe(ablate(THREE, a));
  });
});

describe('roundTrip', () => {
  it('is semantically identical on every shipped pack', () => {
    // The harness runs a live Semgrep control on top of this; the cheap
    // structural version belongs here so a serialiser regression fails in
    // milliseconds instead of six minutes into an ablation run.
    for (const name of ['base', 'bugfix-js', 'bugfix-py', 'bugfix-go', 'bugfix-java', 'routes']) {
      const path = resolve(REPO_ROOT, 'configs', 'semgrep', `${name}.yml`);
      const source = readFileSync(path, 'utf8');
      const before: unknown = parse(source);
      const after: unknown = parse(roundTrip(source));
      expect(after, `${name}.yml round-trips`).toEqual(before);
    }
  });
});

describe('the shipped packs', () => {
  it('every enumerated clause either ablates cleanly or says why it cannot', () => {
    for (const name of ['base', 'bugfix-js', 'bugfix-py', 'bugfix-go', 'bugfix-java']) {
      const path = resolve(REPO_ROOT, 'configs', 'semgrep', `${name}.yml`);
      const source = readFileSync(path, 'utf8');
      const { clauses, ruleIds } = enumerateClauses(source);
      expect(clauses.length, `${name}.yml has clauses`).toBeGreaterThan(0);
      for (const clause of clauses) {
        const where = `${name}.yml :: ${clauseLabel(clause)}`;
        let variant: string;
        try {
          variant = ablate(source, clause);
        } catch (err) {
          // The only tolerated failure is the structural one, with a reason:
          // removing this clause would leave a group with no positive term.
          // Anything else is a harness bug.
          expect(err, where).toBeInstanceOf(AblationError);
          expect((err as Error).message, where).toMatch(/no positive term|no top-level pattern/);
          continue;
        }
        expect(variant, where).not.toBe(source);
        // Still parses, and no rule was lost along the way.
        const parsed = parse(variant) as { rules: unknown[] };
        expect(parsed.rules, where).toHaveLength(ruleIds.length);
      }
    }
  });

  it('never leaves a patterns group with only conditions in it', () => {
    // The failure mode this guards is silent: Semgrep reports `paths.scanned:
    // []` and exit 0 for such a config, which an ablation run would read as
    // "removing the clause changed nothing" -- a DEAD verdict, confidently
    // wrong.
    const conditionsOnly = `rules:
  - id: r
    patterns:
      - pattern-either:
          - patterns:
              - pattern-inside: $ANY = $ASYNC
              - metavariable-regex: {metavariable: $ASYNC, regex: ^async}
          - pattern-inside: async function $F(...) { ... }
      - pattern: $O.$M(...)
    message: m
    severity: INFO
    languages: [javascript]
`;
    const target = enumerateClauses(conditionsOnly).clauses.find(
      (c) => c.kind === 'pattern-inside' && c.body.includes('$ANY = $ASYNC'),
    );
    if (target === undefined) throw new Error('no nested pattern-inside clause');
    expect(() => ablate(conditionsOnly, target)).toThrow(/no positive term/);
  });
});
