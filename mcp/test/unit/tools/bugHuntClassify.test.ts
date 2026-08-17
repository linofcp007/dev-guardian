/**
 * `mapSubcategory` and `languagePacksFor` — the two pure functions behind
 * fix round 2's "make the classifier actually classify" and "add
 * stack-detected language packs" work.
 *
 * `mapSubcategory`'s cases below are real rule ids captured from the live
 * packs `bug_hunt` configures (`p/r2c-bug-scan`, `p/security-audit`, and the
 * five language packs), not invented examples — see the fix report for the
 * `curl`/YAML-inspection commands that produced them. Two of them
 * (`no-null-cipher`, `logger-credential-leak`) are real near-miss false
 * positives the classifier must NOT match, found by testing against every
 * rule id in every pack rather than just the ones a hand-picked example set
 * would have covered.
 */
import { describe, expect, it } from 'vitest';
import {
  BUG_SUBCATEGORIES,
  languagePacksFor,
  mapSubcategory,
} from '../../../src/tools/bugHunt.js';

describe('mapSubcategory', () => {
  describe('real true positives (captured from p/r2c-bug-scan and p/security-audit)', () => {
    const cases: Array<[string, string]> = [
      ['python.lang.correctness.concurrent.uncaught-executor-exceptions', 'race_condition'],
      ['python.django.correctness.string-field-null-checks.no-null-string-field', 'null_safety'],
      ['go.lang.correctness.overflow.overflow.integer-overflow-int16', 'off_by_one'],
      [
        'python.lang.correctness.file-object-redefined-before-close.file-object-redefined-before-close',
        'memory_leak',
      ],
      ['c.lang.security.use-after-free.use-after-free', 'memory_leak'],
      ['python.lang.correctness.unchecked-returns.unchecked-subprocess-call', 'error_handling'],
      ['python.lang.correctness.exceptions.exceptions.raise-not-base-exception', 'error_handling'],
      ['python.lang.correctness.list-modify-iterating.list-modify-while-iterate', 'edge_case'],
      ['python.lang.correctness.dict-modify-iterating.dict-del-while-iterate', 'edge_case'],
      ['python.lang.correctness.common-mistakes.default-mutable-dict.default-mutable-dict', 'edge_case'],
    ];

    it.each(cases)('%s -> %s', (ruleId, expected) => {
      expect(mapSubcategory(ruleId, undefined)).toBe(expected);
    });

    it('every case above is one of the six canonical subcategories', () => {
      for (const [, expected] of cases) {
        expect(BUG_SUBCATEGORIES.has(expected)).toBe(true);
      }
    });
  });

  describe('real near-miss false positives (found by testing every rule id, not a hand-picked set)', () => {
    it('does not classify an insecure-cipher-NAME rule as null_safety', () => {
      // java.lang.security.audit.crypto.no-null-cipher — flags use of the
      // literal `NullCipher` crypto algorithm. A bare `/null/` keyword match
      // would mis-tag this as a null-safety bug; it is a crypto/security
      // finding and must keep falling through, or `categories: ['null_safety']`
      // would incorrectly include a cipher-strength finding.
      const id = 'java.lang.security.audit.crypto.no-null-cipher.no-null-cipher';
      expect(mapSubcategory(id, undefined)).not.toBe('null_safety');
      expect(mapSubcategory(id, undefined)).toBeUndefined();
    });

    it('does not classify a credential-disclosure-via-logging rule as memory_leak', () => {
      // python...logger-credential-leak — flags secrets written to logs. A
      // bare `/leak/` keyword match would mis-tag this as a resource/memory
      // leak; it is a secrets-disclosure finding.
      const id =
        'python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure';
      expect(mapSubcategory(id, undefined)).not.toBe('memory_leak');
      expect(mapSubcategory(id, undefined)).toBeUndefined();
    });
  });

  describe('the six-canonical-name guarantee', () => {
    it('never returns a string outside BUG_SUBCATEGORIES unless it was already the existing tag', () => {
      // The classifier's whole job: a rule id that matches none of the six
      // patterns must not silently invent a seventh bucket.
      const result = mapSubcategory('javascript.lang.correctness.useless-eqeq.eqeq-is-bad', undefined);
      expect(result).toBeUndefined();
    });

    it('passes through a pre-existing raw tag unchanged when no canonical keyword matches', () => {
      const result = mapSubcategory('some.unrelated.rule.id', 'xss');
      expect(result).toBe('xss');
    });
  });

  describe('fallback is not the old no-op ternary', () => {
    // Pins the actual bug fixed this round: the previous line was
    // `return existing && BUG_SUBCATEGORIES.has(existing) ? existing : existing`
    // — both branches identical, so a raw tag that WAS already canonical and
    // one that was NOT were indistinguishable from the return value alone.
    // This still passes under that old code (both return 'null_safety'), so
    // it is not by itself proof of the fix — it exists so a regression back
    // to a *different*, more clearly wrong no-op (e.g. always returning
    // `undefined`, or always returning `existing` even when a keyword DOES
    // match) is caught by the true-positive cases above, which a bare no-op
    // fails outright.
    it('an existing tag that already is canonical survives the fallback', () => {
      expect(mapSubcategory('some.unrelated.rule.id', 'null_safety')).toBe('null_safety');
    });
  });
});

describe('languagePacksFor', () => {
  it('selects nothing for an empty language list', () => {
    expect(languagePacksFor([])).toEqual([]);
  });

  it('selects p/javascript and p/typescript for a TypeScript project (both languages present)', () => {
    expect(languagePacksFor(['javascript', 'typescript'])).toEqual(
      expect.arrayContaining(['p/javascript', 'p/typescript']),
    );
    expect(languagePacksFor(['javascript', 'typescript'])).toHaveLength(2);
  });

  it('selects only p/javascript for a plain JS project (no typescript language)', () => {
    expect(languagePacksFor(['javascript'])).toEqual(['p/javascript']);
  });

  it('selects p/python, p/java and p/golang for their respective languages', () => {
    expect(languagePacksFor(['python'])).toEqual(['p/python']);
    expect(languagePacksFor(['java'])).toEqual(['p/java']);
    expect(languagePacksFor(['go'])).toEqual(['p/golang']);
  });

  it('ignores a language with no configured pack (e.g. csharp, ruby) rather than throwing', () => {
    expect(languagePacksFor(['csharp', 'ruby'])).toEqual([]);
  });

  it('selects every matching pack for a polyglot project, order matching LANGUAGE_PACKS', () => {
    expect(languagePacksFor(['go', 'javascript', 'java', 'python', 'typescript'])).toEqual([
      'p/javascript',
      'p/typescript',
      'p/python',
      'p/java',
      'p/golang',
    ]);
  });
});
