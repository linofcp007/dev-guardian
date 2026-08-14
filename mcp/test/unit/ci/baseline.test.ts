import { describe, expect, it } from 'vitest';
import {
  parseBaseline, serialiseBaseline, buildBaseline, newFindings,
} from '../../../src/ci/baseline.js';
import type { Finding } from '../../../src/types.js';

function finding(over: Partial<Finding> = {}): Finding {
  return {
    fingerprint: 'fp1', tool: 'semgrep', severity: 'high', category: 'security',
    title: 'SQL injection', file_path: 'src/db.ts', fix_available: false, ...over,
  };
}

describe('parseBaseline', () => {
  it('returns null for an absent file, which is NOT an empty baseline', () => {
    // The distinction is the whole point: treating "no file" as "no known
    // findings" would fail the first build of every existing repository.
    expect(parseBaseline(null)).toBeNull();
  });

  it('returns an empty baseline for a file that genuinely holds none', () => {
    const parsed = parseBaseline('{"version":1,"generated_at":"x","entries":[]}');
    expect(parsed).not.toBeNull();
    expect(parsed?.entries).toEqual([]);
  });

  it('returns null for unparseable content rather than throwing', () => {
    expect(parseBaseline('{ not json')).toBeNull();
  });

  it('returns null for a JSON document of the wrong shape', () => {
    expect(parseBaseline('{"version":99}')).toBeNull();
    expect(parseBaseline('[]')).toBeNull();
  });
});

describe('newFindings', () => {
  it('returns everything when the baseline is absent', () => {
    expect(newFindings([finding()], null)).toHaveLength(1);
  });

  it('returns nothing when every fingerprint is baselined', () => {
    const b = buildBaseline([finding()], null, '2026-08-14');
    expect(newFindings([finding()], b)).toEqual([]);
  });

  it('returns only the fingerprints absent from the baseline', () => {
    const b = buildBaseline([finding({ fingerprint: 'old' })], null, '2026-08-14');
    const out = newFindings([finding({ fingerprint: 'old' }), finding({ fingerprint: 'new' })], b);
    expect(out.map((f) => f.fingerprint)).toEqual(['new']);
  });

  it('matches on fingerprint alone, not on severity or title', () => {
    // Guards the wrong implementation that compares whole objects: a scanner
    // re-wording a message would then resurface every baselined finding.
    const b = buildBaseline([finding({ title: 'old wording' })], null, '2026-08-14');
    expect(newFindings([finding({ title: 'new wording', severity: 'critical' })], b)).toEqual([]);
  });
});

describe('buildBaseline', () => {
  it('preserves the original `added` date for a fingerprint already present', () => {
    // A regeneration must not reset the clock on an old suppression — that
    // date is how a reviewer sees how long something has been carried.
    const first = buildBaseline([finding()], null, '2026-01-01');
    const second = buildBaseline([finding()], first, '2026-08-14');
    expect(second.entries[0]?.added).toBe('2026-01-01');
  });

  it('stamps a new fingerprint with the current date', () => {
    const first = buildBaseline([finding({ fingerprint: 'a' })], null, '2026-01-01');
    const second = buildBaseline(
      [finding({ fingerprint: 'a' }), finding({ fingerprint: 'b' })], first, '2026-08-14',
    );
    expect(second.entries.find((e) => e.fingerprint === 'b')?.added).toBe('2026-08-14');
  });

  it('drops entries whose finding no longer exists', () => {
    const first = buildBaseline([finding({ fingerprint: 'gone' })], null, '2026-01-01');
    const second = buildBaseline([finding({ fingerprint: 'kept' })], first, '2026-08-14');
    expect(second.entries.map((e) => e.fingerprint)).toEqual(['kept']);
  });

  it('sorts entries by fingerprint so the file does not churn between runs', () => {
    // A file whose line order moves on every regeneration produces noise
    // diffs and nobody reviews it any more.
    const b = buildBaseline(
      [finding({ fingerprint: 'c' }), finding({ fingerprint: 'a' }), finding({ fingerprint: 'b' })],
      null, '2026-08-14',
    );
    expect(b.entries.map((e) => e.fingerprint)).toEqual(['a', 'b', 'c']);
  });
});

describe('serialiseBaseline', () => {
  it('round-trips through parseBaseline', () => {
    const b = buildBaseline([finding()], null, '2026-08-14');
    expect(parseBaseline(serialiseBaseline(b))).toEqual(b);
  });

  it('ends with a newline so the file is POSIX-clean in a diff', () => {
    expect(serialiseBaseline(buildBaseline([], null, 'x')).endsWith('\n')).toBe(true);
  });
});
