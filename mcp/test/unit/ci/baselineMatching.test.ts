/**
 * Review 8, findings 4, 5, 6 and 9 — what the CI gate matches a finding to a
 * baseline entry by, beyond the identity, and how it reads a baseline that is
 * there but broken.
 *
 * Three changes made the gate call a baselined finding new (exit 1). The
 * baseline now carries a tolerant `match_id` beside the identity — which
 * stays exactly as it was, so a 3.2 reader and every stored suppression still
 * match: a dependency finding without its installed version, a secret without
 * the commit that saw it, a file under the path the baseline recorded.
 */
import { describe, expect, it } from 'vitest';
import { buildBaseline, newFindings, readBaselineText } from '../../../src/ci/baseline.js';
import { computeFingerprint } from '../../../src/fingerprint/findingFingerprint.js';
import { assignIdentities } from '../../../src/fingerprint/findingIdentity.js';
import { REDACTED_SECRET_SNIPPET } from '../../../src/redaction/secretFindingRedaction.js';
import type { Finding } from '../../../src/types.js';

function finding(over: Partial<Finding> = {}): Finding {
  return {
    fingerprint: 'fp1',
    tool: 'semgrep',
    severity: 'high',
    category: 'security',
    title: 'a finding',
    file_path: 'src/db.ts',
    fix_available: false,
    ...over,
  };
}

const dep = (version: string, over: Partial<Finding> = {}): Finding =>
  assignIdentities([
    finding({
      fingerprint: `fp-${version}-${over.rule_id ?? ''}-${over.file_path ?? ''}-${over.snippet ?? ''}`,
      tool: 'trivy',
      rule_id: 'CVE-2020-8203',
      subcategory: 'cve',
      category: 'security',
      file_path: 'package-lock.json',
      snippet: `lodash@${version}->4.17.21`,
      ...over,
    }),
  ])[0] as Finding;

describe('finding 4: a dependency finding keyed without its installed version', () => {
  it('stays known when an upgrade changes the installed version; another CVE, package or manifest is new', () => {
    const baseline = buildBaseline([dep('4.17.15')], null, '2026-01-01');
    const after = dep('4.17.19');
    // The identity is unchanged in kind: it still holds the version.
    expect(after.identity).not.toBe(dep('4.17.15').identity);
    expect(newFindings([after], baseline)).toEqual([]);
    expect(newFindings([dep('4.17.19', { rule_id: 'CVE-2021-23337' })], baseline)).toHaveLength(1);
    expect(newFindings([dep('4.17.19', { snippet: 'minimist@1.2.0->1.2.6' })], baseline)).toHaveLength(1);
    expect(newFindings([dep('4.17.19', { file_path: 'web/package-lock.json' })], baseline)).toHaveLength(1);
  });

  it("keeps the entry's added date across the upgrade", () => {
    const first = buildBaseline([dep('4.17.15')], null, '2026-01-01');
    const second = buildBaseline([dep('4.17.19')], first, '2026-06-01');
    expect(second.entries).toHaveLength(1);
    expect(second.entries[0]?.added).toBe('2026-01-01');
  });
});

const secret = (over: Partial<Finding>): Finding =>
  finding({
    tool: 'gitleaks',
    rule_id: 'aws-access-token',
    subcategory: 'secret',
    category: 'security',
    file_path: 'config/app.js',
    line_start: 3,
    line_end: 3,
    ...over,
  });
const C1 = 'a'.repeat(40);
const C2 = 'b'.repeat(40);

describe('finding 5: a secret keyed the same in history and in the working tree', () => {
  const recorded = assignIdentities([secret({ fingerprint: 'h1', snippet: `rule=aws-access-token;commit=${C1}` })]);
  const baseline = buildBaseline(recorded, null, '2026-01-01');

  it('(b) a squash merge — the same secret in a new commit — is known', () => {
    const squashed = assignIdentities([secret({ fingerprint: 'h2', snippet: `rule=aws-access-token;commit=${C2}` })]);
    expect(newFindings(squashed, baseline)).toEqual([]);
  });

  it('(a) an unrelated uncommitted edit above it: the working-tree copy, a line lower, is known', () => {
    const dirty = assignIdentities([
      secret({ fingerprint: 'h1', snippet: `rule=aws-access-token;commit=${C1}` }),
      secret({ fingerprint: 'w1', snippet: 'rule=aws-access-token', line_start: 4, line_end: 4 }),
    ]);
    expect(newFindings(dirty, baseline)).toEqual([]);
  });

  it('(c) a whitespace commit touching the line — history reports it twice on one line — is known', () => {
    const twice = assignIdentities([
      secret({ fingerprint: 'h1', snippet: `rule=aws-access-token;commit=${C1}` }),
      secret({ fingerprint: 'h3', snippet: `rule=aws-access-token;commit=${C2}` }),
    ]);
    expect(newFindings(twice, baseline)).toEqual([]);
  });

  it('a second secret of the same rule in the same file is still new', () => {
    const two = assignIdentities([
      secret({ fingerprint: 'h1', snippet: `rule=aws-access-token;commit=${C1}` }),
      secret({ fingerprint: 'h4', snippet: `rule=aws-access-token;commit=${C2}`, line_start: 9, line_end: 9 }),
    ]);
    expect(newFindings(two, baseline)).toHaveLength(1);
  });

  // Review 11, finding 2: a match_id match took nothing, so a second secret
  // ABOVE the baselined one — occurrence 0 by line — matched the baselined
  // entry by match_id while the baselined secret matched it exactly.
  it('one to one: a second secret above the baselined one is new, even keyed by line alone', () => {
    const above = assignIdentities([
      secret({ fingerprint: 'h1', snippet: `rule=aws-access-token;commit=${C1}` }),
      secret({ fingerprint: 'h5', snippet: `rule=aws-access-token;commit=${C2}`, line_start: 1, line_end: 1 }),
    ]);
    expect(newFindings(above, baseline).map((f) => f.fingerprint)).toEqual(['h5']);
    // And `baseline update` does not hand the old entry's date to the new one.
    const rebuilt = buildBaseline(above, baseline, '2026-02-02');
    const dates = rebuilt.entries.map((e) => e.added).sort();
    expect(dates).toEqual(['2026-01-01', '2026-02-02']);
  });
});

const code = (path: string, fp: string): Finding =>
  assignIdentities([
    finding({ fingerprint: fp, rule_id: 'js-eval', file_path: path, line_start: 2, line_end: 2, snippet: 'eval(x)' }),
  ])[0] as Finding;

describe('finding 6: a finding in a renamed file', () => {
  it('is known through the path the baseline recorded (renamedFrom: new path → old)', () => {
    const baseline = buildBaseline([code('src/app.js', 'f1')], null, '2026-01-01');
    const moved = code('lib/app.js', 'f2');
    expect(newFindings([moved], baseline)).toHaveLength(1);
    expect(newFindings([moved], baseline, new Map([['lib/app.js', 'src/app.js']]))).toEqual([]);
    // A rename of another file decides nothing for this one.
    expect(newFindings([moved], baseline, new Map([['lib/other.js', 'src/app.js']]))).toHaveLength(1);
  });

  it('keeps its added date across the rename', () => {
    const first = buildBaseline([code('src/app.js', 'f1')], null, '2026-01-01');
    const second = buildBaseline([code('lib/app.js', 'f2')], first, '2026-06-01', new Map([['lib/app.js', 'src/app.js']]));
    expect(second.entries[0]?.added).toBe('2026-01-01');
  });
});

describe('old baselines keep matching', () => {
  const recorded = [code('src/app.js', 'f1'), dep('4.17.15')];
  const current = buildBaseline(recorded, null, '2026-01-01');
  /** What 3.2.x wrote: no match_id. */
  const old = { ...current, entries: current.entries.map(({ match_id: _drop, ...e }) => e) };

  it('a 3.2 baseline (no match_id) matches what it matched, and a rename through its identity', () => {
    expect(old.entries.every((e) => (e as { match_id?: string }).match_id === undefined)).toBe(true);
    expect(newFindings(recorded, old)).toEqual([]);
    expect(newFindings([code('lib/app.js', 'f2')], old, new Map([['lib/app.js', 'src/app.js']]))).toEqual([]);
  });

  it('what 3.2 could not tolerate stays new until a 3.3 baseline update, which keeps every date', () => {
    expect(newFindings([dep('4.17.19')], old)).toHaveLength(1);
    const rewritten = buildBaseline(recorded, old, '2026-06-01');
    expect(rewritten.entries.every((e) => e.added === '2026-01-01')).toBe(true);
    expect(newFindings([dep('4.17.19')], rewritten)).toEqual([]);
  });

  it('a 3.3 baseline is still version 1, its identities written as before (a 3.2 reader matches them)', () => {
    expect(current.version).toBe(1);
    for (const f of recorded) expect(current.entries.some((e) => e.identity === f.identity)).toBe(true);
    expect(current.entries.every((e) => typeof e.match_id === 'string')).toBe(true);
  });
});

describe('finding 9: readBaselineText', () => {
  it('names why a file that is there cannot be read — never "no baseline"', () => {
    expect(readBaselineText(null)).toEqual({ status: 'absent' });
    const conflict = readBaselineText('<<<<<<< HEAD\n{"version":1}\n=======\n{}\n>>>>>>> branch\n');
    expect(conflict.status).toBe('invalid');
    expect(conflict.status === 'invalid' ? conflict.error : '').toMatch(/not valid JSON \(it holds merge-conflict markers\)/);
    expect(readBaselineText('[]')).toEqual({ status: 'invalid', error: 'the document is not a JSON object' });
    expect(readBaselineText('{"version":99,"generated_at":"x","entries":[]}').status).toBe('invalid');
    expect(readBaselineText('{"version":1,"entries":[]}').status).toBe('invalid');
    expect(readBaselineText('{"version":1,"generated_at":"x","entries":[]}').status).toBe('ok');
  });
});

describe('the baseline file holds nothing a secret scanner reads as a credential', () => {
  // gitleaks' generic-api-key rule flags `"<keyword>": "<high-entropy>"`; a
  // field first named `match_key` made the committed baseline a secret
  // finding of its own on the next scan's history pass.
  it('no field name carries a credential keyword', () => {
    const file = buildBaseline([code('src/app.js', 'f1'), dep('4.17.15')], null, '2026-01-01');
    const names = new Set(file.entries.flatMap((e) => Object.keys(e)));
    for (const name of names) expect(name).not.toMatch(/key|token|secret|passw|api|auth|cred/i);
  });
});

describe('a credential finding\'s fingerprint over the redacted snippet', () => {
  const at = { tool: 'bandit', rule_id: 'B105', file_path: 'app.py', line_start: 12, line_end: 12 };
  const plaintextDerived = computeFingerprint({ ...at, snippet: '12 password = "x"' });
  const safe = computeFingerprint({ ...at, snippet: REDACTED_SECRET_SNIPPET });
  const credential = (fingerprint: string): Finding =>
    finding({ ...at, fingerprint, subcategory: 'hardcoded_password_string', snippet: REDACTED_SECRET_SNIPPET, identity: 'i'.repeat(64) });

  it('an entry written before, with the plaintext-derived fingerprint, still matches: by identity', () => {
    const before = buildBaseline([credential(plaintextDerived)], null, '2026-01-01');
    expect(newFindings([credential(safe)], before)).toEqual([]);
  });

  it('a stored row\'s plaintext-derived fingerprint never reaches the committed file', () => {
    const file = buildBaseline([credential(plaintextDerived)], null, '2026-01-01');
    expect(JSON.stringify(file)).not.toContain(plaintextDerived);
    expect(file.entries[0]?.fingerprint).toBe(safe);
  });
});
