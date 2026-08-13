import { describe, expect, it } from 'vitest';
import { normalizeNucleiJsonl } from '../../../src/dast/normalizeNuclei.js';
import { route } from './helpers.js';

const LINE = JSON.stringify({
  'template-id': 'exposed-env-file',
  info: { name: 'Exposed .env file', severity: 'high', description: 'd' },
  host: 'http://localhost:3000',
  'matched-at': 'http://localhost:3000/.env',
  type: 'http',
});

describe('normalizeNucleiJsonl', () => {
  it('maps one jsonl line to one finding with tool nuclei', () => {
    const f = normalizeNucleiJsonl(LINE, []);
    expect(f).toHaveLength(1);
    expect(f[0]?.tool).toBe('nuclei');
    expect(f[0]?.rule_id).toBe('exposed-env-file');
    expect(f[0]?.severity).toBe('high');
  });

  it('skips blank lines and unparseable lines without throwing', () => {
    const f = normalizeNucleiJsonl(`${LINE}\n\nnot json\n${LINE}\n`, []);
    expect(f).toHaveLength(2);
  });

  it('attaches file_path when matched-at maps to a known route', () => {
    const routes = [route({ path_resolved: '/.env', file: 'src/app.ts', line: 4 })];
    const f = normalizeNucleiJsonl(LINE, routes);
    expect(f[0]?.file_path).toBe('src/app.ts');
    expect(f[0]?.line_start).toBe(4);
  });

  it('leaves file_path undefined when no route matches, rather than guessing', () => {
    const f = normalizeNucleiJsonl(LINE, [route({ path_resolved: '/other' })]);
    expect(f[0]?.file_path).toBeUndefined();
  });

  it('substitutes path parameters before comparing, using a fixed literal — never a prefix or wildcard', () => {
    // Every other route fixture in this file uses a literal path_resolved
    // ('/.env', '/other', or the builder's default '/users'), so none of
    // them exercise `substituteParams` at all — a wrong implementation that
    // deletes that call from `matchRoute`, reducing it to
    // `r.path_resolved === pathname`, would pass every other test in this
    // file unchanged. This is the one test that would catch it.
    const templated = route({ path_resolved: '/users/{id}', file: 'src/users.ts', line: 7 });

    // 1. The synthetic literal ('1') matches, so /users/{id} is found for a
    // hit at /users/1 — the concrete case the brief names by name.
    const hitLine = JSON.stringify({
      'template-id': 'users-hit', info: { name: 'Hit', severity: 'low' },
      'matched-at': 'http://localhost:3000/users/1',
    });
    const hit = normalizeNucleiJsonl(hitLine, [templated]);
    expect(hit[0]?.file_path).toBe('src/users.ts');
    expect(hit[0]?.line_start).toBe(7);

    // 2. A longer path that merely STARTS WITH the substituted path must not
    // match — guards a prefix/startsWith comparison masquerading as the
    // required exact-string equality.
    const prefixLine = JSON.stringify({
      'template-id': 'users-prefix', info: { name: 'Prefix', severity: 'low' },
      'matched-at': 'http://localhost:3000/users/1/admin',
    });
    const prefixHit = normalizeNucleiJsonl(prefixLine, [templated]);
    expect(prefixHit[0]?.file_path).toBeUndefined();

    // 3. A different id ('2') must not match either. This is a genuine
    // limitation, not an oversight: substitution fills in the fixed literal
    // '1', never a wildcard, so a nuclei finding actually reported at
    // /users/2 gets no source location from this route. Attaching one
    // anyway (on the theory that "some /users/{id}" is close enough) would
    // be exactly the guessed location the no-match rule exists to prevent.
    // Do not "fix" this into a pattern match.
    const missLine = JSON.stringify({
      'template-id': 'users-miss', info: { name: 'Miss', severity: 'low' },
      'matched-at': 'http://localhost:3000/users/2',
    });
    const missHit = normalizeNucleiJsonl(missLine, [templated]);
    expect(missHit[0]?.file_path).toBeUndefined();
  });

  it('maps unknown severities to info rather than dropping the finding', () => {
    const odd = JSON.stringify({
      'template-id': 'x', info: { name: 'X', severity: 'weird' },
      'matched-at': 'http://localhost:3000/x',
    });
    expect(normalizeNucleiJsonl(odd, [])[0]?.severity).toBe('info');
  });

  // Additions beyond the brief's given tests, targeting the two edge cases
  // named in this task's self-review questions (a line that parses but has
  // no usable template-id; a matched-at that is not a URL) plus the
  // fingerprint-discrimination property the brief asks be judged explicitly.

  it('drops a line with no template-id rather than inventing a rule_id', () => {
    // A line missing the one field that identifies WHAT matched cannot be
    // attributed to anything real. Fabricating a placeholder rule_id (e.g.
    // 'unknown') would violate the "never fabricate a value that is not
    // known" rule; the correct move is to skip just this line, not the whole
    // batch — proven by the sibling valid LINE still producing a finding.
    const noId = JSON.stringify({
      info: { name: 'X', severity: 'low' },
      'matched-at': 'http://localhost:3000/x',
    });
    const f = normalizeNucleiJsonl(`${noId}\n${LINE}`, []);
    expect(f).toHaveLength(1);
    expect(f[0]?.rule_id).toBe('exposed-env-file');
  });

  it('does not throw on a matched-at that is not a URL, and reports no route match', () => {
    // A wrong implementation calls `new URL(matchedAt)` unguarded and lets
    // the exception propagate, losing every finding after the bad line (the
    // exact failure mode "skips blank lines and unparseable lines" already
    // guards for JSON parsing — this is the analogous guard for URL parsing).
    const odd = JSON.stringify({
      'template-id': 'weird-target',
      info: { name: 'W', severity: 'low' },
      'matched-at': 'not a url at all',
    });
    const routes = [route({ path_resolved: '/other' })];
    expect(() => normalizeNucleiJsonl(odd, routes)).not.toThrow();
    const f = normalizeNucleiJsonl(odd, routes);
    expect(f).toHaveLength(1);
    expect(f[0]?.file_path).toBeUndefined();
  });

  it('gives different templates matching the same matched-at different fingerprints', () => {
    // Guards a wrong implementation that fingerprints on (check, path) alone
    // and drops the template-id: two distinct nuclei hits reported at the
    // same URL would collide into one fingerprint, and persisting the second
    // would silently overwrite the first in storage instead of recording two
    // findings.
    const lineA = JSON.stringify({
      'template-id': 'template-a', info: { name: 'A', severity: 'low' },
      'matched-at': 'http://localhost:3000/x',
    });
    const lineB = JSON.stringify({
      'template-id': 'template-b', info: { name: 'B', severity: 'low' },
      'matched-at': 'http://localhost:3000/x',
    });
    const [a] = normalizeNucleiJsonl(lineA, []);
    const [b] = normalizeNucleiJsonl(lineB, []);
    expect(a?.fingerprint).toBeTruthy();
    expect(a?.fingerprint).not.toBe(b?.fingerprint);
  });

  it('gives the same finding the same fingerprint across separate normalisation calls', () => {
    // Fingerprint stability across runs is what lets diff_scans / set_baseline
    // / suppress_finding treat the same nuclei hit on a later scan as the
    // same finding rather than a fresh one each time.
    const [first] = normalizeNucleiJsonl(LINE, []);
    const [second] = normalizeNucleiJsonl(LINE, []);
    expect(first?.fingerprint).toBe(second?.fingerprint);
  });
});
