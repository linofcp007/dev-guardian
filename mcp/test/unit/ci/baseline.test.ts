import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  parseBaseline, serialiseBaseline, buildBaseline, newFindings,
} from '../../../src/ci/baseline.js';
import { evaluateGate } from '../../../src/ci/gate.js';
import { CI_EXIT } from '../../../src/ci/types.js';
import { assignIdentities } from '../../../src/fingerprint/findingIdentity.js';
import { banditParser } from '../../../src/runners/scannerParsers/bandit.js';
import { gitleaksParser } from '../../../src/runners/scannerParsers/gitleaks.js';
import { semgrepParser } from '../../../src/runners/scannerParsers/semgrep.js';
import { trivyParser } from '../../../src/runners/scannerParsers/trivy.js';
import type { Finding } from '../../../src/types.js';

const FIXTURES = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'fixtures');

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
    expect(parsed?.file.entries).toEqual([]);
    expect(parsed?.dropped).toBe(0);
  });

  it('returns null for unparseable content rather than throwing', () => {
    expect(parseBaseline('{ not json')).toBeNull();
  });

  it('returns null for a JSON document of the wrong shape', () => {
    // A wrong-shaped DOCUMENT (bad version, not an object at all) is not the
    // same failure as a wrong-shaped ENTRY inside an otherwise-good document
    // — see the two tests below. There is no file to salvage here, so this
    // stays `null`.
    expect(parseBaseline('{"version":99}')).toBeNull();
    expect(parseBaseline('[]')).toBeNull();
  });

  it('drops an entry with an unrecognised severity but keeps its valid siblings, and reports the count', () => {
    // A baseline written by a FUTURE version of this tool may carry a
    // severity this build's SEVERITIES does not know about yet. Rejecting
    // the whole document over that one entry would make parseBaseline
    // return null — indistinguishable from "no baseline exists" — and
    // un-baseline every OTHER, perfectly valid entry in the same file.
    const text = JSON.stringify({
      version: 1,
      generated_at: 'x',
      entries: [
        { fingerprint: 'a', severity: 'high', title: 'A', added: 'd' },
        { fingerprint: 'b', severity: 'urgent', title: 'B', added: 'd' },
        { fingerprint: 'c', severity: 'low', title: 'C', added: 'd' },
      ],
    });
    const parsed = parseBaseline(text);
    expect(parsed).not.toBeNull();
    expect(parsed?.file.entries.map((e) => e.fingerprint)).toEqual(['a', 'c']);
    expect(parsed?.dropped).toBe(1);
  });

  it('returns a present file with zero entries, not null, when every entry is invalid', () => {
    // Distinct from an absent file: the document exists and parses, so the
    // caller must be able to tell that apart, even though nothing inside it
    // could be trusted.
    const text = JSON.stringify({
      version: 1,
      generated_at: 'x',
      entries: [
        { fingerprint: 'a', severity: 'urgent', title: 'A', added: 'd' },
        { fingerprint: 'b', severity: 'extreme', title: 'B', added: 'd' },
      ],
    });
    const parsed = parseBaseline(text);
    expect(parsed).not.toBeNull();
    expect(parsed?.file.entries).toEqual([]);
    expect(parsed?.dropped).toBe(2);
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
    expect(parseBaseline(serialiseBaseline(b))).toEqual({ file: b, dropped: 0 });
  });

  it('round-trips a file whose entries carry identities', () => {
    const b = buildBaseline([finding({ identity: 'id-1' })], null, '2026-08-14');
    expect(parseBaseline(serialiseBaseline(b))).toEqual({ file: b, dropped: 0 });
  });

  it('ends with a newline so the file is POSIX-clean in a diff', () => {
    expect(serialiseBaseline(buildBaseline([], null, 'x')).endsWith('\n')).toBe(true);
  });
});

// ------------------------------------------------------------ identity

describe('line-independent identity — an additive field on version-1 entries', () => {
  it('writes version 1, with each finding\'s identity as an extra field', () => {
    // Version stays 1 on purpose: 2.0.x rejects any other version outright
    // (its reader returns null, which is "no baseline" — every finding new),
    // while it ignores keys it does not know. See the interop block below.
    const b = buildBaseline([finding({ identity: 'id-1' }), finding({ fingerprint: 'fp2' })], null, 'd');
    expect(b.version).toBe(1);
    expect(b.entries.find((e) => e.fingerprint === 'fp1')?.identity).toBe('id-1');
    // A finding from a tool that computes no identity is still baselined, by fingerprint.
    expect(b.entries.find((e) => e.fingerprint === 'fp2')?.identity).toBeUndefined();
  });

  it('does not report a finding as new when only its fingerprint moved (a line inserted above it)', () => {
    const b = buildBaseline([finding({ fingerprint: 'at-line-10', identity: 'same' })], null, 'd');
    expect(newFindings([finding({ fingerprint: 'at-line-11', identity: 'same' })], b)).toEqual([]);
  });

  it('keeps the `added` date across that shift', () => {
    const first = buildBaseline([finding({ fingerprint: 'at-line-10', identity: 'same' })], null, '2026-01-01');
    const second = buildBaseline([finding({ fingerprint: 'at-line-11', identity: 'same' })], first, '2026-08-14');
    expect(second.entries).toHaveLength(1);
    expect(second.entries[0]).toMatchObject({ fingerprint: 'at-line-11', identity: 'same', added: '2026-01-01' });
  });

  it('reports a finding whose identity is unknown to the baseline, even if a fingerprint collides', () => {
    // Same rule, same line, redacted snippet — different code on that line.
    const b = buildBaseline([finding({ fingerprint: 'fp', identity: 'old-code' })], null, 'd');
    expect(newFindings([finding({ fingerprint: 'fp', identity: 'new-code' })], b)).toHaveLength(1);
  });

  it('writes one entry for one identity, and sorts by it so a line shift does not reorder the file', () => {
    const b = buildBaseline(
      [
        finding({ fingerprint: 'zz', identity: 'a-id' }),
        finding({ fingerprint: 'aa', identity: 'b-id' }),
        finding({ fingerprint: 'mm', identity: 'a-id' }),
      ],
      null,
      'd',
    );
    expect(b.entries.map((e) => e.identity)).toEqual(['a-id', 'b-id']);
  });

  it('still reads a version-2 file (written by a development build of this change)', () => {
    const parsed = parseBaseline(
      JSON.stringify({
        version: 2,
        generated_at: 'x',
        entries: [{ identity: 'i', fingerprint: 'a', severity: 'high', title: 'A', added: 'd' }],
      }),
    );
    expect(parsed?.file.version).toBe(2);
    expect(newFindings([finding({ fingerprint: 'moved', identity: 'i' })], parsed?.file ?? null)).toEqual([]);
    // Rewritten as version 1, dates kept.
    const rewritten = buildBaseline([finding({ fingerprint: 'moved', identity: 'i' })], parsed?.file ?? null, 'now');
    expect(rewritten).toMatchObject({ version: 1, entries: [{ identity: 'i', added: 'd' }] });
  });

  it('rejects an unknown document version and an entry whose identity is not a string', () => {
    expect(parseBaseline('{"version":3,"generated_at":"x","entries":[]}')).toBeNull();
    const parsed = parseBaseline(
      JSON.stringify({
        version: 2,
        generated_at: 'x',
        entries: [
          { identity: 'i', fingerprint: 'a', severity: 'high', title: 'A', added: 'd' },
          { identity: 7, fingerprint: 'b', severity: 'high', title: 'B', added: 'd' },
        ],
      }),
    );
    expect(parsed?.file.entries.map((e) => e.fingerprint)).toEqual(['a']);
    expect(parsed?.dropped).toBe(1);
  });
});

// ------------------------------------------------------------ a real 2.0.0 file

/**
 * `fixtures/baseline/v1-from-2.0.0.json` was written by dev-guardian 2.0.0
 * itself — its own compiled `ci/baseline.js`, `fingerprint/` and scanner
 * parsers, taken from the `v2.0.0` tag's `mcp/dist` — over the committed
 * scanner fixtures in `fixtures/scanners/` (semgrep, trivy-fs, gitleaks,
 * bandit), exactly as `dev-guardian baseline update` would have. Nothing in
 * it was typed by hand. It is what a repository that adopted the CI gate on
 * 2.0.0 has committed today, and it must keep gating.
 */
describe('a v1 baseline written by 2.0.0', () => {
  const v1Text = readFileSync(join(FIXTURES, 'baseline', 'v1-from-2.0.0.json'), 'utf8');
  const scanner = (name: string) => readFileSync(join(FIXTURES, 'scanners', name), 'utf8');

  /** The same scanner output, through today's parsers and identity. */
  function currentFindings(): Finding[] {
    return assignIdentities([
      ...semgrepParser.parse(scanner('semgrep.json')).findings,
      ...trivyParser.parse(scanner('trivy-fs.json')).findings,
      ...gitleaksParser.parse(scanner('gitleaks.json')).findings,
      ...banditParser.parse(scanner('bandit.json')).findings,
    ]);
  }

  it('still parses, as version 1, with nothing dropped', () => {
    const parsed = parseBaseline(v1Text);
    expect(parsed?.file.version).toBe(1);
    expect(parsed?.file.entries).toHaveLength(10);
    expect(parsed?.dropped).toBe(0);
  });

  it('still recognises every finding it recorded — no finding is new, and the gate passes', () => {
    const baseline = parseBaseline(v1Text)?.file ?? null;
    const findings = currentFindings();
    expect(findings).toHaveLength(10);
    expect(newFindings(findings, baseline)).toEqual([]);

    const verdict = evaluateGate({
      findings,
      baseline,
      failOn: 'info',
      steps: [{ tool: 'security_scan_full', ran: true, tools_run: [{ name: 'semgrep', status: 'ok' }], missing_tools: [] }],
      droppedBaselineEntries: 0,
    });
    expect(verdict.exitCode).toBe(CI_EXIT.PASS);
  });

  it('still reports a finding it never recorded', () => {
    const baseline = parseBaseline(v1Text)?.file ?? null;
    const extra = { ...finding({ fingerprint: 'f'.repeat(64) }), identity: 'e'.repeat(64) };
    expect(newFindings([...currentFindings(), extra], baseline)).toEqual([extra]);
  });

  it('`baseline update` adds identities, stays version 1, and keeps every `added` date', () => {
    const previous = parseBaseline(v1Text)?.file ?? null;
    const updated = buildBaseline(currentFindings(), previous, '2026-09-25T12:00:00.000Z');
    expect(updated.version).toBe(1);
    expect(updated.entries).toHaveLength(10);
    for (const entry of updated.entries) {
      expect(entry.identity).toMatch(/^[0-9a-f]{64}$/);
      expect(entry.added).toBe('2026-09-01T10:00:00.000Z');
    }
    // And the fingerprints it carries are the v1 file's, unchanged.
    expect(updated.entries.map((e) => e.fingerprint).sort()).toEqual(
      (previous?.entries ?? []).map((e) => e.fingerprint).sort(),
    );
  });

  it('once updated, survives the line shift the 2.0.0 file could not', () => {
    const withIdentities = buildBaseline(currentFindings(), parseBaseline(v1Text)?.file ?? null, 'now');
    // Every finding on a source line moves down one line; the snippets (the
    // fixtures carry real text, as `semgrep login` would) move with them.
    const shifted = assignIdentities(
      [
        ...semgrepParser.parse(shiftLines(scanner('semgrep.json'))).findings,
        ...trivyParser.parse(scanner('trivy-fs.json')).findings,
        ...gitleaksParser.parse(shiftLines(scanner('gitleaks.json'))).findings,
        ...banditParser.parse(shiftLines(scanner('bandit.json'))).findings,
      ],
    );
    const fingerprintsOnly = parseBaseline(v1Text)?.file ?? null;
    expect(newFindings(shifted, fingerprintsOnly).length).toBeGreaterThan(0); // why identity exists
    expect(newFindings(shifted, withIdentities)).toEqual([]);
  });
});

// ------------------------------------------------------------ mixed-version teams

/**
 * The shipped 2.0.0 reader, byte for byte: `fixtures/baseline/v2.0.0/` holds
 * `mcp/dist/ci/baseline.js` and `mcp/dist/types.js` exactly as the `v2.0.0`
 * tag has them (blob ids 5fb6c63 and b982268). A teammate — or a CI image —
 * still on 2.0.x runs THIS code against the file the current build writes.
 * It must read it as a baseline (not as "no baseline", which reports every
 * finding as new) and, when it regenerates the file, keep every `added` date.
 */
interface V200Entry { fingerprint: string; added: string; identity?: unknown }
interface V200File { version: number; generated_at: string; entries: V200Entry[] }
interface V200BaselineModule {
  parseBaseline(text: string | null): { file: V200File; dropped: number } | null;
  buildBaseline(findings: readonly Finding[], previous: V200File | null, now: string): V200File;
  newFindings(findings: readonly Finding[], baseline: V200File | null): Finding[];
  serialiseBaseline(file: V200File): string;
}

async function load200(): Promise<V200BaselineModule> {
  // A filesystem path, not a file:// URL: the repo path holds a space, and
  // vitest's loader does not decode the `%20` a URL would carry.
  const path = join(FIXTURES, 'baseline', 'v2.0.0', 'ci', 'baseline.js').replace(/\\/g, '/');
  return (await import(path)) as V200BaselineModule;
}

describe('a file this build writes, read by 2.0.0', () => {
  const scanner = (name: string) => readFileSync(join(FIXTURES, 'scanners', name), 'utf8');
  const findings = (): Finding[] =>
    assignIdentities([
      ...semgrepParser.parse(scanner('semgrep.json')).findings,
      ...trivyParser.parse(scanner('trivy-fs.json')).findings,
      ...gitleaksParser.parse(scanner('gitleaks.json')).findings,
      ...banditParser.parse(scanner('bandit.json')).findings,
    ]);
  const written = serialiseBaseline(buildBaseline(findings(), null, '2026-09-25T10:00:00.000Z'));

  it('is accepted by 2.0.0\'s parser, whole: nothing dropped, identities carried along', async () => {
    const v200 = await load200();
    const parsed = v200.parseBaseline(written);
    expect(parsed).not.toBeNull();
    expect(parsed?.dropped).toBe(0);
    expect(parsed?.file.entries).toHaveLength(10);
    for (const e of parsed?.file.entries ?? []) expect(e.identity).toMatch(/^[0-9a-f]{64}$/);
  });

  it('gates in 2.0.0 exactly as before: the same findings are not new', async () => {
    const v200 = await load200();
    expect(v200.newFindings(findings(), v200.parseBaseline(written)?.file ?? null)).toEqual([]);
  });

  it('2.0.0\'s `baseline update` keeps every `added` date, and this build reads the result back', async () => {
    const v200 = await load200();
    const rewrittenBy200 = v200.buildBaseline(
      findings(),
      v200.parseBaseline(written)?.file ?? null,
      '2026-10-01T00:00:00.000Z',
    );
    for (const e of rewrittenBy200.entries) expect(e.added).toBe('2026-09-25T10:00:00.000Z');

    // 2.0.0 dropped the identities it did not know; this build still matches
    // by fingerprint, keeps the dates, and puts the identities back.
    const back = parseBaseline(v200.serialiseBaseline(rewrittenBy200));
    expect(back?.dropped).toBe(0);
    expect(newFindings(findings(), back?.file ?? null)).toEqual([]);
    const restored = buildBaseline(findings(), back?.file ?? null, '2026-10-02T00:00:00.000Z');
    for (const e of restored.entries) {
      expect(e.added).toBe('2026-09-25T10:00:00.000Z');
      expect(e.identity).toMatch(/^[0-9a-f]{64}$/);
    }
  });
});

/** +1 on every line number a scanner fixture reports, and on bandit's `code` prefixes. */
function shiftLines(json: string): string {
  return json
    .replace(/"(line|StartLine|EndLine|line_number)": (\d+)/g, (_m, key: string, n: string) => `"${key}": ${Number(n) + 1}`)
    .replace(/"line_range": \[([\d, ]+)\]/g, (_m, list: string) =>
      `"line_range": [${list.split(',').map((n) => Number(n.trim()) + 1).join(', ')}]`,
    )
    .replace(/(\\n|")(\d+) /g, (_m, lead: string, n: string) => `${lead}${Number(n) + 1} `);
}
