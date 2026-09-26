/**
 * The unredacted gitleaks report `verify_live` reads, and what is left of it
 * once the raw values are taken out.
 */

import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';

import {
  REDACTED,
  STALE_AFTER_MS,
  openPrivateReportDir,
  sanitizeGitleaksReport,
  sweepStaleReportDirs,
} from '../../../../src/secrets/verify/rawReport.js';
import { isVerifiableRule } from '../../../../src/secrets/verify/providers.js';

const GH = ['ghp', 'Z'.repeat(36)].join('_');
const AWS = ['AKIA', 'IOSFODNN7', 'ABCDEFG'].join('');

function item(rule: string, secret: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    RuleID: rule,
    Description: 'd',
    StartLine: 1,
    EndLine: 1,
    StartColumn: 1,
    EndColumn: 10 + secret.length,
    Match: `token = "${secret}"`,
    Secret: secret,
    File: 'app.env',
    SymlinkFile: '',
    Commit: '',
    Entropy: 4.5,
    Author: '',
    Email: '',
    Date: '',
    Message: '',
    Tags: [],
    Fingerprint: `app.env:${rule}:1`,
    ...extra,
  };
}

/** The fields gitleaks' own `--redact` never touches — they locate a finding. */
const LOCATORS = [
  'RuleID',
  'Description',
  'StartLine',
  'EndLine',
  'StartColumn',
  'EndColumn',
  'File',
  'SymlinkFile',
  'Commit',
  'Entropy',
  'Author',
  'Email',
  'Date',
  'Fingerprint',
];

function parse(text: string | undefined): Array<Record<string, unknown>> {
  return JSON.parse(text ?? '[]') as Array<Record<string, unknown>>;
}

describe('sanitizeGitleaksReport', () => {
  it('returns the raw values of supported rules only, aligned with the report items', () => {
    const text = JSON.stringify([item('github-pat', GH), item('aws-access-token', AWS, { StartLine: 2, EndLine: 2 })]);
    const out = sanitizeGitleaksReport(text, isVerifiableRule);
    expect(out?.secrets).toEqual([GH, null]);
  });

  it('redacts each value in the fields that carry it — Secret, Match, and a Message or Tags that repeat it', () => {
    const text = JSON.stringify([
      item('github-pat', GH, { Commit: 'c1', Message: `add ${GH} and ${AWS}`, Tags: ['t', GH] }),
      item('aws-access-token', AWS, { StartLine: 5, EndLine: 5, Commit: 'c1', Message: `add ${GH} and ${AWS}` }),
    ]);
    const out = sanitizeGitleaksReport(text, isVerifiableRule);
    expect(out?.text).not.toContain(GH);
    expect(out?.text).not.toContain(AWS);
    const parsed = parse(out?.text);
    expect(parsed.map((i) => i['Secret'])).toEqual([REDACTED, REDACTED]);
    expect(parsed[0]?.['Match']).toBe(`token = "${REDACTED}"`);
    expect(parsed[1]?.['Message']).toBe(`add ${REDACTED} and ${REDACTED}`);
    expect(parsed[0]?.['Tags']).toEqual(['t', REDACTED]);
  });

  it('cross-redacts a Match that overlaps another finding on the same line', () => {
    // One generic match spanning both tokens, and each token's own finding.
    const line = `creds ${GH} ${AWS}`;
    const text = JSON.stringify([
      item('generic-api-key', `${GH} ${AWS}`.slice(0, 20), { StartColumn: 1, EndColumn: line.length, Match: line }),
      item('github-pat', GH, { StartColumn: 7, EndColumn: 6 + GH.length, Match: GH }),
      item('aws-access-token', AWS, { StartColumn: 8 + GH.length, EndColumn: 7 + GH.length + AWS.length, Match: AWS }),
    ]);
    const out = sanitizeGitleaksReport(text, isVerifiableRule);
    expect(out?.text).not.toContain(GH);
    expect(out?.text).not.toContain(AWS);
  });

  it('leaves every locator field byte-identical, even when another value is a short word found in them', () => {
    // A custom rule that reports `Secret: "test"`: scrubbing everywhere turned
    // `test/fixtures/fake.env` into `REDACTED/fixtures/fake.env`, moving the
    // finding (fingerprint, identity) and defeating `.guardianignore`.
    const items = [
      item('custom-password', 'test', {
        File: 'test/fixtures/fake.env',
        Description: 'test password',
        Fingerprint: 'test/fixtures/fake.env:custom-password:1',
        Author: 'tester',
        Email: 'test@example.com',
      }),
      item('github-pat', GH, {
        StartLine: 9,
        EndLine: 9,
        File: 'test/fixtures/other.env',
        Commit: 'deadbeefc0ffee',
        Fingerprint: 'deadbeefc0ffee:test/fixtures/other.env:github-pat:9',
      }),
      // A short hex value must not corrupt a commit id.
      item('custom-hex', 'beef', { StartLine: 3, EndLine: 3, Commit: 'deadbeefc0ffee', File: 'x.cfg' }),
    ];
    const out = sanitizeGitleaksReport(JSON.stringify(items), isVerifiableRule);
    const parsed = parse(out?.text);
    items.forEach((original, n) => {
      for (const key of LOCATORS) expect(parsed[n]?.[key], `${n}.${key}`).toEqual(original[key]);
    });
    expect(parsed[0]?.['Match']).toBe(`token = "${REDACTED}"`);
  });

  it('withholds the fields gitleaks never serializes redacted — Line, Fragment — and a Match it cannot place', () => {
    const text = JSON.stringify([
      item('github-pat', GH, { Line: `a line with ${GH} and ${AWS}`, Fragment: { Raw: `whole file ${AWS}` } }),
      { RuleID: 'aws-access-token', File: 'f', Match: `x ${AWS} ${GH}`, Secret: AWS },
    ]);
    const out = sanitizeGitleaksReport(text, isVerifiableRule);
    expect(out?.text).not.toContain(GH);
    expect(out?.text).not.toContain(AWS);
    const parsed = parse(out?.text);
    expect(parsed[0]?.['Line']).toBe(REDACTED);
    expect(parsed[0]?.['Fragment']).toBe(REDACTED);
    expect(parsed[1]?.['Match']).toBe(REDACTED);
  });

  it('an item with no usable Secret has its Match withheld too', () => {
    const text = JSON.stringify([{ RuleID: 'github-pat', File: 'f', Match: `x ${GH}`, Secret: '' }]);
    const out = sanitizeGitleaksReport(text, isVerifiableRule);
    expect(out?.text).not.toContain(GH);
    expect(out?.secrets).toEqual([null]);
  });

  it('is null for anything that is not a JSON array — never passed on, since it may hold raw values', () => {
    expect(sanitizeGitleaksReport(`not json ${GH}`, isVerifiableRule)).toBeNull();
    expect(sanitizeGitleaksReport(JSON.stringify({ Secret: GH }), isVerifiableRule)).toBeNull();
  });

  it('stays near-linear: ~5k findings — half of them on ONE line, all in ONE commit — well within budget', () => {
    // The first version cross-scrubbed every string of every item against
    // every distinct value: 3000 items took 16.8 s, 6000 took 66 s, and the
    // MCP server was frozen for all of it.
    const items: Array<Record<string, unknown>> = [];
    const message = `bulk import ${'x'.repeat(200)}`;
    for (let n = 0; n < 2_500; n += 1) {
      const secret = `tok_${String(n).padStart(6, '0')}_${'q'.repeat(24)}`;
      const col = 1 + n * (secret.length + 1);
      items.push(
        item('generic-api-key', secret, {
          File: 'dist/bundle.min.js',
          StartColumn: col,
          EndColumn: col + secret.length - 1,
          Match: secret,
          Commit: 'c0ffee',
          Message: message,
        }),
      );
    }
    for (let n = 0; n < 2_500; n += 1) {
      const secret = ['ghp', `${String(n).padStart(6, '0')}${'W'.repeat(30)}`].join('_');
      items.push(
        item('github-pat', secret, { File: `src/f${n}.ts`, StartLine: 1 + (n % 40), EndLine: 1 + (n % 40), Commit: 'c0ffee', Message: message }),
      );
    }
    const text = JSON.stringify(items);
    const started = performance.now();
    const out = sanitizeGitleaksReport(text, isVerifiableRule);
    const elapsed = performance.now() - started;
    expect(out?.secrets.filter((s) => s !== null)).toHaveLength(2_500);
    expect(out?.text).not.toContain('tok_000123_');
    expect(out?.text).not.toContain(['ghp', `000123${'W'.repeat(30)}`].join('_'));
    // Measured ~50 ms; the budget is for a loaded machine, not a benchmark.
    expect(elapsed).toBeLessThan(3_000);
  });
});

describe('openPrivateReportDir', () => {
  it('creates a private directory and report files, and removes them', () => {
    const dir = openPrivateReportDir();
    const file = dir.pathFor('secrets-history.json');
    expect(dirname(file)).toBe(dir.dir);
    expect(basename(dir.dir)).toMatch(/^guardian-verify-/);
    expect(existsSync(file)).toBe(true);
    if (process.platform !== 'win32') {
      expect(statSync(dir.dir).mode & 0o777).toBe(0o700);
      expect(statSync(file).mode & 0o777).toBe(0o600);
    }
    writeFileSync(file, JSON.stringify([item('github-pat', GH)]));
    expect(readFileSync(file, 'utf8')).toContain(GH);
    expect(dir.remove()).toBeNull();
    expect(existsSync(dir.dir)).toBe(false);
  });
});

describe('sweepStaleReportDirs — what a killed scan left behind', () => {
  function makeDir(root: string, name: string, ageMs: number): string {
    const p = join(root, name);
    mkdirSync(p);
    writeFileSync(join(p, 'secrets.json'), '[]');
    const t = new Date(Date.now() - ageMs);
    utimesSync(p, t, t);
    return p;
  }

  it('removes only stale guardian-verify-* directories — never a fresh one, another name, or a symlink', () => {
    const root = mkdtempSync(join(tmpdir(), 'sweep-root-'));
    try {
      const stale = makeDir(root, 'guardian-verify-stale1', STALE_AFTER_MS + 60_000);
      const fresh = makeDir(root, 'guardian-verify-fresh1', 60_000);
      const other = makeDir(root, 'guardian-gitleaks-old1', STALE_AFTER_MS + 60_000);
      const target = makeDir(root, 'not-ours', STALE_AFTER_MS + 60_000);
      let link: string | null = join(root, 'guardian-verify-link1');
      try {
        symlinkSync(target, link, 'junction');
        const t = new Date(Date.now() - STALE_AFTER_MS - 60_000);
        utimesSync(link, t, t);
      } catch {
        link = null; // no symlink privilege here: that half is not exercised
      }
      const removed = sweepStaleReportDirs(root);
      expect(existsSync(stale)).toBe(false);
      expect(existsSync(fresh)).toBe(true);
      expect(existsSync(other)).toBe(true);
      expect(existsSync(join(target, 'secrets.json'))).toBe(true);
      if (link !== null) expect(readdirSync(root)).toContain('guardian-verify-link1');
      expect(removed).toBe(1);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('never throws — an unreadable root sweeps nothing', () => {
    expect(sweepStaleReportDirs(join(tmpdir(), 'no-such-dir-for-sweep', 'x'))).toBe(0);
  });

  it('openPrivateReportDir sweeps the OS temp directory as it opens', () => {
    const stale = join(tmpdir(), `guardian-verify-sweeptest${process.pid}`);
    mkdirSync(stale, { recursive: true });
    const t = new Date(Date.now() - STALE_AFTER_MS - 60_000);
    utimesSync(stale, t, t);
    const dir = openPrivateReportDir();
    try {
      expect(existsSync(stale)).toBe(false);
    } finally {
      dir.remove();
      rmSync(stale, { recursive: true, force: true });
    }
  });
});
