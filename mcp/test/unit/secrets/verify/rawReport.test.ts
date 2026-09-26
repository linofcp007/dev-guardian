/**
 * The unredacted gitleaks report `verify_live` reads, and what is left of it
 * once the raw values are taken out.
 */

import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname } from 'node:path';
import { describe, expect, it } from 'vitest';

import {
  REDACTED,
  openPrivateReportDir,
  sanitizeGitleaksReport,
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
    Match: `token = "${secret}"`,
    Secret: secret,
    File: 'app.env',
    Commit: '',
    Message: `commit message mentioning ${secret}`,
    Tags: [secret],
    Fingerprint: `app.env:${rule}:1`,
    ...extra,
  };
}

describe('sanitizeGitleaksReport', () => {
  it('returns the raw values of supported rules only, aligned with the report items', () => {
    const text = JSON.stringify([item('github-pat', GH), item('aws-access-token', AWS)]);
    const out = sanitizeGitleaksReport(text, isVerifiableRule);
    expect(out?.secrets).toEqual([GH, null]);
  });

  it('removes EVERY raw value — supported or not — from every field of every item', () => {
    // The unredacted run exposes all secrets, not only the ones verified.
    const text = JSON.stringify([
      item('github-pat', GH, { Match: `a=${GH} b=${AWS}` }),
      item('aws-access-token', AWS),
    ]);
    const out = sanitizeGitleaksReport(text, isVerifiableRule);
    expect(out).not.toBeNull();
    expect(out?.text).not.toContain(GH);
    expect(out?.text).not.toContain(AWS);
    const parsed = JSON.parse(out?.text ?? '[]') as Array<Record<string, unknown>>;
    expect(parsed.map((i) => i['Secret'])).toEqual([REDACTED, REDACTED]);
    expect(parsed[1]?.['Match']).toBe(`token = "${REDACTED}"`);
    // What the parser reads survives.
    expect(parsed.map((i) => i['RuleID'])).toEqual(['github-pat', 'aws-access-token']);
    expect(parsed[0]?.['File']).toBe('app.env');
    expect(parsed[0]?.['StartLine']).toBe(1);
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
