/**
 * Review 10, finding 5 (MEDIUM, a 3.3.0 regression): replacing a baselined
 * secret IN PLACE passed the gate. The tolerant `match_id` keys a secret by
 * (rule, path, occurrence), and the base commit's secret and the pull
 * request's, on the same line of history, were one occurrence — so the
 * baseline's key matched the new secret. The gate now reads each finding's
 * value in memory (`ci/secretValues.ts`, an HMAC under a per-process key)
 * and keys a slot holding two values by nothing.
 *
 * Real git repositories; the findings are what gitleaks reports for them
 * (locators `rule=…;commit=…`), so no gitleaks is needed.
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { buildBaseline, newFindings } from '../../../src/ci/baseline.js';
import { rememberSecretValues, secretFromLine, secretValueOf, secretValuesRead } from '../../../src/ci/secretValues.js';
import { assignIdentities } from '../../../src/fingerprint/findingIdentity.js';
import { resolveProjectPath } from '../../../src/platform/projectPath.js';
import type { Finding } from '../../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const OLD = `AKIA${'QWERTYUIOPASDFGH'}`;
const NEW = `AKIA${'ZXCVBNMLKJHGFDSA'}`;
const FILE = 'config/app.js';

function git(dir: string, ...args: string[]): string {
  return execFileSync('git', ['-C', dir, ...args], { encoding: 'utf8' }).trim();
}

function write(dir: string, body: string): void {
  writeFileSync(join(dir, ...FILE.split('/')), body);
}

function commit(dir: string, body: string, message: string): string {
  write(dir, body);
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '-m', message);
  return git(dir, 'rev-parse', 'HEAD');
}

const body = (key: string, pad = ''): string => `module.exports = {\n  a: 1,\n  key:${pad} "${key}",\n};\n`;

function repo(): { dir: string; base: string } {
  const dir = resolveProjectPath(makeTempDir('secret-values-')).path;
  git(dir, 'init', '-q');
  git(dir, 'config', 'user.email', 't@example.com');
  git(dir, 'config', 'user.name', 'T');
  git(dir, 'config', 'commit.gpgsign', 'false');
  git(dir, 'config', 'core.autocrlf', 'false');
  mkdirSync(join(dir, 'config'));
  return { dir, base: commit(dir, body(OLD), 'base') };
}

/** A gitleaks finding on line 3 of FILE: in history at `sha`, or in the working tree. */
function leak(fingerprint: string, sha: string | null): Finding {
  return {
    fingerprint,
    tool: 'gitleaks',
    rule_id: 'aws-access-token',
    subcategory: 'secret',
    severity: 'high',
    category: 'security',
    title: 'AWS',
    file_path: FILE,
    line_start: 3,
    line_end: 3,
    snippet: sha === null ? 'rule=aws-access-token' : `rule=aws-access-token;commit=${sha}`,
    fix_available: false,
  };
}

async function judged(dir: string, findings: Finding[]): Promise<Finding[]> {
  const all = assignIdentities(findings);
  await rememberSecretValues(dir, all);
  return all;
}

describe('review 10, finding 5: a secret replaced in place is new', () => {
  it('a commit replacing the baselined secret on its line: the new one is new (the old commit still known)', async () => {
    const { dir, base } = repo();
    const baseline = buildBaseline(await judged(dir, [leak('h-old', base)]), null, '2026-01-01');
    const next = commit(dir, body(NEW), 'replace the key');
    const after = await judged(dir, [leak('h-old', base), leak('h-new', next)]);
    expect(newFindings(after, baseline).map((f) => f.fingerprint)).toEqual(['h-new']);
  });

  it('an uncommitted replacement: the working-tree copy is new', async () => {
    const { dir, base } = repo();
    const baseline = buildBaseline(await judged(dir, [leak('h-old', base)]), null, '2026-01-01');
    write(dir, body(NEW));
    const after = await judged(dir, [leak('h-old', base), leak('w-new', null)]);
    expect(newFindings(after, baseline).map((f) => f.fingerprint)).toEqual(['w-new']);
  });

  it('what the tolerance is for still holds: a whitespace commit and an unrelated edit, the same value', async () => {
    const { dir, base } = repo();
    const baseline = buildBaseline(await judged(dir, [leak('h-old', base)]), null, '2026-01-01');
    const spaced = commit(dir, body(OLD, '   '), 'whitespace');
    // An uncommitted edit elsewhere in the file: the files pass sees it too.
    write(dir, `${body(OLD, '   ')}// note\n`);
    const after = await judged(dir, [leak('h-old', base), leak('h-ws', spaced), leak('w-same', null)]);
    expect(newFindings(after, baseline)).toEqual([]);
  });

  it('a 3.3 baseline (keys written without values) still matches the unchanged secret', async () => {
    const { dir, base } = repo();
    const old = buildBaseline(assignIdentities([leak('h-old', base)]), null, '2026-01-01');
    // A squash merge: the same secret, in a commit the baseline never saw.
    git(dir, 'checkout', '-q', '--orphan', 'squashed');
    const squashed = commit(dir, body(OLD), 'squashed');
    expect(newFindings(await judged(dir, [leak('h-squash', squashed)]), old)).toEqual([]);
  });

  it('a value that cannot be read never matches through the tolerant key', async () => {
    const { dir, base } = repo();
    const baseline = buildBaseline(await judged(dir, [leak('h-old', base)]), null, '2026-01-01');
    const gone = 'c'.repeat(40);
    const after = await judged(dir, [leak('h-old', base), leak('h-gone', gone)]);
    expect(secretValueOf(after[1] as Finding)).toBeUndefined();
    expect(newFindings(after, baseline).map((f) => f.fingerprint)).toEqual(['h-gone']);
  });

  it('values are an HMAC of the whitespace-free line, never the secret; nothing read means nothing compared', async () => {
    const { dir, base } = repo();
    const [f] = await judged(dir, [leak('h-old', base)]);
    const value = f === undefined ? undefined : secretValueOf(f);
    expect(value).toMatch(/^[0-9a-f]{64}$/);
    expect(value).not.toContain(OLD);
    expect(readFileSync(join(dir, ...FILE.split('/')), 'utf8')).toContain(OLD);
    expect(secretValuesRead(assignIdentities([leak('x', base)]))).toBe(false);
  });
});

/**
 * Review 11, finding 2: the value is the secret gitleaks matched, cut from the
 * line where its report says (`secretFromLine`) — so a comment appended to the
 * line, or the same value on another line, is the same value. gitleaks counts
 * columns from the newline before a line: exact on the first line of what it
 * scanned as one piece, one late on every other.
 */
describe('secretFromLine: the secret, cut where the redacted report says', () => {
  const entropy = (s: string): number => {
    const counts = new Map<string, number>();
    for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
    let e = 0;
    for (const n of counts.values()) e -= (n / s.length) * Math.log2(n / s.length);
    return Math.fround(e);
  };
  // Its last character occurs twice in it, so the cut one byte to its left
  // (the quote in that character's place) has another entropy.
  const TWICE = `AKIA${'QWERTYUIOPASDFGA'}`;
  const LINE = `const KEY = "${TWICE}"; // note`;
  const at = LINE.indexOf(TWICE);

  it('exact and one column late: the entropy picks the cut', () => {
    const exact = { startColumn: at + 1, endColumn: at + TWICE.length, match: 'REDACTED', entropy: entropy(TWICE) };
    const late = { ...exact, startColumn: at + 2, endColumn: at + TWICE.length + 1 };
    expect(secretFromLine(LINE, exact)).toBe(TWICE);
    expect(secretFromLine(LINE, late)).toBe(TWICE);
    expect(secretFromLine(`${LINE} // and more`, late)).toBe(TWICE);
  });

  it('a redacted match with its context: the context must be on the line', () => {
    const line = `api_key = "${NEW}"`;
    const m = { startColumn: 1, endColumn: line.length, match: 'api_key = "REDACTED"', entropy: entropy(NEW) };
    expect(secretFromLine(line, m)).toBe(NEW);
    expect(secretFromLine(line.replace('api_key', 'api_kez'), m)).toBeNull();
  });

  it('both cuts read as a secret: the fragment decides, and unknown is no cut', () => {
    // A last character that occurs once: the one-left cut (quote first) has the same entropy.
    const key = 'AKIA' + 'BCDEFGHIJKLMNOPQ';
    const line = `k = "${key}";`;
    const start = line.indexOf(key);
    const m = { startColumn: start + 1, endColumn: start + key.length, match: 'REDACTED', entropy: entropy(key) };
    expect(secretFromLine(line, m, true)).toBe(key);
    expect(secretFromLine(line, m, false)).toBe(`"${key.slice(0, -1)}`);
    expect(secretFromLine(line, m)).toBeNull();
  });

  it('a wrong entropy, or a column off the line, is no cut', () => {
    expect(secretFromLine(LINE, { startColumn: at + 1, endColumn: at + TWICE.length, match: "REDACTED", entropy: 0.5 })).toBeNull();
    expect(secretFromLine(LINE, { startColumn: 500, endColumn: 519, match: 'REDACTED' })).toBeNull();
  });
});
