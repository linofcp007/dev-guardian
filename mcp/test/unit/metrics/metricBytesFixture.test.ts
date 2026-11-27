/**
 * The bytes of a run's output, and how each METRIC reader decodes them (`metric-bytes/1`): ONE file,
 * `test/fixtures/metrics/metric-bytes.v1.json`, written once and committed byte-identical at dev-spec-driven's
 * `mcp/tests/fixtures/`, both suites pinning this SAME sha256. Each case is a run's stdout and stderr, with two
 * decided readings: `file` (dev-guardian's `metrics --head`, a `2>&1` capture in print order) and `stream`
 * (dev-spec-driven's `done --run` / `finish --run`, each stream apart). The file reader is tested against its column
 * in `metricFile.test.ts`; this file holds the fixture itself — its bytes, every case's fields, and `differs` exactly
 * when the two readings differ. A change is `metric-bytes/2`: a NEW file landed in both repositories before either
 * tags, never an edit of this one.
 *
 * The coverage below reads the BYTES (a byte-order mark here, NUL-interleaving there), never a case's id, and none of
 * the guess's tunable numbers: those belong to `check --file`'s decoder, and the fixture binds its structure only.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const FIXTURE = fileURLToPath(new URL('../../fixtures/metrics/metric-bytes.v1.json', import.meta.url));
const LINES_FIXTURE = fileURLToPath(new URL('../../fixtures/metrics/metric-lines.v1.json', import.meta.url));
const SHA256 = '8584f38826a7c47b77594cf891141eb67f7204c0daaa778a1bcc65c56f1c9964';

const bytes = readFileSync(FIXTURE);
const text = bytes.toString('utf8');

type Rec = Record<string, unknown>;
const isRec = (v: unknown): v is Rec => typeof v === 'object' && v !== null && !Array.isArray(v);
const rec = (v: unknown): Rec => (isRec(v) ? v : {});
const list = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const strings = (v: unknown): string[] => list(v).filter((x): x is string => typeof x === 'string');
const parsed: unknown = JSON.parse(text);
const fx: Rec = rec(parsed);
const CASES = list(fx['cases']);

// The line format's own vocabulary: a reading's `dropped` names one of metric-lines/1's bounds.
const lines: Rec = rec(JSON.parse(readFileSync(LINES_FIXTURE, 'utf8')));
const BOUNDS = strings(rec(lines['vocabulary'])['bounds']);
const BETTER = strings(rec(lines['grammar'])['better']);

const keysOf = (v: unknown): string => (isRec(v) ? Object.keys(v).sort().join(',') : '');
const num = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);
const count = (v: unknown): boolean => typeof v === 'number' && Number.isInteger(v) && v >= 0;
const strOrNull = (v: unknown): boolean => v === null || typeof v === 'string';
const among = (words: string[], v: unknown): boolean => typeof v === 'string' && words.includes(v);
const hexOk = (v: unknown): v is string => typeof v === 'string' && /^(?:[0-9a-f]{2})*$/.test(v);
const hx = (v: unknown): Buffer => Buffer.from(typeof v === 'string' ? v : '', 'hex');

const NEED = ['id', 'stdout', 'stderr', 'printed', 'fileReadBytes', 'file', 'stream', 'differs'];

/** A case has exactly its fields (an absent value is null, never a missing key) and, at most, a string `note`. */
function caseKeys(c: unknown): boolean {
  if (!isRec(c)) return false;
  const k = Object.keys(c);
  return NEED.every((x) => k.includes(x)) && k.every((x) => NEED.includes(x) || (x === 'note' && typeof c['note'] === 'string'));
}

function tolOk(t: unknown): boolean {
  if (t === null) return true;
  return keysOf(t) === 'amount,percent' && num(rec(t)['amount']) && Number(rec(t)['amount']) >= 0 && typeof rec(t)['percent'] === 'boolean';
}

function metricOk(r: unknown): boolean {
  const o = rec(r);
  return keysOf(r) === 'better,tolerance,unit,value' && num(o['value']) && strOrNull(o['unit']) &&
    (o['better'] === null || among(BETTER, o['better'])) && tolOk(o['tolerance']);
}

/** metric-lines/1's output shape; `metrics` may be empty (a reader that reads nothing is a decided reading too). */
function readingOk(r: unknown): boolean {
  const o = rec(r);
  return keysOf(r) === 'dropped,malformed,metrics,repeats' && isRec(o['metrics']) && Object.values(o['metrics']).every(metricOk) &&
    count(o['repeats']) && count(o['malformed']) && Array.isArray(o['dropped']) && o['dropped'].every((b) => among(BOUNDS, b));
}

/** The two readings differ, ORDER included: a `metrics` written in another order is another reading (as dev-spec-driven reads it). */
const readingsDiffer = (c: Rec): boolean => JSON.stringify(c['file']) !== JSON.stringify(c['stream']);

function caseOk(c: unknown): boolean {
  const o = rec(c);
  if (!caseKeys(c) || typeof o['id'] !== 'string' || o['id'] === '') return false;
  if (!hexOk(o['stdout']) || !hexOk(o['stderr']) || (o['stdout'] === '' && o['stderr'] === '')) return false;
  if (!among(['stdout', 'stderr'], o['printed'])) return false;
  const capture = hx(o['stdout']).length + hx(o['stderr']).length;
  const window = o['fileReadBytes'];
  if (!(window === null || (typeof window === 'number' && Number.isInteger(window) && window > 0 && window < capture))) return false;
  if (!readingOk(o['file']) || !readingOk(o['stream'])) return false;
  const why = o['differs'];
  // differs ⇔ the readings differ: a reason on equal readings, or a difference with none, is refused.
  return readingsDiffer(o) ? typeof why === 'string' && why.trim() !== '' && !why.includes('\n') : why === null;
}

/** The ids of the cases a check refuses (`#<index>` for one without an id). */
function badOf(cases: unknown[], ok: (c: unknown) => boolean): string[] {
  return cases.flatMap((c, i) => (ok(c) ? [] : [typeof rec(c)['id'] === 'string' ? String(rec(c)['id']) : `#${i}`]));
}

const BOM8 = [0xef, 0xbb, 0xbf];
const startsWith = (b: Buffer, ...m: number[]): boolean => b.length >= m.length && m.every((x, i) => b[i] === x);
/** UTF-16LE-shaped from its first byte: no NUL in the first four even bytes, a NUL in each of the four odd ones. */
const le16Head = (b: Buffer): boolean => b.length >= 8 && [0, 2, 4, 6].every((i) => b[i] !== 0 && b[i + 1] === 0);
const nulPair = (b: Buffer): boolean => {
  for (let i = 0; i + 1 < b.length; i += 2) if (b[i] === 0 && b[i + 1] === 0) return true;
  return false;
};
/** The bytes after the last line break (a final LF is the end of the last line, not a line of its own). */
const lastLine = (b: Buffer): Buffer => {
  const s = b.subarray(0, b.length - (b[b.length - 1] === 0x0a ? 1 : 0));
  return s.subarray(s.lastIndexOf(0x0a) + 1);
};
const names = (c: Rec): string[] => [...Object.keys(rec(rec(c['file'])['metrics'])), ...Object.keys(rec(rec(c['stream'])['metrics']))];

/** The byte decisions the readers make, each held by at least one case (read from the bytes, never an id). */
const COVERAGE: Record<string, (c: Rec) => boolean> = {
  'a UTF-8 byte-order mark at the start of stdout, stderr empty': (c) =>
    startsWith(hx(c['stdout']), ...BOM8) && !startsWith(hx(c['stdout']).subarray(3), ...BOM8) && c['stderr'] === '',
  'a byte-order mark at the start of both streams': (c) => startsWith(hx(c['stdout']), ...BOM8) && startsWith(hx(c['stderr']), ...BOM8),
  'a byte-order mark after a line break inside stdout': (c) => hx(c['stdout']).includes(Buffer.from([0x0a, ...BOM8])),
  'two byte-order marks at the start': (c) => startsWith(hx(c['stdout']), ...BOM8, ...BOM8),
  'a UTF-16LE byte-order mark, the whole file read': (c) => startsWith(hx(c['stdout']), 0xff, 0xfe) && c['fileReadBytes'] === null,
  'UTF-16LE-shaped from byte 0, a NUL in its last line': (c) => le16Head(hx(c['stdout'])) && lastLine(hx(c['stdout'])).includes(0),
  'UTF-16LE-shaped from byte 0, its last line NUL-free': (c) => le16Head(hx(c['stdout'])) && !lastLine(hx(c['stdout'])).includes(0),
  'a NUL pair at an even offset (NULs on both sides)': (c) => nulPair(hx(c['stdout'])),
  'a read window over a file with a UTF-16 byte-order mark': (c) => c['fileReadBytes'] !== null && startsWith(hx(c['stdout']), 0xff, 0xfe),
  'a name printed on both streams': (c) =>
    names(c).some((n) => [c['stdout'], c['stderr']].every((h) => hx(h).includes(`METRIC ${n}=`))),
};

describe('metric-bytes.v1.json, how the two METRIC readers decode a run\'s bytes (shared with dev-spec-driven)', () => {
  it('is byte for byte the file dev-spec-driven pins (sha256)', () => {
    expect(createHash('sha256').update(bytes).digest('hex')).toBe(SHA256);
  });

  it('is ASCII with LF line ends, format metric-bytes/1 over metric-lines/1, and names no CI or PR', () => {
    expect([...bytes].filter((b) => b >= 0x80 || b === 13)).toEqual([]);
    expect(text.endsWith('}\n')).toBe(true);
    expect(fx['format']).toBe('metric-bytes/1');
    expect(fx['lineFormat']).toBe('metric-lines/1');
    expect(lines['format']).toBe('metric-lines/1');
    expect(keysOf(fx['modes'])).toBe('file,stream');
    expect(/\b(?:CI|PRs?)\b/.test(text)).toBe(false);
    expect(/pull requests?/i.test(text)).toBe(false);
  });

  it('gives every case its fields, two decided readings, and a reason exactly when the readings differ (order included)', () => {
    expect(CASES.length).toBeGreaterThanOrEqual(10);
    expect(badOf(CASES, caseOk)).toEqual([]);
    const ids = CASES.map((c) => rec(c)['id']);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('holds every byte decision the readers make, and readings that agree as well as readings that differ', () => {
    const missing = Object.entries(COVERAGE).filter(([, p]) => !CASES.some((c) => p(rec(c)))).map(([k]) => k);
    expect(missing).toEqual([]);
    expect(CASES.some((c) => !readingsDiffer(rec(c)))).toBe(true);
    expect(CASES.some((c) => readingsDiffer(rec(c)))).toBe(true);
  });
});
