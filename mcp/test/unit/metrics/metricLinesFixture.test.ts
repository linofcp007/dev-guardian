/**
 * The METRIC line's contract with dev-spec-driven 1.41.0 (`metric-lines/1`) is
 * ONE file, `test/fixtures/metrics/metric-lines.v1.json`: written once and
 * committed byte-identical at dev-spec-driven's `mcp/tests/fixtures/`, both
 * suites pinning this SAME sha256. It holds the line's grammar and bounds, the
 * judge's rule, 36 lines, 5 whole outputs and 21 judge cases. The readers
 * (`src/metrics/`) are tested against it in their own files; this file holds
 * the fixture itself — its bytes, and the fields every case gives a reader.
 * A change is `metric-lines/2`: a NEW file landed in both repositories before
 * either tags, never an edit of this one.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const FIXTURE = fileURLToPath(new URL('../../fixtures/metrics/metric-lines.v1.json', import.meta.url));
const SHA256 = '55a8b9daeb03e700bcfd5487587392e667f635daa0050c55f92438b604701868';

const bytes = readFileSync(FIXTURE);
const text = bytes.toString('utf8');

type Rec = Record<string, unknown>;
const isRec = (v: unknown): v is Rec => typeof v === 'object' && v !== null && !Array.isArray(v);
const parsed: unknown = JSON.parse(text);
const fx: Rec = isRec(parsed) ? parsed : {};
const rec = (v: unknown): Rec => (isRec(v) ? v : {});
const list = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const strings = (v: unknown): string[] => list(v).filter((x): x is string => typeof x === 'string');

const V = rec(fx['vocabulary']);
const G = rec(fx['grammar']);
const KINDS = strings(V['kinds']);
const VERDICTS = strings(V['verdicts']);
const TERMS = strings(V['terms']);
const BOUNDS = strings(V['bounds']);
const BETTER = strings(G['better']);
const LINES = list(fx['lines']);
const OUTPUTS = list(fx['outputs']);
const JUDGE = list(fx['judge']);
const JUDGED = ['within', 'improved', 'regressed'];

const keysOf = (v: unknown): string => (isRec(v) ? Object.keys(v).sort().join(',') : '');
const num = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);
const count = (v: unknown): boolean => typeof v === 'number' && Number.isInteger(v) && v >= 0;
const strOrNull = (v: unknown): boolean => v === null || typeof v === 'string';
const oneLine = (v: unknown): v is string => typeof v === 'string' && !v.includes('\n');
const among = (words: string[], v: unknown): boolean => typeof v === 'string' && words.includes(v);

/** A case has exactly its fields (an absent value is null, never a missing key) and, at most, a string `note`. */
function caseKeys(c: unknown, need: string[]): boolean {
  if (!isRec(c)) return false;
  const k = Object.keys(c);
  return need.every((x) => k.includes(x)) && k.every((x) => need.includes(x) || (x === 'note' && typeof c['note'] === 'string'));
}

function tolOk(t: unknown): boolean {
  if (t === null) return true;
  return keysOf(t) === 'amount,percent' && num(rec(t)['amount']) && Number(rec(t)['amount']) >= 0 && typeof rec(t)['percent'] === 'boolean';
}

function readingOk(r: unknown): boolean {
  const o = rec(r);
  return keysOf(r) === 'better,tolerance,unit,value' && num(o['value']) && strOrNull(o['unit']) &&
    (o['better'] === null || among(BETTER, o['better'])) && tolOk(o['tolerance']);
}

function lineOk(c: unknown): boolean {
  const e = rec(rec(c)['expect']);
  if (!caseKeys(c, ['id', 'text', 'expect']) || typeof rec(c)['id'] !== 'string' || !oneLine(rec(c)['text']) || !among(KINDS, e['kind'])) return false;
  if (e['kind'] !== 'metric') return keysOf(e) === 'kind';
  return keysOf(e) === 'better,kind,name,tolerance,unit,value' && typeof e['name'] === 'string' &&
    readingOk({ value: e['value'], unit: e['unit'], better: e['better'], tolerance: e['tolerance'] });
}

function outputOk(c: unknown): boolean {
  const t = rec(c)['text'];
  const e = rec(rec(c)['expect']);
  return caseKeys(c, ['id', 'text', 'expect']) && typeof rec(c)['id'] === 'string' && typeof t === 'string' && t.includes('\n') &&
    keysOf(e) === 'dropped,malformed,metrics,repeats' && keysOf(e['metrics']) !== '' && Object.values(rec(e['metrics'])).every(readingOk) &&
    count(e['repeats']) && count(e['malformed']) && Array.isArray(e['dropped']) && e['dropped'].every((b) => among(BOUNDS, b));
}

function judgeOk(c: unknown): boolean {
  const o = rec(c);
  const e = rec(o['expect']);
  const why = e['why'];
  const verdict = e['verdict'];
  return caseKeys(c, ['id', 'reference', 'current', 'expect']) && typeof o['id'] === 'string' &&
    (o['reference'] === null || oneLine(o['reference'])) && oneLine(o['current']) &&
    keysOf(e) === 'applied,delta,loosened,verdict,why' && among(VERDICTS, verdict) &&
    (why === null || (Array.isArray(why) && why.length > 0 && why.every((w) => among(TERMS, w)))) &&
    (e['loosened'] === null || among(TERMS, e['loosened'])) &&
    (e['delta'] === null || num(e['delta'])) && (e['applied'] === null || (num(e['applied']) && Number(e['applied']) >= 0)) &&
    // new ⇔ no reference (and no delta); unjudged ⇔ a why; a judged verdict ⇔ the tolerance it applied
    (verdict === 'new') === (o['reference'] === null) && (verdict !== 'new' || e['delta'] === null) &&
    (verdict === 'unjudged') === (why !== null) && (typeof verdict === 'string' && JUDGED.includes(verdict)) === (e['applied'] !== null);
}

/** The ids of the cases a check refuses (`#<index>` for one without an id). */
function badOf(cases: unknown[], ok: (c: unknown) => boolean): string[] {
  return cases.flatMap((c, i) => (ok(c) ? [] : [typeof rec(c)['id'] === 'string' ? String(rec(c)['id']) : `#${i}`]));
}

/** Every value a judge case's `expect[field]` takes (an array's members one by one). */
function used(field: string): Set<unknown> {
  return new Set(JUDGE.flatMap((c) => {
    const v = rec(rec(c)['expect'])[field];
    return Array.isArray(v) ? v : [v];
  }));
}

describe('metric-lines.v1.json, the METRIC line contract shared with dev-spec-driven', () => {
  it('is byte for byte the file dev-spec-driven pins (sha256)', () => {
    expect(createHash('sha256').update(bytes).digest('hex')).toBe(SHA256);
  });

  it('is ASCII with LF line ends, format metric-lines/1, with one set of reader bounds and a grammar', () => {
    expect([...bytes].filter((b) => b >= 0x80 || b === 13)).toEqual([]);
    expect(text.endsWith('}\n')).toBe(true);
    expect(fx['format']).toBe('metric-lines/1');
    const bounds = rec(fx['bounds']);
    expect(keysOf(bounds)).toBe([...BOUNDS].sort().join(','));
    expect(Object.values(bounds).every((v) => typeof v === 'number' && Number.isInteger(v) && v > 0)).toBe(true);
    for (const p of [G['name'], G['number']]) {
      expect(typeof p).toBe('string');
      expect(() => new RegExp(String(p))).not.toThrow();
    }
    expect(G['numberFinite']).toBe(true);
    expect(Number.isInteger(G['unitMaxChars'])).toBe(true);
    expect(BETTER).toEqual(['lower', 'higher']);
  });

  it('gives every line case the fields a reader needs', () => {
    expect(LINES.length).toBeGreaterThanOrEqual(30);
    expect(badOf(LINES, lineOk)).toEqual([]);
  });

  it('gives every whole-output case the fields a reader needs', () => {
    expect(OUTPUTS.length).toBeGreaterThanOrEqual(4);
    expect(badOf(OUTPUTS, outputOk)).toEqual([]);
  });

  it('gives every judge case the fields a judge needs, consistent with its verdict', () => {
    expect(JUDGE.length).toBeGreaterThanOrEqual(15);
    expect(badOf(JUDGE, judgeOk)).toEqual([]);
  });

  it('holds the cases the decisions name: a TAP line, a non-ASCII name, every kind, a repeat, a dropped bound, every verdict and term', () => {
    const expects = LINES.map((c) => ({ text: String(rec(c)['text']), kind: rec(rec(c)['expect'])['kind'] }));
    for (const k of KINDS) expect(expects.some((c) => c.kind === k), k).toBe(true);
    expect(expects.some((c) => /^[ \t]*# METRIC /.test(c.text))).toBe(true);
    expect(expects.some((c) => c.kind === 'malformed' && [...c.text].some((ch) => ch.charCodeAt(0) > 0x7f))).toBe(true);
    const outs = OUTPUTS.map((c) => rec(rec(c)['expect']));
    expect(outs.some((e) => typeof e['repeats'] === 'number' && e['repeats'] > 0)).toBe(true);
    expect(outs.some((e) => list(e['dropped']).length > 0)).toBe(true);
    for (const v of VERDICTS) expect(used('verdict').has(v), v).toBe(true);
    for (const t of TERMS) {
      expect(used('loosened').has(t), `loosened ${t}`).toBe(true);
      expect(used('why').has(t), `why ${t}`).toBe(true);
    }
  });

  it('has one id per case across the three lists, and names no CI or PR', () => {
    const ids = [...LINES, ...OUTPUTS, ...JUDGE].map((c) => rec(c)['id']);
    expect(new Set(ids).size).toBe(ids.length);
    expect(/\b(?:CI|PRs?)\b/.test(text)).toBe(false);
    expect(/pull requests?/i.test(text)).toBe(false);
  });
});
