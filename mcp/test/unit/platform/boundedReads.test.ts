/**
 * Bytes read are not memory used (review of 3.0, W2E, round 2, C1).
 *
 * Every file here was under its read cap and still took the server down:
 * 60 MiB of `{},` in a `package-lock.json` (under the 64 MiB lock cap) made
 * `JSON.parse` build tens of millions of objects; a `yarn.lock` of 60 MiB of
 * newlines became 60 million strings through `.split(/\r?\n/)`; `detect_stack`
 * read eighty `requirements-N.txt` of just under 8 MiB each and concatenated
 * them. So a parse is bounded by the document's STRUCTURE before it runs,
 * lines are iterated rather than split, a lock is parsed only below a cap far
 * under the read cap, and one walk shares one byte-and-file budget whose
 * overflow is named.
 *
 * Measured in `node:22` (22.23.2) under `docker run --memory 768m` (396 MiB
 * heap), one process per shape, before (ada72f20) → after (this change):
 *
 *   package-lock `{},` 8 MiB     2461 ms, 186 MB heap, gap dropped → 3 ms, 67 MiB RSS, gap kept
 *   package-lock `{},` 30/60 MiB  out of heap                      → 4–5 ms, 67 MiB RSS
 *   package-lock `1,` 60 MiB      OOM-killed (cgroup)              → 3 ms, 67 MiB RSS
 *   yarn.lock of newlines 30/60   out of heap (GC saw 659 MB)      → 3–6 ms, 67 MiB RSS
 *   detect_stack, 40 × 8 MiB reqs 646 MB heap, 713 MiB RSS, 1.6 s  → 284 ms, 24 MB heap, 103 MiB RSS
 *   detect_stack, 80 × 8 MiB reqs out of heap                      → 264 ms, 24 MB heap, 103 MiB RSS
 *   .semgrep.yml dense YAML 1 MiB out of heap                      → 9 ms, 59 MiB RSS
 *
 * The test below holds the shapes, at sizes a unit test can afford.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { JSON_MAX_NODES, parseJsonBounded } from '../../../src/platform/boundedJson.js';
import { parseYamlBounded, YAML_CONFIG_MAX_NODES } from '../../../src/platform/boundedParse.js';
import { describeReadRefusal, ReadBudget } from '../../../src/platform/projectFs.js';
import { textLines } from '../../../src/platform/textLines.js';
import { assessManifestCoverage } from '../../../src/runners/scannerParsers/trivy.js';
import { DETECTION_BUDGET_BYTES, detectStack } from '../../../src/runners/stackDetect.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

describe('textLines — lines without an array', () => {
  it('yields every line, \\r\\n and \\n alike; a trailing newline adds no empty line', () => {
    expect([...textLines('a\r\nb\n\nc')]).toEqual(['a', 'b', '', 'c']);
    expect([...textLines('')]).toEqual([]);
    expect([...textLines('x\n')]).toEqual(['x']);
  });

  it('stops when the caller stops: the first line of 8 MiB of newlines costs one string', () => {
    const it8 = textLines('\n'.repeat(8 * 1024 * 1024));
    expect(it8.next().value).toBe('');
  });
});

describe('parseJsonBounded — refused by structure, before JSON.parse runs', () => {
  it('a real document parses; a BOM is tolerated', () => {
    expect(parseJsonBounded('﻿{"a":[1,2,{"b":null}]}')).toEqual({ ok: true, value: { a: [1, 2, { b: null }] } });
  });

  it('[{},{},…] past the node bound is too complex — quickly, and without parsing', () => {
    const text = `[${'{},'.repeat(JSON_MAX_NODES)}{}]`;
    const t0 = Date.now();
    expect(parseJsonBounded(text)).toEqual({ ok: false, reason: 'too-complex' });
    expect(Date.now() - t0).toBeLessThan(5_000);
  });

  it('[1,1,…] is counted too: one array of numbers is not one node', () => {
    expect(parseJsonBounded(`[${'1,'.repeat(100)}1]`, 50)).toEqual({ ok: false, reason: 'too-complex' });
  });

  it('invalid JSON says so', () => {
    expect(parseJsonBounded('{').ok).toBe(false);
  });
});

describe('parseYamlBounded', () => {
  it('a real configuration parses', () => {
    expect(parseYamlBounded('rules:\n  - id: a\n    pattern: x\n')).toEqual({ ok: true, value: { rules: [{ id: 'a', pattern: 'x' }] } });
  });

  it('a flow sequence past the node bound is too complex', () => {
    expect(parseYamlBounded(`[${'1,'.repeat(YAML_CONFIG_MAX_NODES)}1]`)).toMatchObject({ ok: false, reason: 'too-complex' });
  });
});

describe('ReadBudget — one budget per walk, its overflow named', () => {
  it('refuses the read that would pass the byte budget, and every read after it, by name', () => {
    const dir = makeTempDir('budget-');
    for (const n of ['a', 'b', 'c']) writeFileSync(join(dir, n), 'x'.repeat(600));
    const budget = new ReadBudget(1000, 10);
    expect(budget.readText(dir, 'a', 4096)).toMatchObject({ status: 'ok' });
    expect(budget.readText(dir, 'b', 4096)).toEqual({ status: 'refused', reason: 'read-budget' });
    expect(budget.readText(dir, 'c', 4096)).toEqual({ status: 'refused', reason: 'read-budget' });
    expect(budget.refused).toEqual(['b', 'c']);
    expect(budget.spent).toBe(true);
    expect(describeReadRefusal('read-budget')).toBe("it was not read: this check's read budget was spent before it");
  });

  it('the file budget counts too', () => {
    const dir = makeTempDir('budget-');
    for (const n of ['a', 'b']) writeFileSync(join(dir, n), 'x');
    const budget = new ReadBudget(1 << 20, 1);
    expect(budget.readText(dir, 'a', 16)).toMatchObject({ status: 'ok' });
    expect(budget.readText(dir, 'b', 16)).toEqual({ status: 'refused', reason: 'read-budget' });
  });
});

describe("Trivy's coverage — a lock too large to be parsed keeps the gap", () => {
  it('a package-lock.json of {} past the parse cap is not parsed: the manifest stays a gap, "not checked"', () => {
    const dir = makeTempDir('cov-lock-');
    writeFileSync(join(dir, 'package.json'), '{"name":"x"}');
    // 300 KiB: over the 256 KiB a lock that locks nothing could ever be, far under the 64 MiB read cap.
    writeFileSync(join(dir, 'package-lock.json'), `{"packages":{"":{}},"x":[${'{},'.repeat(100_000)}{}]}`);
    const t0 = Date.now();
    const cov = assessManifestCoverage(dir, '{"Results":[]}');
    expect(Date.now() - t0).toBeLessThan(5_000);
    expect(cov.gaps.flatMap((g) => g.files)).toEqual(['package.json']);
  });

  it('a yarn.lock of newlines past the scan cap keeps the gap too', () => {
    const dir = makeTempDir('cov-yarn-');
    writeFileSync(join(dir, 'package.json'), '{"name":"x"}');
    writeFileSync(join(dir, 'yarn.lock'), '\n'.repeat(1024 * 1024));
    expect(assessManifestCoverage(dir, '{"Results":[]}').gaps.flatMap((g) => g.files)).toEqual(['package.json']);
  });

  it('the same package.json beside a lock that locks nothing is no gap (the control)', () => {
    const dir = makeTempDir('cov-ok-');
    writeFileSync(join(dir, 'package.json'), '{"name":"x"}');
    writeFileSync(join(dir, 'package-lock.json'), '{"packages":{"":{}}}');
    expect(assessManifestCoverage(dir, '{"Results":[]}').gaps).toEqual([]);
  });
});

describe('detect_stack — one byte budget for the whole detection, its overflow named', () => {
  it(`files past ${DETECTION_BUDGET_BYTES / (1024 * 1024)} MiB are named in unread_files, never concatenated`, () => {
    const dir = makeTempDir('stack-budget-');
    mkdirSync(join(dir, 'svc'));
    writeFileSync(join(dir, 'requirements.txt'), 'django==4.2\n');
    // Ten files just under the 8 MiB manifest cap: 80 MiB, past the 64 MiB budget.
    const body = Buffer.alloc(8 * 1024 * 1024 - 16, 0x23);
    for (let i = 0; i < 10; i++) writeFileSync(join(dir, `requirements-${i}.txt`), body);
    const t0 = Date.now();
    const s = detectStack(dir);
    expect(Date.now() - t0).toBeLessThan(20_000);
    expect(s.languages).toContain('python');
    const budget = (s.unread_files ?? []).filter((u) => /read budget/.test(u.reason));
    expect(budget.length).toBeGreaterThanOrEqual(2);
    expect(budget.map((u) => u.path).filter((p) => !/^requirements.*\.txt$/.test(p))).toEqual([]);
  }, 60_000);
});
