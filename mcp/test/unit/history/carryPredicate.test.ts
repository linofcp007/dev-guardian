/**
 * The open set's carry-forward reads a finding's fate off a per-key scope
 * (`chainScope` + `scopeAdmits`) and labels it with the per-finding verdict
 * (`openGapFor`, which calls the same `answerFor` every comparison uses).
 * Fix round 2 split them for speed; this holds them EQUAL over random
 * bookkeeping — a finding is carried by the scope exactly when every newer
 * scan's `openGapFor` names a gap; the read the carry makes by tool
 * (`toolsOfKey`) never misses such a finding; and the fold stays one
 * constraint on a long chain, and closes when no file is in every one.
 *
 * Fix round 3 indexes the chain once per key and reads each holder's scope
 * through the scans able to look at its targets (`ChainIndex`), carrying
 * one fold per kind of holder across a GROWING chain — so the property is
 * also checked the way the walk uses it: one index, many holders, the chain
 * growing between them.
 */

import { describe, expect, it } from 'vitest';
import { ChainIndex, chainScope, MAX_ADMIT_PAIRS, meetAdmit, openGapFor, scopeAdmits, type Admit, type Bookkeeping } from '../../../src/history/runCompare.js';
import { findingKey, toolsOfKey } from '../../../src/history/runNames.js';
import type { Finding, ToolRun } from '../../../src/types.js';

/** mulberry32: a small seeded PRNG, so a failure reproduces. */
function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const NAMES = ['semgrep', 'bandit', 'trivy', 'trivy-image', 'trivy-dockerfile', 'nuclei', 'guardian-dast', 'gitleaks', 'mystery-tool'];
const FILES = ['wp/a.php', 'src/b.js', 'app.py', 'registry/app:1 (alpine)'];
const RULES = ['r1', 'r2', 'r3'];
const IMAGES = ['nginx', 'nginx:latest', 'docker.io/library/nginx:latest', 'registry/app:1', 'registry/app:2', 'ghcr.io/o/x@sha256:ab'];

function pick<T>(r: () => number, xs: readonly T[]): T {
  const x = xs[Math.floor(r() * xs.length)];
  if (x === undefined) throw new Error('empty choice');
  return x;
}

function randomBook(r: () => number): Bookkeeping {
  if (r() < 0.05) return { tools_run: [], missing_tools: [] };
  const tools_run: ToolRun[] = [];
  const count = 1 + Math.floor(r() * 4);
  for (let i = 0; i < count; i++) {
    const name = pick(r, NAMES);
    const status = pick(r, ['ok', 'ok', 'ok', 'failed', 'skipped'] as const);
    const run: ToolRun = { name, status };
    if (name === 'trivy-image') {
      // A legacy row recorded no image at all.
      if (r() < 0.8) run.target = pick(r, IMAGES);
    }
    // One or two of each, so a chain's meets are sometimes empty, sometimes not.
    if (status === 'ok' && r() < 0.3) {
      run.partially_parsed = Array.from({ length: 1 + Math.floor(r() * 2) }, () => ({ file: pick(r, FILES), type: 'PartialParsing', message: 'x' }));
    }
    if (status === 'ok' && r() < 0.2) {
      run.failed_rules = Array.from({ length: 1 + Math.floor(r() * 2) }, () => ({ rule_id: pick(r, RULES), message: 'x' }));
    }
    tools_run.push(run);
  }
  const missing_tools = r() < 0.4 ? [pick(r, NAMES)] : [];
  return { tools_run, missing_tools };
}

function randomFinding(r: () => number): Finding {
  const tool = pick(r, ['semgrep', 'bandit', 'trivy', 'nuclei', 'dast', 'gitleaks', 'mystery-tool']);
  const f: Finding = {
    fingerprint: 'fp',
    tool,
    severity: 'high',
    category: tool === 'trivy' && r() < 0.5 ? 'license' : 'security',
    title: 't',
    file_path: pick(r, FILES),
    rule_id: pick(r, RULES),
    fix_available: false,
  };
  if (tool === 'trivy') f.subcategory = pick(r, ['cve', 'dockerfile', 'secret']);
  return f;
}

describe('carry-forward: the per-key scope and the per-finding verdict agree', () => {
  it('over 60 000 random chains: scope admits a finding exactly when every newer scan leaves it open', () => {
    const r = prng(20260926);
    let carried = 0;
    for (let n = 0; n < 60_000; n++) {
      const holder = randomBook(r);
      const chain = Array.from({ length: 1 + Math.floor(r() * 4) }, () => randomBook(r));
      const f = randomFinding(r);
      const byVerdict = chain.every((asked) => openGapFor(holder, asked, f) !== null);
      const file = f.file_path?.replace(/\\/g, '/');
      const byScope = scopeAdmits(chainScope(holder, chain, findingKey(f)), file, f.rule_id);
      if (byScope !== byVerdict) {
        throw new Error(`disagree at case ${n}: ${JSON.stringify({ holder, chain, f, byScope, byVerdict })}`);
      }
      if (byVerdict) carried += 1;
    }
    // Guard the generator: it must exercise both outcomes.
    expect(carried).toBeGreaterThan(1000);
  });

  it("the carry's read by tool never misses a finding of the key it reads for (toolsOfKey inverts findingKey)", () => {
    const r = prng(7);
    const tools = ['semgrep', 'bandit', 'trivy', 'nuclei', 'dast', 'gitleaks', 'npm-audit', 'guardian-scanskill', 'mystery-tool'];
    for (let n = 0; n < 5000; n++) {
      const f = randomFinding(r);
      f.tool = pick(r, tools);
      if (f.tool === 'guardian-scanskill' && r() < 0.5) f.rule_id = 'osv-vulnerable-dependency';
      if (f.tool === 'trivy') f.file_path = pick(r, ['package-lock.json', 'composer.lock', 'Dockerfile', 'registry/app:1 (alpine)']);
      expect(toolsOfKey(findingKey(f))).toContain(f.tool);
    }
  });

  it('a long chain whose newer scans each partly parse another file stops folding: nothing is in all of them', () => {
    const holder: Bookkeeping = { tools_run: [{ name: 'semgrep', status: 'ok' }], missing_tools: [] };
    const partial = (...files: string[]): Bookkeeping => ({
      tools_run: [{ name: 'semgrep', status: 'ok', partially_parsed: files.map((file) => ({ file, type: 'PartialParsing', message: 'x' })) }],
      missing_tools: ['semgrep'],
    });
    const f: Finding = { fingerprint: 'fp', tool: 'semgrep', severity: 'high', category: 'security', title: 't', file_path: 'wp/a.php', rule_id: 'r1', fix_available: false };
    // a.php in both: still open, one constraint however long the chain.
    const same = Array.from({ length: 500 }, () => partial('wp/a.php', 'src/b.js'));
    const open = chainScope(holder, same, 'semgrep');
    expect(open).toEqual({ kind: 'open', admit: { all: false, files: new Set(['wp/a.php', 'src/b.js']), rules: new Set(), pairs: new Map() } });
    expect(scopeAdmits(open, 'wp/a.php', 'r1')).toBe(true);
    // Two scans that partly parsed different files: no finding is in both.
    expect(chainScope(holder, [partial('wp/a.php'), partial('src/b.js')], 'semgrep')).toEqual({ kind: 'never' });
    expect([partial('wp/a.php'), partial('src/b.js')].every((asked) => openGapFor(holder, asked, f) !== null)).toBe(false);
  });

  it('a partial parse AND a different rule not loaded in every newer scan stays bounded, and closes (M-4)', () => {
    const holder: Bookkeeping = { tools_run: [{ name: 'semgrep', status: 'ok' }], missing_tools: [] };
    const gap = (i: number): Bookkeeping => ({
      tools_run: [
        {
          name: 'semgrep',
          status: 'ok',
          partially_parsed: [{ file: `f${i}.php`, type: 'PartialParsing', message: 'x' }],
          failed_rules: [{ rule_id: `r${i}`, message: 'x' }],
        },
      ],
      missing_tools: ['semgrep'],
    });
    const f = (file: string, rule: string): Finding => ({ fingerprint: 'fp', tool: 'semgrep', severity: 'high', category: 'security', title: 't', file_path: file, rule_id: rule, fix_available: false });
    const two = [gap(0), gap(1)];
    // (f0 or r0) and (f1 or r1): exactly the two crossed pairs.
    for (const [file, rule, open] of [['f0.php', 'r1', true], ['f1.php', 'r0', true], ['f0.php', 'r0', false], ['f9.php', 'r9', false]] as const) {
      expect(scopeAdmits(chainScope(holder, two, 'semgrep'), file, rule)).toBe(open);
      expect(two.every((asked) => openGapFor(holder, asked, f(file, rule)) !== null)).toBe(open);
    }
    const index = new ChainIndex();
    const t0 = performance.now();
    for (let i = 0; i < 5000; i++) index.push(gap(i));
    expect(index.scope(holder, 'semgrep')).toEqual({ kind: 'never' });
    expect(performance.now() - t0).toBeLessThan(2000);
  });

  it('one index, a growing chain, many holders: the scope still agrees with every newer scan\'s verdict', () => {
    const r = prng(31337);
    let carried = 0;
    let checks = 0;
    for (let history = 0; history < 400; history++) {
      const books = Array.from({ length: 2 + Math.floor(r() * 12) }, () => randomBook(r));
      const index = new ChainIndex();
      const chain: Bookkeeping[] = [];
      for (const holder of books) {
        if (chain.length > 0) {
          for (let k = 0; k < 6; k++) {
            const f = randomFinding(r);
            const byVerdict = chain.every((asked) => openGapFor(holder, asked, f) !== null);
            const byScope = scopeAdmits(index.scope(holder, findingKey(f)), f.file_path?.replace(/\\/g, '/'), f.rule_id);
            checks += 1;
            if (byScope !== byVerdict) {
              throw new Error(`disagree in history ${history}: ${JSON.stringify({ holder, chain, f, byScope, byVerdict })}`);
            }
            if (byVerdict) carried += 1;
          }
        }
        index.push(holder);
        chain.push(holder);
      }
    }
    expect(checks).toBeGreaterThan(10_000);
    expect(carried).toBeGreaterThan(500);
  });
});

/**
 * Round 3's review, M-2: two disjoint sets of W partly parsed files and W
 * rules not loaded, alternating over 2000 scans, cost W x W per step (17.6 s
 * at W = 200). A constraint already met is skipped (exact), and a meet past
 * MAX_ADMIT_PAIRS keeps the constraint itself — a superset, so it only ever
 * carries MORE.
 */
describe('the admit set stays bounded (round 3 review, M-2)', () => {
  const holder: Bookkeeping = { tools_run: [{ name: 'semgrep', status: 'ok' }], missing_tools: [] };
  const gapOf = (tag: string, w: number): Bookkeeping => ({
    tools_run: [
      {
        name: 'semgrep',
        status: 'ok',
        partially_parsed: Array.from({ length: w }, (_, i) => ({ file: `${tag}-${i}.php`, type: 'PartialParsing', message: 'x' })),
        failed_rules: Array.from({ length: w }, (_, i) => ({ rule_id: `${tag}-r${i}`, message: 'x' })),
      },
    ],
    missing_tools: ['semgrep'],
  });

  it('2000 scans alternating two disjoint sets of 200 files and 200 rules: within budget', () => {
    const a = gapOf('a', 200);
    const b = gapOf('b', 200);
    const index = new ChainIndex();
    const t0 = performance.now();
    for (let i = 0; i < 2000; i++) {
      index.push(i % 2 === 0 ? a : b);
      index.scope(holder, 'semgrep');
    }
    expect(performance.now() - t0).toBeLessThan(2000);
  });

  it('the same shape under the bound stays exact: a repeat that is skipped changes nothing', () => {
    const a = gapOf('a', 3);
    const b = gapOf('b', 3);
    const chain = Array.from({ length: 50 }, (_, i) => (i % 2 === 0 ? a : b));
    const f = (file: string, rule: string): Finding => ({ fingerprint: 'fp', tool: 'semgrep', severity: 'high', category: 'security', title: 't', file_path: file, rule_id: rule, fix_available: false });
    for (const [file, rule] of [['a-0.php', 'b-r1'], ['b-2.php', 'a-r0'], ['a-0.php', 'a-r1'], ['c.php', 'b-r0']] as const) {
      const exact = chain.every((asked) => openGapFor(holder, asked, f(file, rule)) !== null);
      expect(scopeAdmits(chainScope(holder, chain, 'semgrep'), file, rule), `${file} ${rule}`).toBe(exact);
    }
  });

  it('past the bound the meet is a superset of the exact one: it never drops a finding', () => {
    const side = Math.ceil(Math.sqrt(MAX_ADMIT_PAIRS)) + 1;
    const set = (tag: string): Set<string> => new Set(Array.from({ length: side }, (_, i) => `${tag}${i}`));
    const c1 = { files: set('f'), rules: set('r') };
    const c2 = { files: set('g'), rules: set('s') };
    const approx = meetAdmit(meetAdmit({ all: true }, c1), c2);
    const admits = (s: Admit, file: string, rule: string): boolean => scopeAdmits({ kind: 'open', admit: s }, file, rule);
    const inC = (c: typeof c1, file: string, rule: string): boolean => c.files.has(file) || c.rules.has(rule);
    let checked = 0;
    for (const file of ['f0', 'g0', 'x']) {
      for (const rule of ['r0', 's0', 'y']) {
        if (!(inC(c1, file, rule) && inC(c2, file, rule))) continue;
        checked += 1;
        expect(admits(approx, file, rule), `${file} ${rule}`).toBe(true);
      }
    }
    expect(checked).toBeGreaterThan(0);
    expect(!approx.all && approx.pairs.size === 0).toBe(true);
  });
});
