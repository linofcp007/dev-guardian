/**
 * The open set's carry-forward reads a finding's fate off a per-key scope
 * (`chainScope` + `scopeAdmits`) and labels it with the per-finding verdict
 * (`openGapFor`, which calls the same `answerFor` every comparison uses).
 * Fix round 2 split them for speed; this holds them EQUAL over random
 * bookkeeping — a finding is carried by the scope exactly when every newer
 * scan's `openGapFor` names a gap; the read the carry makes by tool
 * (`toolsOfKey`) never misses such a finding; and the fold stays one
 * constraint on a long chain, and closes when no file is in every one.
 */

import { describe, expect, it } from 'vitest';
import { chainScope, openGapFor, scopeAdmits, type Bookkeeping } from '../../../src/history/runCompare.js';
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
const IMAGES = ['nginx', 'nginx:latest', 'docker.io/library/nginx:latest', 'registry/app:1'];

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
    expect(open).toEqual({ kind: 'open', constraints: [{ files: new Set(['wp/a.php', 'src/b.js']), rules: new Set() }] });
    expect(scopeAdmits(open, 'wp/a.php', 'r1')).toBe(true);
    // Two scans that partly parsed different files: no finding is in both.
    expect(chainScope(holder, [partial('wp/a.php'), partial('src/b.js')], 'semgrep')).toEqual({ kind: 'never' });
    expect([partial('wp/a.php'), partial('src/b.js')].every((asked) => openGapFor(holder, asked, f) !== null)).toBe(false);
  });
});
