/**
 * `platform/boundedParse.ts`'s YAML gates, held to the real parser (review of
 * 3.0, W2E round 3, C1).
 *
 * Round 2 counted only `\n { [ ,` before parsing, so `- - - … x` — a million
 * levels of nesting on ONE line, 2 MB — passed, and ran a 768 MB server out
 * of memory through `scan_sast`, the rule-id reader and `scan_containers`.
 * The gates now are bytes, an over-count of every indicator character, and
 * the nesting depth measured on the parser's own syntax tree; then the value
 * is bounded by its size once aliases are followed. These tests throw every
 * shape of `test/helpers/yamlFuzz.ts` at them, sized to the largest the
 * character gates admit, plus a seeded random corpus.
 *
 * Measured in `node:22` under `docker run --memory 768m` (the numbers are in
 * CHANGELOG.md): every admitted input parsed in at most 0.54 s and 62 MB of
 * heap at the configuration bounds, 1.2 s and 112 MB at the API-spec bounds,
 * 0.91 s and 101 MB over 400 random documents; before this change the
 * reviewer's 500 KB `- - - …` took 2.6–3.7 s and 215 MB, and 2 MB ran out of
 * heap, through each of the three entry points below. Here
 * the absolute bounds run under `GUARDIAN_PERF_STRICT=1`; the shapes that
 * were quadratic are held linear by ratio.
 */
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as plainParse } from 'yaml';
import { describe, expect, it } from 'vitest';
import {
  describeYamlRefusal,
  parseYamlBounded,
  parseYamlDocumentBounded,
  YAML_CONFIG_LIMITS,
  YAML_SPEC_LIMITS,
  yamlGate,
  yamlTooComplex,
  type YamlLimits,
} from '../../../src/platform/boundedParse.js';
import { inspectProjectSemgrepConfigs } from '../../../src/platform/projectSemgrepConfig.js';
import { checkCompose } from '../../../src/runners/composeChecks.js';
import { ruleIdsInFile } from '../../../src/runners/semgrepRuleIds.js';
import { costOf, expectLinear, PERF_STRICT } from '../../helpers/timing.js';
import { mulberry32, randomYaml, YAML_FAMILIES } from '../../helpers/yamlFuzz.js';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..');

const reasonOf = (text: string, limits?: YamlLimits): string => {
  const r = parseYamlBounded(text, limits);
  return r.ok ? 'ok' : r.reason;
};

describe('the one-line nesting round 2 missed is refused before any parse', () => {
  it.each([
    ['- ', 'the reviewer’s 2 MB `- - - … x`'],
    ['? ', 'nested complex keys'],
  ])('%j × 1 000 000 (%s): too large; × 250 000 (500 KB): too complex', (unit) => {
    expect(reasonOf(`${unit.repeat(1_000_000)}x\n`)).toBe('too-large');
    expect(reasonOf(`${unit.repeat(250_000)}x\n`)).toBe('too-complex');
  });

  it.each([
    ['one-line sequences', `${'- '.repeat(65)}x\n`],
    ['one-line complex keys', `${'? '.repeat(65)}x\n`],
    ['flow sequences', `${'['.repeat(65)}${']'.repeat(65)}\n`],
    ['flow maps', `${'{a: '.repeat(65)}x${'}'.repeat(65)}\n`],
    ['flow sequences over lines', `${'[\n'.repeat(65)}${']'.repeat(65)}\n`],
    ['block maps by indentation', Array.from({ length: 65 }, (_, i) => `${' '.repeat(i)}a:`).join('\n') + ' x\n'],
  ])('%s 65 deep: too deep, measured on the syntax tree', (_label, text) => {
    expect(reasonOf(text)).toBe('too-deep');
  });

  it('64 deep is admitted', () => {
    expect(reasonOf(`${'- '.repeat(64)}x\n`)).toBe('ok');
  });

  it("the reviewer's three entry points refuse the 2 MB line, and say why", () => {
    const body = `${'- '.repeat(1_000_000)}x\n`;
    const p = mkdtempSync(join(tmpdir(), 'dg-yaml-sites-'));
    writeFileSync(join(p, '.semgrep.yml'), body);
    expect(inspectProjectSemgrepConfigs(p).unusable.map((u) => u.target)).toEqual(['.semgrep.yml']);
    expect(ruleIdsInFile(join(p, '.semgrep.yml'))).toEqual([]);
    expect(checkCompose(body, 'docker-compose.yml')).toEqual([]);
  });
});

describe('real files pass, unchanged', () => {
  const packs = readdirSync(join(REPO, 'configs', 'semgrep')).filter((f) => f.endsWith('.yml'));

  it.each(packs)('configs/semgrep/%s parses to exactly what the plain parser makes of it', (pack) => {
    const text = readFileSync(join(REPO, 'configs', 'semgrep', pack), 'utf8');
    const r = parseYamlBounded(text);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.value).toEqual(plainParse(text));
  });
});

describe('aliases, merge keys, documents, duplicate keys', () => {
  it('a billion laughs is refused by its expanded size, not by the time it takes', () => {
    expect(reasonOf(YAML_FAMILIES['laughs']?.(12) ?? '')).toBe('too-expanded');
  });

  it('an alias inside the node it names is refused: toJS would build a circular value', () => {
    const r = parseYamlBounded('a: &a [x, *a]\nb: 1\n');
    expect(r).toEqual({ ok: false, reason: 'invalid', detail: 'an alias refers to the node that holds it' });
  });

  it('shared anchors are counted as expanded, and small ones pass', () => {
    const r = parseYamlBounded('base: &b {image: x, privileged: true}\nweb: *b\nworker: {<<: *b}\n');
    expect(r).toEqual({ ok: true, value: { base: { image: 'x', privileged: true }, web: { image: 'x', privileged: true }, worker: { '<<': { image: 'x', privileged: true } } } });
  });

  it("anchored collections holding aliases — yaml's own alias counter took 49 s — are linear now", () => {
    expectLinear('alias chain', (n) => void parseYamlBounded(YAML_FAMILIES['alias-chain']?.(n) ?? '', YAML_SPEC_LIMITS), 1_000);
    // A ratio test's own bound, as the other timing files give theirs: 3.2 s alone on Windows, past 10 s in node:22 under load.
  }, 120_000);

  it('more than one document is refused before any is composed', () => {
    expect(parseYamlBounded('a: 1\n---\nb: 2\n')).toEqual({ ok: false, reason: 'invalid', detail: 'the file holds more than one YAML document' });
  });

  it('a map of many keys is linear (the pairwise duplicate check was quadratic), and a later duplicate wins', () => {
    expectLinear('wide map', (n) => void parseYamlBounded(YAML_FAMILIES['wide-map']?.(n) ?? ''), 2_500);
    expect(parseYamlBounded('privileged: false\nprivileged: true\n')).toEqual({ ok: true, value: { privileged: true } });
  }, 120_000);

  it('every refusal has a sentence', () => {
    for (const reason of ['too-large', 'too-complex', 'too-deep', 'too-expanded', 'invalid'] as const) {
      expect(describeYamlRefusal({ reason, detail: 'x' }).length).toBeGreaterThan(10);
    }
  });
});

/**
 * The strict bound. Standalone, the slowest admitted input took 1.2 s
 * (`node:22`, 768 MB); inside a vitest worker in the same container the
 * slowest shapes (one error per line, deep-and-wide nesting) took up to
 * 5.4 s, even after a warm-up and a full collection. 10 s still sits far
 * below what the gates exist for: the quadratic paths took more than 60 s.
 */
const STRICT_MS = 10_000;

/** The largest n the character gates (bytes, indicators) admit for a family. */
function largestPreAdmitted(gen: (n: number) => string, limits: YamlLimits): number {
  if (yamlTooComplex(gen(1), limits)) return 0;
  let lo = 1;
  let hi = 2;
  while (hi <= 1 << 22 && !yamlTooComplex(gen(hi), limits)) {
    lo = hi;
    hi *= 2;
  }
  if (hi > 1 << 22) return lo;
  while (hi - lo > 1) {
    const mid = Math.floor((lo + hi) / 2);
    if (yamlTooComplex(gen(mid), limits)) hi = mid;
    else lo = mid;
  }
  return lo;
}

describe('fuzz: every family at the largest size the character gates admit', () => {
  for (const [name, limits] of [
    ['configuration', YAML_CONFIG_LIMITS],
    ['API spec', YAML_SPEC_LIMITS],
  ] as const) {
    it.each(Object.keys(YAML_FAMILIES))(`%s (${name} bounds): an answer, a value never circular${PERF_STRICT ? ', under 10 s' : ''}`, (family) => {
      const gen = YAML_FAMILIES[family];
      if (gen === undefined) throw new Error(family);
      const n = largestPreAdmitted(gen, limits);
      const text = gen(Math.max(n, 1));
      const r = parseYamlBounded(text, limits);
      if (r.ok) expect(() => JSON.stringify(r.value)).not.toThrow();
      else expect(['too-large', 'too-complex', 'too-deep', 'too-expanded', 'invalid']).toContain(r.reason);
      // Timed after a warm-up and a full collection: a vitest worker carries every earlier test's heap.
      if (PERF_STRICT) expect(costOf(() => void parseYamlBounded(text, limits))).toBeLessThan(STRICT_MS);
    }, 60_000);
  }
});

describe('fuzz: a seeded random corpus of block, flow, anchor, alias, merge, tag and corrupted documents', () => {
  it('every input gets an answer, every admitted value is acyclic, and the gate predicts the parse', () => {
    const outcomes: Record<string, number> = {};
    for (let seed = 1; seed <= 60; seed++) {
      const rand = mulberry32(seed);
      const text = randomYaml(rand, 50 + Math.floor(rand() * 2_500), seed % 3 === 0);
      const r = parseYamlBounded(text);
      const key = r.ok ? 'ok' : r.reason;
      outcomes[key] = (outcomes[key] ?? 0) + 1;
      if (r.ok) {
        expect(() => JSON.stringify(r.value)).not.toThrow();
        expect(yamlGate(text)).toBeNull();
      }
      if (PERF_STRICT) expect(costOf(() => void parseYamlBounded(text)), `seed ${seed}`).toBeLessThan(STRICT_MS);
    }
    // The corpus reaches every outcome that matters, so a regression in any gate shows.
    expect(Object.keys(outcomes).sort()).toEqual(expect.arrayContaining(['invalid', 'ok', 'too-expanded']));
  }, 120_000);

  it('the document form refuses the same inputs', () => {
    const rand = mulberry32(7);
    const text = randomYaml(rand, 400);
    expect(parseYamlDocumentBounded(text).ok).toBe(parseYamlBounded(text).ok);
  });
});
