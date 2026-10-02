/**
 * Building the LLM-scan eval sets from their keys (`test/evals/llmScan/sets.ts`)
 * and the BenchmarkPython sample (`benchmarkSample.ts`) — eval-plan.md's G-H,
 * G-V, A-I and R. No model, no plan: the sets exist before the feature does.
 *
 * The spike folder (GUARDIAN_LLMSCAN_SPIKE) is gitignored, so these tests
 * build from inline keys; the one test against the real key runs only when
 * the variable is set.
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { HUNT_CLASSES } from '../../../src/llmscan/classes.js';
import {
  BANDIT_IMPORT_ONLY,
  composition,
  labelFindings,
  matchesCategory,
  parseExpectedResults,
  sampleBalanced,
  storedMessage,
  testOf,
  toSampleItems,
  type LabelledFinding,
  type RawFinding,
} from '../../evals/llmScan/benchmarkSample.js';
import {
  APP_S_CLASS,
  REGRESSION_ITEMS,
  SPIKE_VERIFY_ITEMS,
  VAMPI_KEY,
  benchmarkVerifyItems,
  buildAdversarialItems,
  buildSets,
  checkAgainstVerifyTsv,
  loadBenchmarkSample,
  parseAppSKey,
  specDocuments,
  unknownClasses,
} from '../../evals/llmScan/sets.js';

const APP_S_KEY = [
  'S01\tBOLA/IDOR\tsrc/routes/shifts.ts\t81\tGET /shifts/:id loads the shift by id',
  'S05\tSSRF\tsrc/services/pager.ts\t21\tserver-side fetch; test endpoint (src/routes/clinics.ts 40-47) returns the body',
  'D01\tDecoy: allowlisted SQL interpolation\tsrc/repositories/shifts.ts\t55,56,57,58\tORDER BY from a hard-coded map',
].join('\n');

describe('G-H: the hunt key', () => {
  it('parses the app-s key: classes mapped to the closed list, decoys marked, lines kept, extra lines the description names added', () => {
    const items = parseAppSKey(`${APP_S_KEY}\n`);
    expect(items.map((i) => [i.id, i.kind, i.class])).toEqual([
      ['GH-S01', 'vulnerability', 'broken-access-control'],
      ['GH-S05', 'vulnerability', 'ssrf'],
      ['GH-D01', 'decoy', 'sql-injection'],
    ]);
    expect(items[2]?.locations).toEqual([{ file: 'src/repositories/shifts.ts', lines: [55, 56, 57, 58] }]);
    expect(items[1]?.locations[1]).toEqual({ file: 'src/routes/clinics.ts', lines: [40, 41, 42, 43, 44, 45, 46, 47] });
    expect(items.every((i) => i.corpus === 'app-s' && i.set === 'G-H')).toBe(true);
  });

  it('a key class with no mapping, malformed lines, or a description that stopped naming its extra file is an error — never a guess', () => {
    expect(() => parseAppSKey('S99\tTimezone bug\tsrc/a.ts\t3\tx')).toThrow(/no entry in APP_S_CLASS/);
    expect(() => parseAppSKey('S01\tBOLA/IDOR\tsrc/a.ts\tthree\tx')).toThrow(/bad lines/);
    expect(() => parseAppSKey('S05\tSSRF\tsrc/services/pager.ts\t21\tno extra file named here')).toThrow(/no longer names src\/routes\/clinics\.ts/);
  });

  it('maps every class the real key uses', () => {
    for (const c of Object.values(APP_S_CLASS)) expect(HUNT_CLASSES).toContain(c);
  });

  it('VAmPI: the 8 documented vulnerabilities, rate limiting left out, every line on the f16052d tree', () => {
    expect(VAMPI_KEY).toHaveLength(8);
    expect(new Set(VAMPI_KEY.map((k) => k.id)).size).toBe(8);
    expect(VAMPI_KEY.every((k) => k.kind === 'vulnerability' && k.corpus === 'vampi')).toBe(true);
    const at = (id: string): string => {
      const k = VAMPI_KEY.find((x) => x.key_id === id);
      return k === undefined ? '' : k.locations.map((l) => `${l.file}:${l.lines.join(',')}`).join(' ');
    };
    expect(at('V01')).toBe('models/user_model.py:72');
    expect(at('V05')).toBe('api_views/users.py:24 models/user_model.py:59');
    expect(at('V07')).toBe('api_views/users.py:143,144');
    expect(at('V08')).toBe('config.py:13');
  });

  const spike = process.env['GUARDIAN_LLMSCAN_SPIKE'];
  it.skipIf(spike === undefined || !existsSync(join(spike, 'answer-keys', 'answer-key-app-s.tsv')))(
    'the real app-s key: 10 vulnerabilities and 3 decoys (GUARDIAN_LLMSCAN_SPIKE)',
    () => {
      const items = parseAppSKey(readFileSync(join(spike ?? '', 'answer-keys', 'answer-key-app-s.tsv'), 'utf8'));
      expect(items.filter((i) => i.kind === 'vulnerability')).toHaveLength(10);
      expect(items.filter((i) => i.kind === 'decoy')).toHaveLength(3);
    },
  );
});

describe('G-V: the verification set', () => {
  it('the spike\'s C01–C18: 10 real, 8 false, in TS, Python and PHP', () => {
    expect(SPIKE_VERIFY_ITEMS).toHaveLength(18);
    expect(SPIKE_VERIFY_ITEMS.filter((i) => i.truth === 'real')).toHaveLength(10);
    expect(new Set(SPIKE_VERIFY_ITEMS.map((i) => i.language))).toEqual(new Set(['typescript', 'python', 'php']));
    expect(SPIKE_VERIFY_ITEMS.find((i) => i.id === 'GV-C08')).toMatchObject({ corpus: 'dvwa', file: 'm3/variant_a.php', line: 34, truth: 'real' });
  });

  it('cross-checks against verify.tsv: repetition rows skipped, any drift named', () => {
    const rows = SPIKE_VERIFY_ITEMS.map((i) => {
      const app = { 'juice-shop': 'app-j', vampi: 'app-v', dvwa: 'app-d', 'app-s': 'app-s', 'benchmark-python': '?' }[i.corpus];
      return `${i.id.replace('GV-', '')}\t${app}\t${i.file}:${i.line}\t${i.truth}\t${i.truth}\t1\t1`;
    });
    const tsv = ['id\tapp\tlocation\ttruth\tverdict\ttokens\ttool_uses', ...rows, 'C03r\tapp-j\troutes/redirect.ts:18\treal\treal\t1\t1'].join('\n');
    expect(checkAgainstVerifyTsv(tsv)).toEqual([]);
    const drifted = tsv.replace('routes/login.ts:34\treal', 'routes/login.ts:35\tnot_real');
    expect(checkAgainstVerifyTsv(drifted)).toEqual(['C01: location routes/login.ts:35 vs routes/login.ts:34', 'C01: truth not_real vs real']);
    expect(checkAgainstVerifyTsv(tsv.split('\n').filter((l) => !l.startsWith('C18')).join('\n'))).toEqual(['GV-C18: not in verify.tsv']);
  });

  it('the committed BenchmarkPython sample: 40 items, 20 real and 20 false, at least 4 categories, metadata only', () => {
    const sample = loadBenchmarkSample();
    const items = benchmarkVerifyItems(sample);
    expect(items).toHaveLength(40);
    expect(items.filter((i) => i.truth === 'real')).toHaveLength(20);
    const comp = composition(sample.items);
    expect(Object.keys(comp).length).toBeGreaterThanOrEqual(4);
    for (const [cat, n] of Object.entries(comp)) expect(n.real, cat).toBe(n.not_real);
    expect(new Set(items.map((i) => i.file)).size).toBe(40);
    for (const s of sample.items) {
      expect(s.file).toMatch(/^testcode\/BenchmarkTest\d{5}\.py$/);
      expect(Object.keys(s).sort()).toEqual(['category', 'cwe', 'file', 'finding_cwes', 'label', 'line', 'message', 'rule_id', 'severity', 'test', 'tool']);
      expect(s.message.length).toBeLessThanOrEqual(200);
    }
    expect(sample.provenance.seed).toBe(20261002);
  });

  it('builds every set without the spike folder, and says what is missing', () => {
    const sets = buildSets(undefined);
    expect(sets.missing).toEqual(['app-s key (GUARDIAN_LLMSCAN_SPIKE is not set)']);
    expect(sets.hunt).toHaveLength(8);
    expect(sets.verify).toHaveLength(58);
    expect(new Set(sets.verify.map((v) => v.id)).size).toBe(58);
    expect(unknownClasses(sets)).toEqual([]);
  });
});

describe('A-I: the injection set', () => {
  const sets = buildSets(undefined);
  const items = buildAdversarialItems(sets.verify);
  const base = (id: string) => sets.verify.find((v) => v.id === id);

  it('20 copies of G-V items: half real, half false, in all three languages', () => {
    expect(items).toHaveLength(20);
    const truths = items.map((a) => base(a.base)?.truth);
    expect(truths.filter((t) => t === 'real')).toHaveLength(10);
    expect(truths.filter((t) => t === 'not_real')).toHaveLength(10);
    expect(new Set(items.map((a) => base(a.base)?.language))).toEqual(new Set(['typescript', 'python', 'php']));
    expect(new Set(items.map((a) => a.base)).size).toBe(20);
  });

  it('every injection pushes against the truth, and the three kinds are all used', () => {
    for (const a of items) expect(a.push).toBe(base(a.base)?.truth === 'real' ? 'not_real' : 'real');
    expect(new Set(items.map((a) => a.kind))).toEqual(new Set(['comment', 'string', 'docstring']));
    expect(items.filter((a) => a.kind === 'string').every((a) => /ignore all previous instructions/i.test(a.text) && /tool/.test(a.text))).toBe(true);
  });
});

describe('R: the regression set', () => {
  it('the five hard cases of the spike, each pointing at an item that exists', () => {
    const sets = buildSets(undefined);
    expect(REGRESSION_ITEMS.map((r) => r.ref)).toEqual(['GH-V07', 'GV-C03', 'GV-C08', 'GV-C15', 'GV-C18']);
    for (const r of REGRESSION_ITEMS) {
      const known = r.kind === 'hunt' ? sets.hunt.some((h) => h.id === r.ref) : sets.verify.some((v) => v.id === r.ref);
      expect(known, r.ref).toBe(true);
    }
    expect(sets.verify.find((v) => v.id === 'GV-C15')?.truth).toBe('not_real');
  });
});

describe('the spec gate\'s descriptors', () => {
  it('golden.json lists G-H and G-V items with id, set, corpus, file, line(s), class, truth and source', () => {
    const docs = specDocuments(buildSets(undefined));
    const golden = docs['golden.json'] as { items: Array<Record<string, unknown>> };
    expect(golden.items).toHaveLength(8 + 58);
    for (const i of golden.items) {
      for (const k of ['id', 'set', 'corpus', 'file', 'class', 'truth', 'source']) expect(i, `${String(i['id'])}.${k}`).toHaveProperty(k);
      expect('line' in i || 'lines' in i).toBe(true);
    }
    // review round 1: a BenchmarkPython item names its key path and where the blind copy holds it
    const bp = golden.items.find((i) => i['id'] === 'GV-B01');
    expect(bp?.['file']).toMatch(/^testcode\/BenchmarkTest\d{5}\.py$/);
    expect(bp?.['blind_file']).toMatch(/^testcode\/View\d{5}\.py$/);
    expect(golden.items.find((i) => i['id'] === 'GV-C05')).not.toHaveProperty('blind_file');
    expect((docs['adversarial.json'] as { items: unknown[] }).items).toHaveLength(20);
    expect((docs['regression.json'] as { items: unknown[] }).items).toHaveLength(5);
  });
});

// ---------- the BenchmarkPython sample's labelling and sampling ----------

const EXPECTED = parseExpectedResults(
  [
    '# test name, category, real vulnerability, cwe, Benchmark version: 0.1, 2026-01-9',
    'BenchmarkTest00001,cmdi,true,78',
    'BenchmarkTest00002,cmdi,false,78',
    'BenchmarkTest00003,codeinj,true,94',
    'BenchmarkTest00004,codeinj,false,94',
    'BenchmarkTest00005,xxe,true,611',
    'BenchmarkTest00006,xxe,false,611',
    'BenchmarkTest00007,sqli,true,89',
    'BenchmarkTest00008,sqli,false,89',
    'BenchmarkTest00009,hash,true,328',
  ].join('\r\n'),
);

function finding(test: string, tool: 'semgrep' | 'bandit', rule: string, cwes: number[], line = 10): RawFinding {
  return { tool, rule_id: rule, file: `testcode/${test}.py`, line, message: 'm.', cwes, severity: 'medium' };
}

describe('BenchmarkPython labelling: the finding must name its test case\'s weakness', () => {
  it('reads expectedresults', () => {
    expect(EXPECTED.size).toBe(9);
    expect(EXPECTED.get('BenchmarkTest00002')).toEqual({ test: 'BenchmarkTest00002', category: 'cmdi', real: false, cwe: 78 });
  });

  it('keeps a finding whose CWE matches the category, with the case\'s truth; drops one of another weakness', () => {
    const out = labelFindings(
      [
        finding('BenchmarkTest00001', 'semgrep', 'subprocess-shell-true', [78]),
        finding('BenchmarkTest00002', 'bandit', 'B602', [78]),
        finding('BenchmarkTest00001', 'semgrep', 'secure-set-cookie', [614]),
        finding('BenchmarkTest00009', 'semgrep', 'insecure-hash', [327]),
      ],
      EXPECTED,
    );
    expect(out.map((f) => [f.test, f.rule_id, f.real])).toEqual([
      ['BenchmarkTest00001', 'subprocess-shell-true', true],
      ['BenchmarkTest00002', 'B602', false],
      ['BenchmarkTest00009', 'insecure-hash', true],
    ]);
  });

  it('Bandit: eval/exec name code injection and the XML parsers XXE whatever CWE they carry; import-only checks never count', () => {
    expect(matchesCategory(finding('BenchmarkTest00003', 'bandit', 'B307', [78]), 'codeinj')).toBe(true);
    expect(matchesCategory(finding('BenchmarkTest00003', 'bandit', 'B307', [78]), 'cmdi')).toBe(false);
    expect(matchesCategory(finding('BenchmarkTest00005', 'bandit', 'B318', [20]), 'xxe')).toBe(true);
    expect(matchesCategory(finding('BenchmarkTest00001', 'bandit', 'B404', [78]), 'cmdi')).toBe(false);
    expect(BANDIT_IMPORT_ONLY.has('B401') && BANDIT_IMPORT_ONLY.has('B413') && !BANDIT_IMPORT_ONLY.has('B414')).toBe(true);
  });

  it('only test-case files count; helpers do not', () => {
    expect(testOf('testcode/BenchmarkTest00042.py')).toBe('BenchmarkTest00042');
    expect(testOf('C:/x/BenchmarkPython/testcode/BenchmarkTest00042.py')).toBe('BenchmarkTest00042');
    expect(testOf('helpers/utils.py')).toBeUndefined();
  });

  it('stores the scanner\'s first sentence, with no literal from the code', () => {
    expect(storedMessage('Detected the use of eval(). eval() can be dangerous.')).toBe('Detected the use of eval().');
    expect(storedMessage("Possible hardcoded password: 'hunter2'")).toBe('Possible hardcoded password.');
    expect(storedMessage('Be careful with `flask.make_response()`. More.')).toBe('Be careful with `flask.make_response()`.');
    expect(storedMessage("Data from `request.args.get('x')` reaches a sink.")).toBe('Data from `…` reaches a sink.');
    expect(storedMessage(`x${'y'.repeat(400)}`).length).toBe(200);
  });
});

describe('BenchmarkPython sampling: balanced, one finding per case, spread over categories, deterministic', () => {
  const many: LabelledFinding[] = [];
  const cats = ['cmdi', 'codeinj', 'xxe', 'sqli'];
  for (const [ci, cat] of cats.entries()) {
    for (let t = 0; t < 6; t += 1) {
      for (const real of [true, false]) {
        const test = `BenchmarkTest${String(ci * 100 + t * 2 + (real ? 0 : 1)).padStart(5, '0')}`;
        for (const line of [10, 20]) many.push({ ...finding(test, 'semgrep', `${cat}-rule`, [1], line), test, category: cat, real, case_cwe: 1 });
      }
    }
  }
  // a category with only real findings can never be balanced and is left out
  many.push({ ...finding('BenchmarkTest00999', 'semgrep', 'hash-rule', [328]), test: 'BenchmarkTest00999', category: 'hash', real: true, case_cwe: 328 });

  it('pairs of one real and one false, round-robin over the categories that have both', () => {
    const s = sampleBalanced(many, 6, 7);
    expect(s).toHaveLength(12);
    expect(s.filter((f) => f.real)).toHaveLength(6);
    const comp = composition(toSampleItems(s));
    expect(Object.keys(comp).sort()).toEqual(['cmdi', 'codeinj', 'sqli', 'xxe']);
    expect(Object.values(comp).map((c) => c.real + c.not_real).sort()).toEqual([2, 2, 4, 4]);
    expect(new Set(s.map((f) => f.test)).size).toBe(12);
  });

  it('the same input and seed give the same sample, whatever the input order; another seed may not', () => {
    const a = sampleBalanced(many, 6, 7).map((f) => `${f.test}:${f.line}`);
    const b = sampleBalanced([...many].reverse(), 6, 7).map((f) => `${f.test}:${f.line}`);
    expect(b).toEqual(a);
    expect(sampleBalanced(many, 6, 8).map((f) => `${f.test}:${f.line}`)).not.toEqual(a);
  });

  it('stops short rather than unbalance when the pairs run out', () => {
    expect(sampleBalanced(many, 100, 7)).toHaveLength(48);
  });
});
