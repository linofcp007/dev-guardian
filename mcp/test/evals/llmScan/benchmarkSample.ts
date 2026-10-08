/**
 * The BenchmarkPython half of the verification set (G-V): REAL scanner
 * findings over OWASP BenchmarkPython, each labelled by the corpus's own
 * `expectedresults-0.1.csv`, sampled balanced (half real, half false) across
 * categories with a fixed seed.
 *
 * Labelling rule (eval-plan.md, G-V): a finding in `BenchmarkTestNNNNN.py`
 * is kept only when its weakness matches that test case's category — by CWE
 * ({@link CATEGORY_CWES}), or for the few Bandit tests whose CWE is generic
 * by the test id ({@link BANDIT_CATEGORY}). Then the case's `true`/`false`
 * is the finding's truth: the case is exploitable exactly when the finding
 * that names its weakness is real. A finding of some OTHER weakness in the
 * same file says nothing either way and is dropped, as are Bandit's
 * import-only checks (B401–B413), which flag an `import` line rather than
 * the code the case is about.
 *
 * What is stored (`data/benchmark-python-sample.json`) is finding METADATA
 * only — file, line, tool, rule, message, label, category, CWE. No code from
 * the GPL corpus ever enters the repository; the code is read from
 * `GUARDIAN_BENCHMARK_PY_SRC` at run time, into a blind copy.
 *
 * Regenerate with `npm run eval:llm-scan -- --build-benchmark-sample
 * --semgrep-json=<f> --bandit-json=<f>` after running both scanners over the
 * corpus's `testcode/` (see the data file's `provenance`).
 */

import { mulberry32 } from '../../helpers/yamlFuzz.js';

/** The CWEs that name each BenchmarkPython category's weakness. */
export const CATEGORY_CWES: Readonly<Record<string, readonly number[]>> = {
  cmdi: [77, 78],
  codeinj: [94, 95],
  deserialization: [502],
  hash: [327, 328, 916],
  ldapi: [90],
  pathtraver: [22, 23, 36, 73],
  redirect: [601],
  securecookie: [614, 1004],
  sqli: [89],
  trustbound: [501],
  weakrand: [330, 338],
  xpathi: [643],
  xss: [79, 80],
  xxe: [611, 776],
};

/**
 * Bandit tests whose `issue_cwe` is generic (CWE-20, or CWE-78 for `eval`):
 * the category they really name. Everything else is judged by CWE.
 */
export const BANDIT_CATEGORY: Readonly<Record<string, string>> = {
  B102: 'codeinj',
  B307: 'codeinj',
  B313: 'xxe',
  B314: 'xxe',
  B315: 'xxe',
  B316: 'xxe',
  B317: 'xxe',
  B318: 'xxe',
  B319: 'xxe',
  B320: 'xxe',
  B506: 'deserialization',
};

/** Bandit's import blacklist: the finding is the `import` line, not the code under test. */
export const BANDIT_IMPORT_ONLY: ReadonlySet<string> = new Set(
  Array.from({ length: 13 }, (_, i) => `B4${String(i + 1).padStart(2, '0')}`),
);

export interface ExpectedCase {
  test: string;
  category: string;
  real: boolean;
  cwe: number;
}

export function parseExpectedResults(csv: string): Map<string, ExpectedCase> {
  const out = new Map<string, ExpectedCase>();
  for (const raw of csv.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) continue;
    const [test, category, real, cwe] = line.split(',').map((s) => s.trim());
    if (test === undefined || category === undefined || real === undefined || cwe === undefined) continue;
    if (real !== 'true' && real !== 'false') continue;
    out.set(test, { test, category, real: real === 'true', cwe: Number(cwe) });
  }
  return out;
}

/** One scanner finding, normalised across Semgrep and Bandit. */
export interface RawFinding {
  tool: 'semgrep' | 'bandit';
  rule_id: string;
  /** Corpus-relative POSIX path. */
  file: string;
  line: number;
  message: string;
  cwes: number[];
  severity: string;
}

function asRecord(v: unknown): Record<string, unknown> | undefined {
  return typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
}

/** `testcode/BenchmarkTest00001.py` from whatever spelling the scanner used. */
export function corpusRelative(path: string): string {
  const p = path.replace(/\\/g, '/');
  const at = p.lastIndexOf('testcode/');
  return at === -1 ? p.replace(/^\.\//, '') : p.slice(at);
}

/** Findings of a `semgrep --json` report. */
export function semgrepFindings(report: unknown): RawFinding[] {
  const results = asRecord(report)?.['results'];
  if (!Array.isArray(results)) throw new Error('not a Semgrep JSON report: no results array');
  const out: RawFinding[] = [];
  for (const r of results) {
    const rec = asRecord(r);
    const extra = asRecord(rec?.['extra']);
    const meta = asRecord(extra?.['metadata']);
    const start = asRecord(rec?.['start']);
    const path = rec?.['path'];
    const rule = rec?.['check_id'];
    const line = start?.['line'];
    if (typeof path !== 'string' || typeof rule !== 'string' || typeof line !== 'number') continue;
    const cweRaw = meta?.['cwe'];
    const cweList = Array.isArray(cweRaw) ? cweRaw : typeof cweRaw === 'string' ? [cweRaw] : [];
    const cwes = cweList.flatMap((c) => {
      const m = typeof c === 'string' ? /CWE-(\d+)/.exec(c) : null;
      return m?.[1] !== undefined ? [Number(m[1])] : [];
    });
    out.push({
      tool: 'semgrep',
      rule_id: rule,
      file: corpusRelative(path),
      line,
      message: typeof extra?.['message'] === 'string' ? extra['message'] : '',
      cwes,
      severity: typeof extra?.['severity'] === 'string' ? extra['severity'] : 'unknown',
    });
  }
  return out;
}

/** Findings of a `bandit -f json` report. */
export function banditFindings(report: unknown): RawFinding[] {
  const results = asRecord(report)?.['results'];
  if (!Array.isArray(results)) throw new Error('not a Bandit JSON report: no results array');
  const out: RawFinding[] = [];
  for (const r of results) {
    const rec = asRecord(r);
    const file = rec?.['filename'];
    const rule = rec?.['test_id'];
    const line = rec?.['line_number'];
    if (typeof file !== 'string' || typeof rule !== 'string' || typeof line !== 'number') continue;
    const cwe = asRecord(rec?.['issue_cwe'])?.['id'];
    out.push({
      tool: 'bandit',
      rule_id: rule,
      file: corpusRelative(file),
      line,
      message: typeof rec?.['issue_text'] === 'string' ? rec['issue_text'] : '',
      cwes: typeof cwe === 'number' ? [cwe] : [],
      severity: typeof rec?.['issue_severity'] === 'string' ? rec['issue_severity'].toLowerCase() : 'unknown',
    });
  }
  return out;
}

/**
 * The scanner's message, trimmed to its first sentence (at most 200
 * characters) and stripped of anything quoted from the code: Bandit's B105
 * appends the literal it saw, and a Semgrep message can interpolate a
 * metavariable (with a registry login) — a stored message must never carry
 * corpus text. Back-quoted rule text without a string literal in it
 * (`flask.make_response()`) is the rule's own words and is kept.
 */
export function storedMessage(message: string): string {
  const one = message.replace(/\s+/g, ' ').trim();
  const cut = /^(.+?[.!?])(\s|$)/.exec(one)?.[1] ?? one;
  const noQuote = cut.replace(/:\s*'[^']*'\s*\.?$/, '.').replace(/`[^`]*(['"]|Benchmark)[^`]*`/g, '`…`');
  return noQuote.length > 200 ? `${noQuote.slice(0, 199)}…` : noQuote;
}

export interface LabelledFinding extends RawFinding {
  test: string;
  category: string;
  real: boolean;
  case_cwe: number;
}

/** The test case a finding's file is, or undefined for helpers and anything else. */
export function testOf(file: string): string | undefined {
  return /(?:^|\/)testcode\/(BenchmarkTest\d+)\.py$/.exec(file)?.[1];
}

/** Whether a finding names its test case's weakness (see the file header). */
export function matchesCategory(f: RawFinding, category: string): boolean {
  if (f.tool === 'bandit') {
    if (BANDIT_IMPORT_ONLY.has(f.rule_id)) return false;
    const override = BANDIT_CATEGORY[f.rule_id];
    if (override !== undefined) return override === category;
  }
  const accepted = CATEGORY_CWES[category];
  return accepted !== undefined && f.cwes.some((c) => accepted.includes(c));
}

export function labelFindings(findings: readonly RawFinding[], expected: ReadonlyMap<string, ExpectedCase>): LabelledFinding[] {
  const out: LabelledFinding[] = [];
  for (const f of findings) {
    const test = testOf(f.file);
    if (test === undefined) continue;
    const c = expected.get(test);
    if (c === undefined || !matchesCategory(f, c.category)) continue;
    out.push({ ...f, test, category: c.category, real: c.real, case_cwe: c.cwe });
  }
  return out;
}

function shuffled<T>(items: readonly T[], rand: () => number): T[] {
  const a = [...items];
  for (let i = a.length - 1; i > 0; i -= 1) {
    const j = Math.floor(rand() * (i + 1));
    const x = a[i];
    const y = a[j];
    if (x === undefined || y === undefined) continue;
    a[i] = y;
    a[j] = x;
  }
  return a;
}

/**
 * A balanced sample: `pairs` real findings and `pairs` false ones, one
 * finding per test case, spread across every category that has both
 * labels. Round-robin over the categories (sorted), one real + one false per
 * category per round, so no category dominates; within a (category, label)
 * the test cases, and within a case its findings, are in seeded order.
 * Deterministic for a given input and seed.
 */
export function sampleBalanced(labelled: readonly LabelledFinding[], pairs: number, seed: number): LabelledFinding[] {
  const rand = mulberry32(seed);
  // (category, label) -> test -> findings, every level sorted before shuffling so input order never matters
  const byKey = new Map<string, Map<string, LabelledFinding[]>>();
  const sorted = [...labelled].sort(
    (a, b) => a.test.localeCompare(b.test) || a.line - b.line || a.tool.localeCompare(b.tool) || a.rule_id.localeCompare(b.rule_id),
  );
  for (const f of sorted) {
    const key = `${f.category}|${f.real ? 'real' : 'not_real'}`;
    const tests = byKey.get(key) ?? new Map<string, LabelledFinding[]>();
    const list = tests.get(f.test) ?? [];
    list.push(f);
    tests.set(f.test, list);
    byKey.set(key, tests);
  }
  const queue = (category: string, real: boolean): LabelledFinding[] => {
    const tests = byKey.get(`${category}|${real ? 'real' : 'not_real'}`);
    if (tests === undefined) return [];
    return shuffled([...tests.keys()].sort(), rand).flatMap((t) => {
      const fs = tests.get(t) ?? [];
      const pick = shuffled(fs, rand)[0];
      return pick === undefined ? [] : [pick];
    });
  };
  const categories = [...new Set(sorted.map((f) => f.category))].sort();
  const queues = categories
    .map((c) => ({ category: c, real: queue(c, true), fake: queue(c, false) }))
    .filter((q) => q.real.length > 0 && q.fake.length > 0);

  const out: LabelledFinding[] = [];
  let taken = 0;
  for (let round = 0; taken < pairs; round += 1) {
    let progressed = false;
    for (const q of queues) {
      if (taken >= pairs) break;
      const r = q.real[round];
      const f = q.fake[round];
      if (r === undefined || f === undefined) continue;
      out.push(r, f);
      taken += 1;
      progressed = true;
    }
    if (!progressed) break;
  }
  return out;
}

/** One stored item of the sample. */
export interface BenchmarkSampleItem {
  file: string;
  line: number;
  tool: 'semgrep' | 'bandit';
  rule_id: string;
  severity: string;
  message: string;
  label: 'real' | 'not_real';
  category: string;
  /** The test case's CWE (expectedresults). */
  cwe: number;
  /** The CWEs the scanner attached to the finding. */
  finding_cwes: number[];
  test: string;
}

export interface BenchmarkSampleFile {
  note: string;
  provenance: {
    corpus: string;
    commit: string | null;
    expected_results: string;
    semgrep: { version: string | null; config: string; findings: number };
    bandit: { version: string | null; findings: number };
    labelled: number;
    seed: number;
    pairs: number;
    generated_at: string;
  };
  composition: Record<string, { real: number; not_real: number }>;
  items: BenchmarkSampleItem[];
}

export function toSampleItems(sample: readonly LabelledFinding[]): BenchmarkSampleItem[] {
  return sample.map((f) => ({
    file: f.file,
    line: f.line,
    tool: f.tool,
    rule_id: f.rule_id,
    severity: f.severity,
    message: storedMessage(f.message),
    label: f.real ? 'real' : 'not_real',
    category: f.category,
    cwe: f.case_cwe,
    finding_cwes: [...f.cwes].sort((a, b) => a - b),
    test: f.test,
  }));
}

export function composition(items: readonly BenchmarkSampleItem[]): Record<string, { real: number; not_real: number }> {
  const out: Record<string, { real: number; not_real: number }> = {};
  for (const i of items) {
    const c = out[i.category] ?? { real: 0, not_real: 0 };
    c[i.label] += 1;
    out[i.category] = c;
  }
  return out;
}

export function isSampleFile(v: unknown): v is BenchmarkSampleFile {
  const r = asRecord(v);
  return r !== undefined && Array.isArray(r['items']) && asRecord(r['provenance']) !== undefined;
}
