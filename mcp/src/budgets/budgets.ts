/**
 * Budgets — `.guardian/budgets.yml`.
 *
 * Three different budget files used to be REFERENCED across this codebase
 * (`commands/guardian-budget.md` names `.guardian/budgets.yml` itself,
 * `lighthouserc.json`, and a `package.json` `"performance"` field) and
 * nothing read any of them. This module is the one that now does, for the
 * one this repo ships a shape for: `.guardian/budgets.yml`, read by both
 * `perf_check` (perf budgets) and `quality_check` (quality budgets) — see
 * those tools for where the measurements come from and how a violation
 * becomes a Finding via {@link budgetViolationFindings}.
 *
 * Deliberately small: a flat `perf` object and a flat `quality` object, each
 * with a handful of named numeric fields. No nesting, no per-path budgets,
 * no globbing — those are all real features a future task could add, but
 * every one of them is a claim about what the file format is FOR, and
 * nothing has asked for one yet. `loadBudgets` will need to grow when one
 * does; it validates its own field names precisely so an unrecognised or
 * mistyped one is reported (`kind: 'invalid'`) rather than silently ignored.
 *
 * `perf.inp_ms`, never `fid_ms`: INP replaced FID as a Core Web Vital
 * (Google, March 2024) — `perf_check`'s own Lighthouse summary already
 * reports `interaction-to-next-paint`, never `first-input-delay`, and this
 * schema follows it. FID does not appear anywhere in this codebase; keep it
 * that way.
 */

import { describeReadRefusal, readProjectText } from '../platform/projectFs.js';
import { join } from 'node:path';
import { describeYamlRefusal, parseYamlBounded } from '../platform/boundedParse.js';
import type { Category, Finding } from '../types.js';
import { makeFinding } from '../runners/scannerParsers/index.js';

export interface PerfBudgets {
  /** Largest Contentful Paint, milliseconds. */
  lcp_ms?: number;
  /** Interaction to Next Paint, milliseconds — see the module doc for why not FID. */
  inp_ms?: number;
  /** Cumulative Layout Shift, unitless (Lighthouse's own scale). */
  cls?: number;
  /** Total Blocking Time, milliseconds. */
  tbt_ms?: number;
  /** Total page weight, kilobytes — see perfCheck.ts for what Lighthouse audit this reads. */
  bundle_size_kb?: number;
}

export interface QualityBudgets {
  /** jscpd's duplicated-lines percentage, project-wide. */
  duplication_pct?: number;
  /** Highest per-function cyclomatic complexity (radon) anywhere in the project. */
  complexity?: number;
}

export interface Budgets {
  perf?: PerfBudgets;
  quality?: QualityBudgets;
}

export type BudgetsLoadResult =
  | { kind: 'none' }
  | { kind: 'loaded'; path: string; budgets: Budgets }
  | { kind: 'invalid'; path: string; error: string };

const PERF_FIELDS: readonly (keyof PerfBudgets)[] = ['lcp_ms', 'inp_ms', 'cls', 'tbt_ms', 'bundle_size_kb'];
const QUALITY_FIELDS: readonly (keyof QualityBudgets)[] = ['duplication_pct', 'complexity'];

/**
 * Read and validate `.guardian/budgets.yml` under `projectPath`. Never
 * throws: a missing file is `kind: 'none'` (nothing configured, not an
 * error); anything that IS there but does not parse as this module's shape —
 * broken YAML, a non-mapping document, an unrecognised top-level key, a
 * field that is not a number — is `kind: 'invalid'`, naming the path and
 * why, so a typo'd budget reads as a reported problem rather than a budget
 * that silently never fires.
 */
export function loadBudgets(projectPath: string): BudgetsLoadResult {
  const path = join(projectPath, '.guardian', 'budgets.yml');
  // The repository's file: bounded, regular files only, never through a
  // link out of the project (`platform/projectFs.ts`).
  const read = readProjectText(projectPath, path, 1024 * 1024);
  if (read.status === 'absent') return { kind: 'none' };
  if (read.status === 'refused') {
    return { kind: 'invalid', path, error: `the file was not read: ${describeReadRefusal(read.reason)}` };
  }
  // Bounded by bytes, indicators and depth (platform/boundedParse.ts): 1 MiB of dense YAML took
  // `yaml` 6 s and ~500 MB of heap.
  const parsed = parseYamlBounded(read.text);
  if (!parsed.ok) {
    return {
      kind: 'invalid',
      path,
      error: parsed.reason === 'invalid' ? `invalid YAML: ${parsed.detail ?? 'unparsable'}` : `the file was not read: ${describeYamlRefusal(parsed)}`,
    };
  }
  const doc = parsed.value;

  if (!isRecord(doc)) {
    return { kind: 'invalid', path, error: 'the document must be a mapping with perf: and/or quality: keys' };
  }

  const knownTopLevel = new Set(['perf', 'quality']);
  for (const key of Object.keys(doc)) {
    if (!knownTopLevel.has(key)) {
      return { kind: 'invalid', path, error: `unrecognised top-level key "${key}" (only perf, quality)` };
    }
  }

  const budgets: Budgets = {};
  if ('perf' in doc) {
    const parsed = parseSection(doc['perf'], PERF_FIELDS, 'perf');
    if (typeof parsed === 'string') return { kind: 'invalid', path, error: parsed };
    budgets.perf = parsed;
  }
  if ('quality' in doc) {
    const parsed = parseSection(doc['quality'], QUALITY_FIELDS, 'quality');
    if (typeof parsed === 'string') return { kind: 'invalid', path, error: parsed };
    budgets.quality = parsed;
  }

  return { kind: 'loaded', path, budgets };
}

/** One section (`perf:` or `quality:`) parsed against its known numeric fields, or an error string. */
function parseSection<K extends string>(
  raw: unknown,
  fields: readonly K[],
  sectionName: string,
): Record<K, number> | string {
  if (!isRecord(raw)) return `"${sectionName}:" must be a mapping of budget name to number`;
  const known = new Set<string>(fields);
  const out: Partial<Record<K, number>> = {};
  for (const [key, value] of Object.entries(raw)) {
    if (!known.has(key)) return `unrecognised ${sectionName} budget "${key}" (known: ${fields.join(', ')})`;
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      return `${sectionName}.${key} must be a number, got ${JSON.stringify(value)}`;
    }
    out[key as K] = value;
  }
  return out as Record<K, number>;
}

// ---------------------------------------------------------------------- evaluation

export interface BudgetViolation {
  /** `"perf.lcp_ms"` / `"quality.duplication_pct"` — the dotted budget name. */
  budget: string;
  measured: number;
  limit: number;
  /** `'ms'`, `'%'`, `'KB'`, or `''` for a unitless metric (CLS, complexity). */
  unit: string;
}

const PERF_UNITS: Record<keyof PerfBudgets, string> = {
  lcp_ms: 'ms',
  inp_ms: 'ms',
  cls: '',
  tbt_ms: 'ms',
  bundle_size_kb: 'KB',
};
const QUALITY_UNITS: Record<keyof QualityBudgets, string> = {
  duplication_pct: '%',
  complexity: '',
};

/**
 * Every perf metric present in BOTH `measured` and `budgets` whose measured
 * value exceeds the budget — every field here is "smaller is better", so
 * `measured > limit` is a violation for all five, uniformly. A metric absent
 * from either side (not measured, or no budget set for it) is silently
 * skipped: that is a coverage gap for the CALLER to report (perf_check
 * already does, via Lighthouse's own `tools_run`/coverage), not a budget
 * violation.
 */
export function evaluatePerfBudgets(
  measured: Partial<Record<keyof PerfBudgets, number | null | undefined>>,
  budgets: PerfBudgets | undefined,
): BudgetViolation[] {
  if (!budgets) return [];
  const violations: BudgetViolation[] = [];
  for (const key of PERF_FIELDS) {
    const limit = budgets[key];
    const value = measured[key];
    if (limit === undefined || value === undefined || value === null) continue;
    if (value > limit) violations.push({ budget: `perf.${key}`, measured: value, limit, unit: PERF_UNITS[key] });
  }
  return violations;
}

/** Same rule as {@link evaluatePerfBudgets}, for the two quality metrics. */
export function evaluateQualityBudgets(
  measured: Partial<Record<keyof QualityBudgets, number | null | undefined>>,
  budgets: QualityBudgets | undefined,
): BudgetViolation[] {
  if (!budgets) return [];
  const violations: BudgetViolation[] = [];
  for (const key of QUALITY_FIELDS) {
    const limit = budgets[key];
    const value = measured[key];
    if (limit === undefined || value === undefined || value === null) continue;
    if (value > limit) violations.push({ budget: `quality.${key}`, measured: value, limit, unit: QUALITY_UNITS[key] });
  }
  return violations;
}

// ---------------------------------------------------------------------- findings

/**
 * A budget violation as a {@link Finding}, in the same shape as every other
 * scanner's — `perf.*` budgets are `category: 'performance'`, `quality.*`
 * ones `category: 'quality'`, both `tool: 'budgets'`, `subcategory: 'budget'`.
 * `filePath` is the budgets file itself (relative — `loadBudgets`'s `path`
 * is absolute; the caller passes the project-relative form), so a click
 * through the finding lands on the configuration that set the limit.
 */
export function budgetViolationFindings(violations: readonly BudgetViolation[], filePath: string): Finding[] {
  return violations.map((v) => {
    const category: Category = v.budget.startsWith('perf.') ? 'performance' : 'quality';
    return makeFinding({
      tool: 'budgets',
      rule_id: v.budget,
      severity: 'medium',
      category,
      subcategory: 'budget',
      title: `${v.budget} over budget: ${v.measured}${v.unit} > ${v.limit}${v.unit}`,
      message:
        `${v.budget} measured ${v.measured}${v.unit}, over the ${v.limit}${v.unit} budget set in ${filePath}. ` +
        'Either bring it back under budget or, if the budget itself is wrong, edit that file — it is the ' +
        'single source of truth perf_check and quality_check both read.',
      file_path: filePath,
      fix_available: false,
    });
  });
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
