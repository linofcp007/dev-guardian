/**
 * `dev-guardian metrics --head <file> [--base <file>]`: the METRIC lines of a
 * change's output judged against its base's (`judge.ts`), and how the CLI
 * prints and exits on it. Nothing here reads a database, runs a command or
 * opens a file: the CLI hands over what `metricFile.ts` read.
 *
 * The exit code is advisory unless `--strict`: 2 only when the
 * head holds no METRIC line it could read — nothing was measured — and 0
 * otherwise, a regression included; `--strict` makes a regressed or loosened
 * metric, a metric the base has and the head lacks, or a malformed head line
 * exit 1. A base that cannot be judged is no reference: every head metric is
 * then `new`.
 */

import { untrustedText } from '../platform/untrustedText.js';
import { decimalString, parseDecimal } from './decimal.js';
import { judgeMetric, judgmentNumbers, type MetricJudgment, type MetricTerm, type MetricVerdict } from './judge.js';
import { METRIC_FORMAT, type MetricOutput, type MetricReading, type MetricTolerance } from './metricLine.js';

interface MetricComparison {
  readonly name: string;
  readonly head: MetricReading;
  readonly base: MetricReading | null;
  readonly judgment: MetricJudgment;
}

interface MetricsComparison {
  readonly head: MetricOutput;
  readonly base: MetricOutput | null;
  readonly comparisons: readonly MetricComparison[];
  /** Names the base read and the head did not, in the base's order. */
  readonly missing: readonly string[];
}

export function compareMetricOutputs(head: MetricOutput, base: MetricOutput | null): MetricsComparison {
  const comparisons = [...head.metrics.values()].map((reading) => {
    const reference = base?.metrics.get(reading.name) ?? null;
    return { name: reading.name, head: reading, base: reference, judgment: judgeMetric(reference, reading) };
  });
  const missing = base === null ? [] : [...base.metrics.keys()].filter((name) => !head.metrics.has(name));
  return { head, base, comparisons, missing };
}

type MetricsExit = 0 | 1 | 2;

export function metricsExitCode(c: MetricsComparison, strict: boolean): MetricsExit {
  if (c.head.metrics.size === 0) return 2;
  if (!strict) return 0;
  const failing =
    c.comparisons.some((m) => m.judgment.verdict === 'regressed' || m.judgment.loosened !== null) ||
    c.missing.length > 0 ||
    c.head.malformed > 0;
  return failing ? 1 : 0;
}

function namesWith(c: MetricsComparison, keep: (m: MetricComparison) => boolean): string[] {
  return c.comparisons.filter(keep).map((m) => m.name);
}

const verdictIs = (v: MetricVerdict) => (m: MetricComparison): boolean => m.judgment.verdict === v;

function toleranceJson(t: MetricTolerance | null): { amount: number; percent: boolean } | null {
  return t === null ? null : { amount: Number(t.raw), percent: t.percent };
}

function outputJson(file: string, o: MetricOutput) {
  return {
    file,
    metrics: o.metrics.size,
    malformed: o.malformed,
    malformed_lines: o.malformedLines.map((l) => ({ text: untrustedText(l.text), part: l.part })),
    repeats: o.repeats,
    dropped: [...o.dropped],
  };
}

export interface MetricsReportContext {
  readonly toolVersion: string;
  readonly headFile: string;
  readonly baseFile: string | null;
  readonly strict: boolean;
  readonly exitCode: MetricsExit;
}

/** The `--format json` document. Keys are stable; every string read from a file is shown escaped. */
export function metricsJson(c: MetricsComparison, ctx: MetricsReportContext): Record<string, unknown> {
  return {
    format: METRIC_FORMAT,
    tool_version: ctx.toolVersion,
    exit_code: ctx.exitCode,
    strict: ctx.strict,
    head: outputJson(ctx.headFile, c.head),
    base: c.base === null || ctx.baseFile === null ? null : outputJson(ctx.baseFile, c.base),
    comparisons: c.comparisons.map((m) => {
      const { delta, applied } = judgmentNumbers(m.judgment);
      return {
        name: m.name,
        unit: m.head.unit === null ? null : untrustedText(m.head.unit),
        base: m.base === null ? null : m.base.value,
        head: m.head.value,
        delta,
        applied,
        // The judge's terms: the reference's.
        better: m.base === null ? null : m.base.better,
        tolerance: m.base === null ? null : toleranceJson(m.base.tolerance),
        verdict: m.judgment.verdict,
        why: m.judgment.why === null ? null : [...m.judgment.why],
        loosened: m.judgment.loosened,
      };
    }),
    regressed: namesWith(c, verdictIs('regressed')),
    improved: namesWith(c, verdictIs('improved')),
    within: namesWith(c, verdictIs('within')),
    new: namesWith(c, verdictIs('new')),
    unjudged: namesWith(c, verdictIs('unjudged')),
    loosened: namesWith(c, (m) => m.judgment.loosened !== null),
    missing: [...c.missing],
  };
}

const TERM_WORD: Record<MetricTerm, string> = { better: 'no better=', tolerance: 'no tolerance=', unit: 'the unit changed' };

function withUnit(value: string, unit: string | null, cell: (s: string) => string): string {
  return unit === null ? value : `${value} ${cell(unit)}`;
}

/** `+6.6 (+1.6%)`: the exact delta, and its share of |base| rounded for reading. */
function changeText(m: MetricComparison): string {
  const delta = m.judgment.delta;
  if (delta === null || m.base === null) return '—';
  const text = decimalString(delta);
  const signed = text.startsWith('-') || text === '0' ? text : `+${text}`;
  const base = m.base.value;
  if (base === 0) return signed;
  const pct = (Number(text) / Math.abs(base)) * 100;
  return `${signed} (${pct >= 0 ? '+' : ''}${pct.toFixed(1)}%)`;
}

function ruleText(m: MetricComparison): string {
  if (m.base === null) return '—';
  const better = m.base.better ?? 'no direction';
  const t = m.base.tolerance;
  const tol = t === null ? 'no tolerance' : `${t.raw}${t.percent ? '%' : ''}`;
  return `${better}, ${tol}`;
}

function verdictText(m: MetricComparison): string {
  const j = m.judgment;
  const head = j.verdict === 'unjudged' && j.why !== null ? `unjudged: ${j.why.map((w) => TERM_WORD[w]).join(', ')}` : j.verdict;
  const applied = j.applied === null ? '' : ` (tolerance ${decimalString(j.applied)})`;
  return j.loosened === null ? `${head}${applied}` : `${head}${applied}; loosened ${j.loosened}`;
}

function summaryLine(c: MetricsComparison): string {
  const counts = new Map<string, number>();
  for (const m of c.comparisons) counts.set(m.judgment.verdict, (counts.get(m.judgment.verdict) ?? 0) + 1);
  const parts = (['regressed', 'improved', 'within', 'unjudged', 'new'] as const)
    .filter((v) => (counts.get(v) ?? 0) > 0)
    .map((v) => `${counts.get(v) ?? 0} ${v}`);
  const loosened = c.comparisons.filter((m) => m.judgment.loosened !== null).length;
  if (loosened > 0) parts.push(`${loosened} loosened`);
  if (c.missing.length > 0) parts.push(`${c.missing.length} missing from the head`);
  return parts.length > 0 ? parts.join(', ') : 'nothing to compare';
}

function readNotes(label: string, o: MetricOutput, cell: (s: string) => string): string[] {
  const notes: string[] = [];
  if (o.malformed > 0) {
    const shown = o.malformedLines.map((l) => `${cell(l.text.trim())} (${l.part})`).join('; ');
    notes.push(`${label}: ${o.malformed} malformed METRIC line(s), not read: ${shown}`);
  }
  if (o.repeats > 0) notes.push(`${label}: ${o.repeats} earlier line(s) of a name replaced by its last one`);
  for (const b of o.dropped) notes.push(`${label}: ${DROPPED_WORDS[b]}`);
  return notes;
}

const DROPPED_WORDS: Record<MetricOutput['dropped'][number], string> = {
  readBytes: 'over 64 MiB: only its last 64 MiB were read',
  candidateBytes: 'a METRIC line over 512 bytes was not read',
  candidates: 'past 1,000 METRIC lines: the earlier ones were not read',
  names: 'past 20 names: the names printed first were not read',
};

/** A table cell of text read from a file: escaped, in a code span, its pipes kept out of the table's columns. */
function markdownCell(s: string): string {
  return `\`${untrustedText(s).replace(/`/g, "'").replace(/\|/g, '\\|')}\``;
}

function humanCell(s: string): string {
  return untrustedText(s);
}

function valueText(r: MetricReading | null, cell: (s: string) => string): string {
  if (r === null) return '—';
  const exact = parseDecimal(r.raw);
  return withUnit(exact === null ? r.raw : decimalString(exact), r.unit, cell);
}

function rows(c: MetricsComparison, cell: (s: string) => string, name: (s: string) => string): string[][] {
  return c.comparisons.map((m) => [name(m.name), valueText(m.base, cell), valueText(m.head, cell), changeText(m), ruleText(m), verdictText(m)]);
}

const HEADER = ['metric', 'base', 'head', 'change', 'rule (the base line\'s)', 'verdict'];

export function metricsMarkdown(c: MetricsComparison, ctx: MetricsReportContext): string {
  const lines = ['### dev-guardian metrics', ''];
  if (c.head.metrics.size === 0) {
    lines.push('The head output holds no METRIC line that could be read: nothing was measured.', '');
  } else {
    lines.push(`| ${HEADER.join(' | ')} |`, `| ${HEADER.map(() => '---').join(' | ')} |`);
    for (const r of rows(c, markdownCell, (n) => `\`${n}\``)) lines.push(`| ${r.join(' | ')} |`);
    lines.push('');
  }
  lines.push(`${c.base === null ? 'No base output: the values are shown, nothing is compared.' : summaryLine(c)}`);
  if (c.missing.length > 0) lines.push('', `Missing from the head: ${c.missing.map((n) => `\`${n}\``).join(', ')}.`);
  const notes = [...readNotes('head', c.head, markdownCell), ...(c.base === null ? [] : readNotes('base', c.base, markdownCell))];
  if (notes.length > 0) lines.push('', ...notes.map((n) => `- ${n}`));
  lines.push('', `${METRIC_FORMAT}, dev-guardian ${ctx.toolVersion}${ctx.strict ? ', --strict' : ''}: exit ${ctx.exitCode}.`);
  return `${lines.join('\n')}\n`;
}

function padTable(table: string[][]): string[] {
  const widths = table[0]?.map((_, i) => Math.max(...table.map((r) => (r[i] ?? '').length))) ?? [];
  return table.map((r) => r.map((cell, i) => cell.padEnd(widths[i] ?? 0)).join('  ').trimEnd());
}

export function metricsHuman(c: MetricsComparison, ctx: MetricsReportContext): string {
  const lines = [`dev-guardian metrics (${METRIC_FORMAT}) — head: ${humanCell(ctx.headFile)}${ctx.baseFile === null ? '' : ` · base: ${humanCell(ctx.baseFile)}`}`];
  if (c.head.metrics.size === 0) {
    lines.push('The head output holds no METRIC line that could be read: nothing was measured (exit 2).');
  } else {
    lines.push('', ...padTable([HEADER, ...rows(c, humanCell, (n) => n)]), '');
    lines.push(c.base === null ? 'No base output: the values are shown, nothing is compared.' : summaryLine(c));
  }
  if (c.missing.length > 0) lines.push(`Missing from the head: ${c.missing.join(', ')}.`);
  lines.push(...readNotes('head', c.head, humanCell), ...(c.base === null ? [] : readNotes('base', c.base, humanCell)));
  lines.push(`exit ${ctx.exitCode}${ctx.strict ? ' (--strict)' : ''}`);
  return `${lines.join('\n')}\n`;
}
