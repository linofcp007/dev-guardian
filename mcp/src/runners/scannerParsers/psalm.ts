/**
 * Psalm taint-analysis parser (`runners/psalmRun.ts` has how the report is
 * made, and why the JSON one).
 *
 * One finding per tainted sink: Psalm reports the same sink once per source
 * that reaches it (wp-statistics: 11 issues on 6 sinks), so issues are kept
 * once per (type, file, line, column), the first one's trace. Psalm gives no
 * severity (every taint issue is `error`) and no CWE: both come from the
 * issue type here — {@link PSALM_TAINT_TYPES}, the 20 types the 6.20.1 PHAR
 * defines. The trace goes into the message, source first (its first step has
 * no location). A result outside the project is dropped.
 */

import type { Finding, Severity } from '../../types.js';
import { asArray, getNumber, getProp, getString, makeFinding, toRelativeIfPossible, type ParserContext, type ParserOutput, type ScannerParser } from './index.js';

const PSALM_TOOL_NAME = 'psalm';

/** Each taint type's severity and CWE (MITRE, CWE 4.20). */
const PSALM_TAINT_TYPES: Readonly<Record<string, { severity: Severity; cwe?: string }>> = {
  TaintedSql: { severity: 'high', cwe: '89' },
  TaintedShell: { severity: 'critical', cwe: '78' },
  TaintedEval: { severity: 'critical', cwe: '95' },
  TaintedInclude: { severity: 'high', cwe: '98' },
  TaintedUnserialize: { severity: 'high', cwe: '502' },
  TaintedCallable: { severity: 'high', cwe: '470' },
  TaintedSSRF: { severity: 'high', cwe: '918' },
  TaintedFile: { severity: 'high', cwe: '22' },
  TaintedHtml: { severity: 'medium', cwe: '79' },
  TaintedTextWithQuotes: { severity: 'medium', cwe: '79' },
  TaintedHeader: { severity: 'medium', cwe: '113' },
  TaintedCookie: { severity: 'medium', cwe: '565' },
  TaintedLdap: { severity: 'high', cwe: '90' },
  TaintedXpath: { severity: 'medium', cwe: '643' },
  TaintedExtract: { severity: 'medium', cwe: '621' },
  TaintedUserSecret: { severity: 'medium', cwe: '200' },
  TaintedSystemSecret: { severity: 'medium', cwe: '200' },
  TaintedSleep: { severity: 'low', cwe: '400' },
  TaintedCustom: { severity: 'medium' },
  TaintedInput: { severity: 'medium', cwe: '20' },
};

/** At most this many steps of a trace go into a message. */
const TRACE_STEPS = 8;

export const psalmParser: ScannerParser = {
  name: PSALM_TOOL_NAME,
  parse(input: unknown, ctx: ParserContext = {}): ParserOutput {
    let issues: unknown = input;
    if (typeof input === 'string') {
      try {
        issues = JSON.parse(input);
      } catch {
        return { findings: [], cves: [] };
      }
    }
    const seen = new Set<string>();
    const findings: Finding[] = [];
    for (const raw of asArray(issues)) {
      const type = getString(raw, 'type');
      const file = getString(raw, 'file_path');
      if (type === undefined || file === undefined || !type.startsWith('Tainted')) continue;
      const key = `${type}\0${file}\0${String(getNumber(raw, 'line_from'))}\0${String(getNumber(raw, 'column_from'))}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const finding = mapIssue(raw, type, file, ctx);
      if (finding) findings.push(finding);
    }
    return { findings, cves: [] };
  },
};

function mapIssue(raw: unknown, type: string, file: string, ctx: ParserContext): Finding | null {
  const rel = toRelativeIfPossible(file, ctx.project_path);
  if (rel.startsWith('/') || rel.startsWith('../') || /^[A-Za-z]:/.test(rel)) return null;
  const known = PSALM_TAINT_TYPES[type] ?? { severity: 'medium' as Severity };
  const message = getString(raw, 'message') ?? type;
  const trace = asArray(getProp(raw, 'taint_trace'))
    .map((step) => {
      const label = getString(step, 'label');
      if (label === undefined) return null;
      const at = getString(step, 'file_path');
      const line = getNumber(step, 'line_from');
      return at !== undefined && line !== undefined ? `${label} (${toRelativeIfPossible(at, ctx.project_path)}:${String(line)})` : label;
    })
    .filter((s): s is string => s !== null);
  const shown = trace.length > TRACE_STEPS ? [...trace.slice(0, TRACE_STEPS - 1), '…', trace[trace.length - 1] ?? ''] : trace;
  const input: Parameters<typeof makeFinding>[0] = {
    tool: PSALM_TOOL_NAME,
    rule_id: type,
    severity: known.severity,
    category: 'security',
    subcategory: 'taint',
    title: message,
    message: shown.length > 0 ? `${message}: ${shown.join(' → ')}` : message,
    file_path: rel,
    fix_available: false,
    taxonomy: { cwe: known.cwe },
  };
  const lineFrom = getNumber(raw, 'line_from');
  const lineTo = getNumber(raw, 'line_to');
  if (lineFrom !== undefined) {
    input.line_start = lineFrom;
    input.line_end = Math.max(lineFrom, lineTo ?? lineFrom);
  }
  const snippet = getString(raw, 'snippet');
  if (snippet !== undefined) input.snippet = snippet;
  return makeFinding(input);
}
