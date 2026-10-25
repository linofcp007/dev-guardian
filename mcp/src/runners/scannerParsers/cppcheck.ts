/**
 * cppcheck XML v2 parser (`runners/cppcheckRun.ts` has the report's shape and
 * why XML, not SARIF).
 *
 * One finding per `<error>` that reports a defect — never one of the ids that
 * report coverage (`CPPCHECK_COVERAGE_IDS`: a file not analysed, a missing
 * include, a configuration limit), which the runner turns into gaps and
 * notes, nor any `information` result: the runner enables that severity for
 * what it says about coverage only, and an id off the list (3.6.1:
 * `ConfigurationNotChecked`, a configuration skipped) was a low "security"
 * finding. The first `<location>` is the defect; the others are the trace, each
 * with what happened there, and go into the message. `severity` `error` is
 * `high` and `warning` `medium`, one step lower when cppcheck marks the result
 * `inconclusive`. The CWE is cppcheck's own (`cwe="476"`). A result outside
 * the project (a compile database can name files elsewhere) is dropped.
 */

import type { Finding, Severity } from '../../types.js';
import { CPPCHECK_COVERAGE_IDS, parseCppcheckXml, type CppcheckError } from '../cppcheckRun.js';
import { makeFinding, toRelativeIfPossible, type ParserContext, type ParserOutput, type ScannerParser } from './index.js';

const CPPCHECK_TOOL_NAME = 'cppcheck';

const LOWER: Readonly<Record<Severity, Severity>> = { critical: 'high', high: 'medium', medium: 'low', low: 'info', info: 'info' };

export const cppcheckParser: ScannerParser = {
  name: CPPCHECK_TOOL_NAME,
  parse(input: unknown, ctx: ParserContext = {}): ParserOutput {
    if (typeof input !== 'string') return { findings: [], cves: [] };
    const findings: Finding[] = [];
    for (const e of parseCppcheckXml(input).errors) {
      if (CPPCHECK_COVERAGE_IDS.has(e.id) || e.severity === 'information') continue;
      const finding = mapError(e, ctx);
      if (finding) findings.push(finding);
    }
    return { findings, cves: [] };
  },
};

function mapError(e: CppcheckError, ctx: ParserContext): Finding | null {
  const at = e.locations[0];
  if (at === undefined || at.file === '') return null;
  const file = toRelativeIfPossible(at.file, ctx.project_path);
  if (file.startsWith('/') || file.startsWith('../') || /^[A-Za-z]:/.test(file)) return null;
  const base: Severity = e.severity === 'error' ? 'high' : e.severity === 'warning' ? 'medium' : 'low';
  const trace = e.locations
    .slice(1)
    .filter((l) => l.info !== undefined && l.line !== undefined)
    .map((l) => `${toRelativeIfPossible(l.file, ctx.project_path)}:${String(l.line)}: ${l.info ?? ''}`);
  const input: Parameters<typeof makeFinding>[0] = {
    tool: CPPCHECK_TOOL_NAME,
    rule_id: e.id,
    severity: e.inconclusive ? LOWER[base] : base,
    category: 'security',
    subcategory: e.id,
    title: e.msg,
    message:
      `${e.verbose}${e.inconclusive ? ' (inconclusive)' : ''}` + (trace.length > 0 ? ` — ${trace.join('; ')}` : ''),
    file_path: file,
    fix_available: false,
    taxonomy: { cwe: e.cwe },
  };
  if (at.line !== undefined) {
    input.line_start = at.line;
    input.line_end = at.line;
  }
  return makeFinding(input);
}
