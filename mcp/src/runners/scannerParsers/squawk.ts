/**
 * squawk `--reporter json` parser (`runners/squawkRun.ts`, squawk 2.71.0's `ReportViolation`).
 *
 * One JSON array of `{ file, line, column, level, message, note, help, rule_name, column_end, line_end }`, `line`
 * and `line_end` counted from 0. Every violation is `low`, subcategory `migration-safety`: squawk cannot know how
 * big a table is, and a lock on an empty one is no defect — the guardian-review skill tells the model when one
 * matters (a table that holds data). squawk's own `level` (Warning, Error) is no severity of the code: kept out.
 * A `syntax-error` violation is no finding — squawk read the file only up to it; the run names the file as partial.
 */

import type { Finding } from '../../types.js';
import {
  asArray,
  getNumber,
  getString,
  makeFinding,
  parseInputAsJson,
  toRelativeIfPossible,
  type ParserContext,
  type ParserOutput,
  type ScannerParser,
} from './index.js';

const SQUAWK_TOOL_NAME = 'squawk';

/** The rule squawk names a file it could not parse with. */
export const SQUAWK_SYNTAX_ERROR_RULE = 'syntax-error';

export const squawkParser: ScannerParser = {
  name: SQUAWK_TOOL_NAME,
  parse(input: unknown, ctx: ParserContext = {}): ParserOutput {
    const findings: Finding[] = [];
    for (const raw of asArray(parseInputAsJson(input))) {
      const finding = mapViolation(raw, ctx);
      if (finding) findings.push(finding);
    }
    return { findings, cves: [] };
  },
};

function mapViolation(raw: unknown, ctx: ParserContext): Finding | null {
  const rule = getString(raw, 'rule_name');
  const file = getString(raw, 'file');
  if (rule === undefined || rule === '' || rule === SQUAWK_SYNTAX_ERROR_RULE || file === undefined || file === '') return null;
  const message = getString(raw, 'message') ?? rule;
  const help = getString(raw, 'help');
  const note = getString(raw, 'note');
  const line = getNumber(raw, 'line');
  const lineEnd = getNumber(raw, 'line_end');
  const input: Parameters<typeof makeFinding>[0] = {
    tool: SQUAWK_TOOL_NAME,
    rule_id: rule,
    severity: 'low',
    category: 'bug',
    subcategory: 'migration-safety',
    title: message,
    message: `${rule}: ${message}${note ? ` (${note})` : ''}${help ? ` — ${help}` : ''} (https://squawkhq.com/docs/${rule})`,
    file_path: toRelativeIfPossible(file, ctx.project_path),
    fix_available: false,
  };
  if (line !== undefined) input.line_start = line + 1;
  const end = lineEnd !== undefined && line !== undefined && lineEnd >= line ? lineEnd : line;
  if (end !== undefined) input.line_end = end + 1;
  return makeFinding(input);
}
