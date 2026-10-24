/**
 * shellcheck `-f json1` parser.
 *
 * `{ comments: [{ file, line, endLine, column, endColumn, level, code,
 * message, fix }] }`, `code` a number (`2086` is SC2086). `level` is `error`
 * (`medium`), `warning` or `info` (`low`) or `style` (`info`) — the same
 * scale as staticcheck's, these being quality findings. Every finding is a
 * `quality_check` `smell`. SC1072 / SC1073 (the parse stopped there) are
 * findings too — the script does not parse — and their file is also named a
 * partial gap by `runners/shellcheckRun.ts`.
 */

import type { Finding, Severity } from '../../types.js';
import {
  asArray,
  getNumber,
  getProp,
  getString,
  makeFinding,
  parseInputAsJson,
  toRelativeIfPossible,
  type ParserContext,
  type ParserOutput,
  type ScannerParser,
} from './index.js';

const SHELLCHECK_TOOL_NAME = 'shellcheck';

const SEVERITY: Readonly<Record<string, Severity>> = { error: 'medium', warning: 'low', info: 'low', style: 'info' };

export const shellcheckParser: ScannerParser = {
  name: SHELLCHECK_TOOL_NAME,
  parse(input: unknown, ctx: ParserContext = {}): ParserOutput {
    const findings: Finding[] = [];
    for (const raw of asArray(getProp(parseInputAsJson(input), 'comments'))) {
      const finding = mapComment(raw, ctx);
      if (finding) findings.push(finding);
    }
    return { findings, cves: [] };
  },
};

function mapComment(raw: unknown, ctx: ParserContext): Finding | null {
  const code = getNumber(raw, 'code');
  const file = getString(raw, 'file');
  if (code === undefined || !file) return null;
  const rule = `SC${String(code)}`;
  const message = getString(raw, 'message') ?? `${rule} violation`;
  const line = getNumber(raw, 'line');
  const endLine = getNumber(raw, 'endLine');
  const input: Parameters<typeof makeFinding>[0] = {
    tool: SHELLCHECK_TOOL_NAME,
    rule_id: rule,
    severity: SEVERITY[getString(raw, 'level') ?? ''] ?? 'low',
    category: 'quality',
    subcategory: 'smell',
    title: message,
    message: `${rule}: ${message} (https://www.shellcheck.net/wiki/${rule})`,
    file_path: toRelativeIfPossible(file, ctx.project_path),
    fix_available: false,
  };
  if (line !== undefined) input.line_start = line;
  const end = endLine !== undefined && line !== undefined && endLine >= line ? endLine : line;
  if (end !== undefined) input.line_end = end;
  return makeFinding(input);
}
