/**
 * ESLint `--format json` parser.
 *
 * The report is an array of `{ filePath, messages: [{ ruleId, severity,
 * message, line, endLine, fatal? }] }`. Every message with a rule id becomes a
 * `quality` finding; ESLint's severity 2 ("error") is `medium`, 1 ("warn")
 * `low`. A message without a rule id is a fatal parse error for that file —
 * not a finding about the code, but a file ESLint could not analyse — and is
 * reported through {@link eslintFatalErrors} instead, so the tool can say so.
 *
 * `subcategory` is the `quality_check` category the rule belongs to
 * (`complexity`, `naming`, else `smell`), which is what its `categories`
 * input filters on.
 */

import type { Finding } from '../../types.js';
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

export const ESLINT_TOOL_NAME = 'eslint';

/** Core and common-plugin rules that measure complexity. */
const COMPLEXITY_RULES = new Set([
  'complexity',
  'max-depth',
  'max-lines',
  'max-lines-per-function',
  'max-nested-callbacks',
  'max-params',
  'max-statements',
  'sonarjs/cognitive-complexity',
]);

/** Core and common-plugin rules about identifiers. */
const NAMING_RULES = new Set([
  'camelcase',
  'id-denylist',
  'id-length',
  'id-match',
  'new-cap',
  '@typescript-eslint/naming-convention',
]);

export const eslintParser: ScannerParser = {
  name: ESLINT_TOOL_NAME,
  parse(input: unknown, ctx: ParserContext = {}): ParserOutput {
    const findings: Finding[] = [];
    for (const file of fileEntries(input)) {
      const filePath = getString(file, 'filePath');
      if (!filePath) continue;
      for (const msg of asArray(getProp(file, 'messages'))) {
        const finding = mapMessage(msg, filePath, ctx);
        if (finding) findings.push(finding);
      }
    }
    return { findings, cves: [] };
  },
};

/** `<file>: <message>` for every message ESLint raised without a rule (parse errors). */
export function eslintFatalErrors(input: unknown): string[] {
  const out: string[] = [];
  for (const file of fileEntries(input)) {
    const filePath = getString(file, 'filePath') ?? '(unknown file)';
    for (const msg of asArray(getProp(file, 'messages'))) {
      if (typeof getProp(msg, 'ruleId') === 'string') continue;
      out.push(`${filePath}: ${getString(msg, 'message') ?? 'parse error'}`);
    }
  }
  return out;
}

function fileEntries(input: unknown): unknown[] {
  const root = parseInputAsJson(input);
  return Array.isArray(root) ? root : [];
}

function mapMessage(raw: unknown, filePath: string, ctx: ParserContext): Finding | null {
  const ruleId = getString(raw, 'ruleId');
  if (!ruleId) return null;
  const message = getString(raw, 'message') ?? `${ruleId} violation`;
  const line = getNumber(raw, 'line');
  const endLine = getNumber(raw, 'endLine') ?? line;
  const input: Parameters<typeof makeFinding>[0] = {
    tool: ESLINT_TOOL_NAME,
    rule_id: ruleId,
    severity: getNumber(raw, 'severity') === 2 ? 'medium' : 'low',
    category: 'quality',
    subcategory: COMPLEXITY_RULES.has(ruleId) ? 'complexity' : NAMING_RULES.has(ruleId) ? 'naming' : 'smell',
    title: message,
    message,
    file_path: toRelativeIfPossible(filePath, ctx.project_path),
    fix_available: getProp(raw, 'fix') !== undefined,
  };
  if (line !== undefined) input.line_start = line;
  if (endLine !== undefined) input.line_end = endLine;
  return makeFinding(input);
}
