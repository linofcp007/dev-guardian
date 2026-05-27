/**
 * Ruff JSON parser.
 *
 * Output is a top-level array of `{code, filename, location, end_location,
 * message, fix}`. We map ruff rule codes to severity by prefix family:
 *
 *   S* (flake8-bandit, security)         → high
 *   F*, E*, B*, ARG* (functional issues) → medium
 *   W*, N*, RUF*, PL* (style/warnings)   → low
 *   everything else                      → low
 *
 * `fix_available` is true when ruff includes a `fix` payload (any
 * applicability — the caller decides whether to apply automatically).
 */

import type { Category, Finding, Severity } from '../../types.js';
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

export const RUFF_TOOL_NAME = 'ruff';

export const ruffParser: ScannerParser = {
  name: RUFF_TOOL_NAME,
  parse(input: unknown, ctx: ParserContext = {}): ParserOutput {
    const root = parseInputAsJson(input);
    const items = Array.isArray(root) ? root : asArray(getProp(root, 'results'));
    const findings: Finding[] = [];

    for (const raw of items) {
      const finding = mapItem(raw, ctx);
      if (finding) findings.push(finding);
    }

    return { findings, cves: [] };
  },
};

function mapItem(raw: unknown, ctx: ParserContext): Finding | null {
  const code = getString(raw, 'code');
  const filename = getString(raw, 'filename');
  if (!code || !filename) return null;

  const message = getString(raw, 'message');
  const location = getProp(raw, 'location');
  const endLocation = getProp(raw, 'end_location');
  const lineStart = getNumber(location, 'row');
  const lineEnd = getNumber(endLocation, 'row') ?? lineStart;
  const hasFix = getProp(raw, 'fix') !== undefined && getProp(raw, 'fix') !== null;

  const { severity, category } = classifyRuff(code);

  const input: Parameters<typeof makeFinding>[0] = {
    tool: RUFF_TOOL_NAME,
    rule_id: code,
    severity,
    category,
    subcategory: code.replace(/[0-9]+$/, ''), // 'F401' -> 'F'
    title: message ?? `${code} violation`,
    file_path: toRelativeIfPossible(filename, ctx.project_path),
    fix_available: hasFix,
  };
  if (message !== undefined) input.message = message;
  if (lineStart !== undefined) input.line_start = lineStart;
  if (lineEnd !== undefined) input.line_end = lineEnd;
  return makeFinding(input);
}

function classifyRuff(code: string): { severity: Severity; category: Category } {
  if (code.startsWith('S')) return { severity: 'high', category: 'security' };
  if (code.startsWith('F') || code.startsWith('E') || code.startsWith('B') || code.startsWith('ARG'))
    return { severity: 'medium', category: 'quality' };
  return { severity: 'low', category: 'quality' };
}
