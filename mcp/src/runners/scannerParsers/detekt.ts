/**
 * detekt SARIF parser (`--report sarif:<file>`, detekt 1.23).
 *
 * Each result names its rule with its rule set — `detekt.complexity.LongMethod`
 * — and every level is `warning`, so the rule set decides both the
 * `quality_check` kind and the severity: `complexity` is `complexity`,
 * `naming` is `naming`, every other set a `smell`; the sets that report what
 * can go wrong at run time (`potential-bugs`, `exceptions`, `coroutines`) are
 * `medium`, `complexity`, `performance` and `empty-blocks` `low`, style,
 * naming and comments `info` — the scale shellcheck's and staticcheck's
 * findings use. Paths are `file:` URIs.
 */

import { fileURLToPath } from 'node:url';
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

const DETEKT_TOOL_NAME = 'detekt';

const KIND: Readonly<Record<string, 'complexity' | 'naming'>> = { complexity: 'complexity', naming: 'naming' };

const SEVERITY: Readonly<Record<string, Severity>> = {
  'potential-bugs': 'medium',
  exceptions: 'medium',
  coroutines: 'medium',
  complexity: 'low',
  performance: 'low',
  'empty-blocks': 'low',
};

export const detektParser: ScannerParser = {
  name: DETEKT_TOOL_NAME,
  parse(input: unknown, ctx: ParserContext = {}): ParserOutput {
    const findings: Finding[] = [];
    for (const run of asArray(getProp(parseInputAsJson(input), 'runs'))) {
      for (const result of asArray(getProp(run, 'results'))) {
        const finding = mapResult(result, ctx);
        if (finding) findings.push(finding);
      }
    }
    return { findings, cves: [] };
  },
};

/** `file:///C:/p/A.kt` → `C:\p\A.kt`; anything else as written. */
function pathOf(uri: string): string {
  if (!uri.startsWith('file:')) return uri;
  try {
    return fileURLToPath(uri);
  } catch {
    return uri;
  }
}

function mapResult(raw: unknown, ctx: ParserContext): Finding | null {
  const ruleId = getString(raw, 'ruleId');
  const location = getProp(asArray(getProp(raw, 'locations'))[0], 'physicalLocation');
  const uri = getString(getProp(location, 'artifactLocation'), 'uri');
  if (!ruleId || !uri) return null;
  // `detekt.<rule set>.<rule>`.
  const parts = ruleId.split('.');
  const rule = parts.at(-1) ?? ruleId;
  const set = parts.length >= 3 ? (parts[1] ?? '') : '';
  const message = getString(getProp(raw, 'message'), 'text') ?? `${rule} violation`;
  const region = getProp(location, 'region');
  const line = getNumber(region, 'startLine');
  const endLine = getNumber(region, 'endLine');
  const input: Parameters<typeof makeFinding>[0] = {
    tool: DETEKT_TOOL_NAME,
    rule_id: rule,
    severity: SEVERITY[set] ?? 'info',
    category: 'quality',
    subcategory: KIND[set] ?? 'smell',
    title: message,
    message: `${rule} (${set || 'detekt'}): ${message} (https://detekt.dev/docs/rules/${set || 'style'}#${rule.toLowerCase()})`,
    file_path: toRelativeIfPossible(pathOf(uri), ctx.project_path),
    fix_available: false,
  };
  if (line !== undefined) input.line_start = line;
  const end = endLine !== undefined && line !== undefined && endLine >= line ? endLine : line;
  if (end !== undefined) input.line_end = end;
  return makeFinding(input);
}
