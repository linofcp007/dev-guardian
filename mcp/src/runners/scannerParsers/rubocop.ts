/**
 * RuboCop `--format json` parser.
 *
 * `{ metadata, files: [{ path, offenses: [{ severity, message, cop_name,
 * location: { start_line, last_line } }] }], summary }`. The department
 * decides the `quality_check` kind: `Metrics/*` is `complexity`, `Naming/*`
 * `naming`, `Lint/*` and `Security/*` a `smell`. RuboCop's own severity
 * decides the finding's, on the scale shellcheck's and detekt's use: `fatal`
 * and `error` are `medium` (a `Security/*` cop's warning too — `eval`,
 * `Marshal.load`, `YAML.load`), `warning` `low`, `convention` and `refactor`
 * `info`. `Lint/Syntax` is a finding too — the file does not parse — and its
 * file is also named a partial gap by `runners/rubocopRun.ts`.
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

const RUBOCOP_TOOL_NAME = 'rubocop';

const SEVERITY: Readonly<Record<string, Severity>> = {
  fatal: 'medium',
  error: 'medium',
  warning: 'low',
  convention: 'info',
  refactor: 'info',
  info: 'info',
};

const KIND: Readonly<Record<string, 'complexity' | 'naming'>> = { Metrics: 'complexity', Naming: 'naming' };

export const rubocopParser: ScannerParser = {
  name: RUBOCOP_TOOL_NAME,
  parse(input: unknown, ctx: ParserContext = {}): ParserOutput {
    const findings: Finding[] = [];
    for (const file of asArray(getProp(parseInputAsJson(input), 'files'))) {
      const path = getString(file, 'path');
      if (!path) continue;
      for (const offense of asArray(getProp(file, 'offenses'))) {
        const finding = mapOffense(offense, path, ctx);
        if (finding) findings.push(finding);
      }
    }
    return { findings, cves: [] };
  },
};

function mapOffense(raw: unknown, path: string, ctx: ParserContext): Finding | null {
  const cop = getString(raw, 'cop_name');
  if (!cop) return null;
  const department = cop.slice(0, cop.indexOf('/'));
  const level = getString(raw, 'severity') ?? '';
  const message = getString(raw, 'message') ?? `${cop} offense`;
  const location = getProp(raw, 'location');
  const line = getNumber(location, 'start_line') ?? getNumber(location, 'line');
  const last = getNumber(location, 'last_line');
  const severity: Severity = department === 'Security' && level === 'warning' ? 'medium' : (SEVERITY[level] ?? 'info');
  const input: Parameters<typeof makeFinding>[0] = {
    tool: RUBOCOP_TOOL_NAME,
    rule_id: cop,
    severity,
    category: 'quality',
    subcategory: KIND[department] ?? 'smell',
    title: message,
    message: `${cop}: ${message} (https://docs.rubocop.org/rubocop/cops_${department.toLowerCase()}.html#${cop.toLowerCase().replace('/', '')})`,
    file_path: toRelativeIfPossible(path, ctx.project_path),
    fix_available: false,
  };
  if (line !== undefined) input.line_start = line;
  const end = last !== undefined && line !== undefined && last >= line ? last : line;
  if (end !== undefined) input.line_end = end;
  return makeFinding(input);
}
