/**
 * hadolint JSON output parser.
 *
 * `hadolint --format json <Dockerfile>` prints a flat JSON array — one entry
 * per check failure (and, separately, per parse error, in the same shape):
 * `{ file, line, column, level, code, message }` — confirmed against
 * hadolint's own formatter source (`src/Hadolint/Formatter/Json.hs`) rather
 * than assumed. `level` is one of `error | warning | info | style`;
 * `normalizeSeverity` already maps `error`->high and `warning`->medium, and
 * `style` (not one of its cases) falls through to its documented default,
 * `medium` — deliberately: hadolint's own severities span security-relevant
 * rules (DL3002 "last USER should not be root") and pure style ones
 * (DL3059 "consecutive RUN"), and neither this parser nor hadolint itself
 * tags which is which.
 *
 * hadolint exits 1 when it found anything at or above its failure threshold
 * (default: any finding) — same convention as jscpd/ruff/bandit/staticcheck
 * elsewhere in this codebase: a non-zero exit WITH a report is a result, not
 * a failure. The caller (`scanContainers.ts`) treats exit 0 and 1 alike.
 */

import type { Finding } from '../../types.js';
import {
  asArray,
  getNumber,
  getString,
  makeFinding,
  normalizeSeverity,
  parseInputAsJson,
  toRelativeIfPossible,
  type ParserContext,
  type ParserOutput,
  type ScannerParser,
} from './index.js';

export const HADOLINT_TOOL_NAME = 'hadolint';

export const hadolintParser: ScannerParser = {
  name: HADOLINT_TOOL_NAME,
  parse(input: unknown, ctx: ParserContext = {}): ParserOutput {
    const root = parseInputAsJson(input);
    const findings: Finding[] = [];
    for (const raw of asArray(root)) {
      const finding = mapEntry(raw, ctx);
      if (finding) findings.push(finding);
    }
    return { findings, cves: [] };
  },
};

function mapEntry(raw: unknown, ctx: ParserContext): Finding | null {
  const code = getString(raw, 'code');
  if (!code) return null;
  const message = getString(raw, 'message') ?? code;
  const file = getString(raw, 'file');
  const line = getNumber(raw, 'line');

  const input: Parameters<typeof makeFinding>[0] = {
    tool: HADOLINT_TOOL_NAME,
    rule_id: code,
    severity: normalizeSeverity(getString(raw, 'level')),
    category: 'security',
    subcategory: 'dockerfile-lint',
    title: message,
    fix_available: false,
  };
  if (file !== undefined) input.file_path = toRelativeIfPossible(file, ctx.project_path);
  if (line !== undefined) {
    input.line_start = line;
    input.line_end = line;
  }
  return makeFinding(input);
}
