/**
 * gosec (`-fmt=json`) output parser.
 *
 * The report's `Issues` carry `rule_id` (`G701`), `severity` and
 * `confidence` (HIGH/MEDIUM/LOW), `cwe: {id, url}` (`id` a numeric string),
 * `details`, an absolute `file`, `line` as a string — `"15"`, or `"15-17"` for
 * a span — and `code`: the flagged line with one line of context each side,
 * every line prefixed `N: ` (`findingIdentity.ts` strips the prefixes). An
 * issue `#nosec` suppressed carries `nosec: true` or a non-empty
 * `suppressions` and is reported only under `-show-ignored`; it is skipped
 * here either way. Severity maps directly; confidence goes into the message,
 * as Bandit's does.
 */

import type { Finding } from '../../types.js';
import { redactCredentialSnippet } from '../../redaction/secretFindingRedaction.js';
import {
  asArray,
  getProp,
  getString,
  makeFinding,
  normalizeSeverity,
  parseInputAsJson,
  toRelativeIfPossible,
  type ParserContext,
  type ParserOutput,
  type ScannerParser,
} from './index.js';

const GOSEC_TOOL_NAME = 'gosec';

/**
 * Rules whose flagged line holds a credential: their subcategory names it,
 * which is what `isCredentialFinding` reads — so the snippet is redacted and
 * the identity never hashes the secret. G101 is "hard-coded credentials"
 * (CWE-798); G117 (CWE-499) flags a field that MAY be marshalled out, not a
 * value, and is not one.
 */
const CREDENTIAL_RULES: Readonly<Record<string, string>> = { G101: 'hardcoded_credentials' };

export const gosecParser: ScannerParser = {
  name: GOSEC_TOOL_NAME,
  parse(input: unknown, ctx: ParserContext = {}): ParserOutput {
    const root = parseInputAsJson(input);
    const findings: Finding[] = [];
    for (const raw of asArray(getProp(root, 'Issues'))) {
      const finding = mapIssue(raw, ctx);
      if (finding) findings.push(finding);
    }
    return { findings, cves: [] };
  },
};

/** `"15"` → 15–15, `"15-17"` → 15–17; undefined for anything else. */
function lineSpan(raw: string | undefined): { start: number; end: number } | undefined {
  const m = /^\s*(\d+)(?:\s*-\s*(\d+))?\s*$/.exec(raw ?? '');
  if (m === null) return undefined;
  const start = Number(m[1]);
  const end = m[2] !== undefined ? Number(m[2]) : start;
  return start >= 1 ? { start, end: Math.max(start, end) } : undefined;
}

function mapIssue(raw: unknown, ctx: ParserContext): Finding | null {
  const ruleId = getString(raw, 'rule_id');
  const file = getString(raw, 'file');
  if (!ruleId || !file) return null;
  if (getProp(raw, 'nosec') === true || asArray(getProp(raw, 'suppressions')).length > 0) return null;

  const details = getString(raw, 'details');
  const confidence = getString(raw, 'confidence');
  const span = lineSpan(getString(raw, 'line'));
  const code = getString(raw, 'code');
  const subcategory = CREDENTIAL_RULES[ruleId];

  const input: Parameters<typeof makeFinding>[0] = {
    tool: GOSEC_TOOL_NAME,
    rule_id: ruleId,
    severity: normalizeSeverity(getString(raw, 'severity')),
    category: 'security',
    title: details ?? `gosec ${ruleId}`,
    file_path: toRelativeIfPossible(file, ctx.project_path),
    fix_available: false,
    taxonomy: { cwe: getProp(getProp(raw, 'cwe'), 'id') },
  };
  if (subcategory !== undefined) input.subcategory = subcategory;
  if (details !== undefined) input.message = confidence ? `${details} (confidence: ${confidence.toLowerCase()})` : details;
  if (span !== undefined) {
    input.line_start = span.start;
    input.line_end = span.end;
  }
  if (code !== undefined) input.snippet = code;
  return redactCredentialSnippet(makeFinding(input));
}
