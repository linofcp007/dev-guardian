/**
 * Semgrep `--json` output parser.
 *
 * Maps each entry in `results[]` to a single Finding:
 *   - severity:    extra.severity (INFO/WARNING/ERROR) → info/medium/high,
 *                  bumped to `critical` for security rules.
 *   - category:    extra.metadata.category when present, else heuristic on
 *                  the check_id; falls back to 'quality'.
 *   - subcategory: extra.metadata.subcategory or heuristic
 *   - rule_id:     check_id
 *   - file_path:   path, normalised to project-relative POSIX
 *   - line range:  start.line .. end.line
 *   - snippet:     extra.lines, clamped to 1 KB by `makeFinding`
 *   - fix_available: true when `extra.fix` (autofix string) exists
 */

import type { Category, Finding, Severity } from '../../types.js';
import {
  asArray,
  getNumber,
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

export const SEMGREP_TOOL_NAME = 'semgrep';

export const semgrepParser: ScannerParser = {
  name: SEMGREP_TOOL_NAME,
  parse(input: unknown, ctx: ParserContext = {}): ParserOutput {
    const root = parseInputAsJson(input);
    const results = asArray(getProp(root, 'results'));
    const findings: Finding[] = [];

    for (const raw of results) {
      const finding = mapResult(raw, ctx);
      if (finding) findings.push(finding);
    }

    return { findings, cves: [] };
  },
};

function mapResult(raw: unknown, ctx: ParserContext): Finding | null {
  const extra = getProp(raw, 'extra');
  const start = getProp(raw, 'start');
  const end = getProp(raw, 'end');
  const metadata = getProp(extra, 'metadata');

  const checkId = getString(raw, 'check_id');
  const message = getString(extra, 'message');
  const filePath = getString(raw, 'path');
  if (!checkId || !filePath) return null;

  const severity = mapSeverity(getString(extra, 'severity'), metadata);
  const category = mapCategory(metadata, checkId);
  const subcategory = mapSubcategory(metadata, checkId);
  const lineStart = getNumber(start, 'line');
  const lineEnd = getNumber(end, 'line') ?? lineStart;

  const fixAvailable =
    getString(extra, 'fix') !== undefined ||
    Array.isArray(getProp(extra, 'fixed_lines'));

  const input: Parameters<typeof makeFinding>[0] = {
    tool: SEMGREP_TOOL_NAME,
    rule_id: checkId,
    severity,
    category,
    title: shortenTitle(message, checkId),
    fix_available: fixAvailable,
    file_path: toRelativeIfPossible(filePath, ctx.project_path),
  };
  if (message !== undefined) input.message = message;
  if (subcategory !== undefined) input.subcategory = subcategory;
  if (lineStart !== undefined) input.line_start = lineStart;
  if (lineEnd !== undefined) input.line_end = lineEnd;
  const snippet = getString(extra, 'lines');
  if (snippet !== undefined) input.snippet = snippet;

  return makeFinding(input);
}

function mapSeverity(rawSeverity: string | undefined, metadata: unknown): Severity {
  // Semgrep's three-level severity is too coarse for security rules; if the
  // rule self-identifies as security, bump ERROR → critical so it actually
  // shows up in the critical bucket.
  const base = normalizeSeverity(rawSeverity);
  const cat = getString(metadata, 'category')?.toLowerCase();
  if (base === 'high' && (cat === 'security' || cat === 'vulnerability')) return 'critical';
  return base;
}

function mapCategory(metadata: unknown, checkId: string): Category {
  const explicit = getString(metadata, 'category')?.toLowerCase();
  if (explicit) {
    if (explicit === 'security' || explicit === 'vulnerability') return 'security';
    if (explicit === 'performance') return 'performance';
    if (explicit === 'best-practice' || explicit === 'maintainability' || explicit === 'correctness')
      return 'quality';
    if (explicit === 'bug' || explicit === 'correctness') return 'bug';
  }

  // Heuristic on the check_id string.
  const lowered = checkId.toLowerCase();
  if (
    /(security|audit|sqli|xss|injection|secret|crypto|csrf|ssrf|deserial|path[-_]traversal)/i.test(
      lowered,
    )
  ) {
    return 'security';
  }
  if (/(perf|performance|n-plus-one|slow)/i.test(lowered)) return 'performance';
  if (/(bug|race|null|undefined|nullable|off[-_]by[-_]one)/i.test(lowered)) return 'bug';
  return 'quality';
}

function mapSubcategory(metadata: unknown, checkId: string): string | undefined {
  const explicit = getString(metadata, 'subcategory');
  if (explicit) return explicit.toLowerCase();
  const owasp = getString(metadata, 'owasp');
  if (owasp) return owasp.toLowerCase().split(':')[0];
  // Try the last segment of the check_id as a coarse subcategory.
  const parts = checkId.split('.');
  const last = parts.at(-1);
  return last && last !== checkId ? last : undefined;
}

function shortenTitle(message: string | undefined, checkId: string): string {
  if (message && message.length > 0) {
    const firstLine = message.split(/\r?\n/)[0] ?? message;
    return firstLine.length > 140 ? firstLine.slice(0, 137) + '…' : firstLine;
  }
  return checkId;
}
