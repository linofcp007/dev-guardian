/**
 * Ruff JSON parser.
 *
 * Output is a top-level array of `{code, filename, location, end_location,
 * message, fix}`. We map ruff rule codes to severity by family — the code's
 * letters, compared whole (`SIM102` is flake8-simplify, never `S`):
 *
 *   S (flake8-bandit, security)          → high
 *   F, E, B, ARG (functional issues)     → medium
 *   W, N, RUF, PL*, SIM, … (style)       → low
 *   everything else                      → low
 *
 * `fix_available` is true when ruff includes a `fix` payload (any
 * applicability — the caller decides whether to apply automatically).
 *
 * A syntax error is no finding: the file it is in was not linted, which
 * {@link ruffSyntaxErrors} names for the run (`partially_parsed`).
 */

import type { Category, Finding, PartialParse, Severity } from '../../types.js';
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

const RUFF_TOOL_NAME = 'ruff';

/** `ToolRun.partially_parsed`'s type for a file Ruff could not parse — the label the CI gate accepts. */
const RUFF_SYNTAX_ERROR = 'Syntax error';

export const ruffParser: ScannerParser = {
  name: RUFF_TOOL_NAME,
  parse(input: unknown, ctx: ParserContext = {}): ParserOutput {
    const findings: Finding[] = [];

    for (const raw of entries(input)) {
      const finding = mapItem(raw, ctx);
      if (finding) findings.push(finding);
    }

    return { findings, cves: [] };
  },
};

function entries(input: unknown): unknown[] {
  const root = parseInputAsJson(input);
  return Array.isArray(root) ? root : asArray(getProp(root, 'results'));
}

/**
 * Whether a report entry is a syntax error rather than a rule's finding. Read
 * from Ruff's own JSON renderer snapshots (`…json__tests__syntax_errors.snap`,
 * 2026-10-25): 0.5.0 to 0.12.0 write `code: null` and a `SyntaxError: …`
 * message, 0.13.0 to 0.17.2 `code: "invalid-syntax"`; before 0.5 it was rule
 * E999 (`syntax-error`).
 */
function isSyntaxError(raw: unknown): boolean {
  const code = getProp(raw, 'code');
  return code === null || code === undefined || code === 'invalid-syntax' || code === 'E999';
}

/**
 * The files Ruff could not parse — and so did not lint — once each,
 * project-relative when inside `projectPath`: one `Syntax error` entry with
 * the first message for each.
 */
export function ruffSyntaxErrors(input: unknown, projectPath?: string): PartialParse[] {
  const out: PartialParse[] = [];
  for (const raw of entries(input)) {
    const filename = getString(raw, 'filename');
    if (filename === undefined || !isSyntaxError(raw)) continue;
    const file = toRelativeIfPossible(filename, projectPath);
    if (out.some((p) => p.file === file)) continue;
    out.push({ file, type: RUFF_SYNTAX_ERROR, message: (getString(raw, 'message') ?? 'syntax error').slice(0, 300) });
  }
  return out;
}

function mapItem(raw: unknown, ctx: ParserContext): Finding | null {
  const code = getString(raw, 'code');
  const filename = getString(raw, 'filename');
  if (!code || !filename || isSyntaxError(raw)) return null;

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

/** The functional families: pyflakes, pycodestyle errors, bugbear, unused arguments. */
const MEDIUM_FAMILIES: ReadonlySet<string> = new Set(['F', 'E', 'B', 'ARG']);

function classifyRuff(code: string): { severity: Severity; category: Category } {
  // The letters before the number: `S105` → S, `SIM102` → SIM (startsWith('S') made every SIM, SLF and SLOT high security).
  const family = code.replace(/[0-9]+$/, '');
  if (family === 'S') return { severity: 'high', category: 'security' };
  if (MEDIUM_FAMILIES.has(family)) return { severity: 'medium', category: 'quality' };
  return { severity: 'low', category: 'quality' };
}
