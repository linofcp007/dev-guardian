/**
 * PHPCS `--report=json` parser.
 *
 * Top-level shape:
 *   {
 *     "totals": { "errors": N, "warnings": M, … },
 *     "files": {
 *       "src/foo.php": {
 *         "errors": 3,
 *         "warnings": 1,
 *         "messages": [
 *           { "message": "...", "source": "WordPress.Security.EscapeOutput.OutputNotEscaped",
 *             "severity": 5, "line": 10, "column": 5, "type": "ERROR" }
 *         ]
 *       }
 *     }
 *   }
 *
 * Severity mapping (PHPCS 1-5 numeric):
 *   >=5 → high, >=3 → medium, else low.
 *
 * Category:
 *   `source` starts with `WordPress.Security.` → security
 *   `source` starts with `Generic.Files.` / `Squiz.` / `PEAR.` → quality
 *   otherwise → quality
 *
 * A file PHPCS did not process is no finding: {@link phpcsUnprocessed}
 * names it for the run (`partially_parsed`).
 */

import type { Category, Finding, PartialParse, Severity } from '../../types.js';
import {
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

const PHPCS_TOOL_NAME = 'phpcs';

/**
 * PHPCS's own messages for a file it did not process (`src/Files/File.php`
 * and `src/Runner.php` at 3.13.5): a sniff threw and "checking has been
 * aborted" (`Internal.Exception`), the tokenizer refused the file — it is
 * then ignored (`Internal.Tokenizer.Exception`) — or, with short open tags
 * off, the file was all inline HTML and "nothing will be checked"
 * (`Internal.NoCodeFound`).
 */
const UNPROCESSED_SOURCES: ReadonlySet<string> = new Set(['Internal.Exception', 'Internal.Tokenizer.Exception', 'Internal.NoCodeFound']);

/** `ToolRun.partially_parsed`'s type for such a file. */
const PHPCS_NOT_ANALYSED = 'Not analysed';

export const phpcsParser: ScannerParser = {
  name: PHPCS_TOOL_NAME,
  parse(input: unknown, ctx: ParserContext = {}): ParserOutput {
    const findings: Finding[] = [];
    for (const [filePath, m] of messagesOf(input)) {
      const finding = mapMessage(filePath, m, ctx);
      if (finding) findings.push(finding);
    }
    return { findings, cves: [] };
  },
};

/** Every message of the report, with the file it is in. */
function messagesOf(input: unknown): Array<[string, unknown]> {
  const files = getProp(parseInputAsJson(input), 'files');
  if (!files || typeof files !== 'object') return [];
  const out: Array<[string, unknown]> = [];
  for (const [filePath, rawFileEntry] of Object.entries(files as Record<string, unknown>)) {
    const messages = getProp(rawFileEntry, 'messages');
    if (!Array.isArray(messages)) continue;
    for (const m of messages) out.push([filePath, m]);
  }
  return out;
}

/**
 * The files PHPCS did not process, or stopped processing
 * ({@link UNPROCESSED_SOURCES}) — once each, project-relative when inside
 * `projectPath`, PHPCS's code and message in the entry's message. Measured on
 * PHPCS 3.13.5 with WPCS 3.3.0 (2026-10-25): those messages were read as
 * findings — `Internal.Exception` a high one — and phpcs-wpcs stayed `ok`.
 */
export function phpcsUnprocessed(input: unknown, projectPath?: string): PartialParse[] {
  const out: PartialParse[] = [];
  for (const [filePath, m] of messagesOf(input)) {
    const source = getString(m, 'source');
    if (source === undefined || !UNPROCESSED_SOURCES.has(source)) continue;
    const file = toRelativeIfPossible(filePath, projectPath);
    if (out.some((p) => p.file === file)) continue;
    out.push({ file, type: PHPCS_NOT_ANALYSED, message: `${source}: ${getString(m, 'message') ?? 'not processed'}`.slice(0, 300) });
  }
  return out;
}

function mapMessage(filePath: string, raw: unknown, ctx: ParserContext): Finding | null {
  const source = getString(raw, 'source');
  const message = getString(raw, 'message');
  if (!source || !message || UNPROCESSED_SOURCES.has(source)) return null;

  const sev = getNumber(raw, 'severity');
  const severity = mapSeverity(sev);
  const category = mapCategory(source);
  const lineStart = getNumber(raw, 'line');
  // PHPCS doesn't always emit `end_line`; reuse start.
  const lineEnd = lineStart;

  const input: Parameters<typeof makeFinding>[0] = {
    tool: PHPCS_TOOL_NAME,
    rule_id: source,
    severity,
    category,
    subcategory: source.split('.').slice(0, 3).join('.'), // e.g. WordPress.Security.EscapeOutput
    title: message,
    message,
    file_path: toRelativeIfPossible(filePath, ctx.project_path),
    // A JSON boolean (3.13.5); the old expression was `false` whatever it said.
    fix_available: getProp(raw, 'fixable') === true,
  };
  if (lineStart !== undefined) input.line_start = lineStart;
  if (lineEnd !== undefined) input.line_end = lineEnd;
  return makeFinding(input);
}

function mapSeverity(n: number | undefined): Severity {
  if (n === undefined) return 'low';
  if (n >= 5) return 'high';
  if (n >= 3) return 'medium';
  return 'low';
}

function mapCategory(source: string): Category {
  if (source.startsWith('WordPress.Security.')) return 'security';
  if (source.startsWith('WordPress.DB.')) return 'security'; // SQL prep
  if (source.startsWith('WordPress.XSS.')) return 'security';
  return 'quality';
}
