/**
 * Scanner parser interface and shared helpers.
 *
 * Each parser converts a single scanner's raw output (string or already-
 * parsed JSON) into the canonical `ParserOutput` shape:
 *   - `findings[]` — what the scan-tool factory persists into `findings`
 *   - `cves[]`     — only populated by parsers that yield package CVEs
 *                    (currently just Trivy)
 *
 * Parsers must be pure functions over their input: no I/O, no global state,
 * no time. Anything tool-side (scan_id, project_path resolution) is the
 * caller's responsibility.
 *
 * Severity normalization: every parser maps its scanner-native severity to
 * one of {info, low, medium, high, critical}. Unknown / missing severities
 * default to `medium` — neither suppressed nor escalated — and the parser
 * may flag them via the `subcategory` if it matters.
 */

import { computeFingerprint } from '../../fingerprint/findingFingerprint.js';
import { classifyTaxonomy } from '../../frameworks/taxonomy.js';
import type { Category, Finding, Severity } from '../../types.js';

export interface ParserContext {
  /**
   * Project root the scanner ran against. Used by parsers to normalize file
   * paths to project-relative when the scanner reports absolute paths.
   */
  project_path?: string;
  /**
   * The source file this invocation's raw output should be attributed to,
   * for a scanner whose own output carries no per-finding file path at all
   * (`pipAudit.ts` — pip-audit's JSON never says which requirements file a
   * dependency came from). Every other parser here already reads its own
   * per-finding path from the scanner's output and ignores this field.
   */
  source_file?: string;
  /**
   * Semgrep only: maps a `check_id` to the rule's own id, without the path
   * prefix Semgrep derives from a local config's location
   * (`runners/semgrepRuleIds.ts`). Set by `semgrepParserFor`.
   */
  semgrep_rule_id?: (checkId: string) => string;
}

export interface ParserCveInput {
  cve_id: string;
  package_name: string;
  installed_version?: string;
  fixed_version?: string;
  severity: Severity;
}

export interface ParserOutput {
  findings: Finding[];
  cves: ParserCveInput[];
}

export interface ScannerParser {
  /** Canonical scanner name as written to `findings.tool`. */
  name: string;
  parse(input: unknown, ctx?: ParserContext): ParserOutput;
}

/**
 * Convert backslashes to forward slashes and strip a Windows drive prefix.
 * Idempotent for already-POSIX paths.
 */
export function toPosixPath(p: string): string {
  if (!p) return p;
  return p.replace(/^[a-zA-Z]:/, '').replace(/\\/g, '/');
}

/**
 * If a scanner reports an absolute path, try to express it as
 * project-relative when we know the project root. Falls back to the
 * scanner's value when the path is outside the project.
 */
export function toRelativeIfPossible(filePath: string, projectPath?: string): string {
  if (!filePath || !projectPath) return toPosixPath(filePath);
  const posixFile = toPosixPath(filePath);
  const posixRoot = toPosixPath(projectPath).replace(/\/$/, '');
  if (posixFile.startsWith(`${posixRoot}/`)) {
    return posixFile.slice(posixRoot.length + 1);
  }
  if (posixFile === posixRoot) return '';
  return posixFile;
}

/**
 * Limit a snippet to 1 KB before storage. Long snippets bloat the DB and
 * give diminishing context for the model; the fingerprint already uses the
 * 1-KB cap so we stay consistent.
 */
const SNIPPET_MAX_BYTES = 1024;

export function clampSnippet(snippet: string | undefined): string | undefined {
  if (snippet === undefined || snippet === null) return undefined;
  if (snippet.length === 0) return undefined;
  return snippet.length > SNIPPET_MAX_BYTES ? snippet.slice(0, SNIPPET_MAX_BYTES) : snippet;
}

/**
 * Constructor for a Finding that auto-computes the fingerprint and applies
 * the defaults required by the strict `Finding` type. Parsers should always
 * go through this helper rather than building findings by hand.
 *
 * `taxonomy` is what the scanner said about the weakness — CWEs and OWASP
 * labels, as strings or lists, raw (`frameworks/taxonomy.ts`
 * `classifyTaxonomy` normalises them and derives the 2025 categories). It
 * sets `cwe`/`owasp` and is deliberately NOT part of the fingerprint: a
 * scanner that starts naming a CWE must not turn a stored finding into a new
 * one.
 */
export function makeFinding(input: {
  tool: string;
  rule_id?: string;
  severity: Severity;
  category: Category;
  subcategory?: string;
  title: string;
  message?: string;
  file_path?: string;
  line_start?: number;
  line_end?: number;
  snippet?: string;
  fix_available?: boolean;
  taxonomy?: { cwe?: unknown; owasp?: unknown; deriveOwasp?: boolean };
}): Finding {
  const snippet = clampSnippet(input.snippet);
  const fingerprintInput: Parameters<typeof computeFingerprint>[0] = {
    tool: input.tool,
  };
  if (input.rule_id !== undefined) fingerprintInput.rule_id = input.rule_id;
  if (input.file_path !== undefined) fingerprintInput.file_path = input.file_path;
  if (input.line_start !== undefined) fingerprintInput.line_start = input.line_start;
  if (input.line_end !== undefined) fingerprintInput.line_end = input.line_end;
  if (snippet !== undefined) fingerprintInput.snippet = snippet;

  const fingerprint = computeFingerprint(fingerprintInput);

  const finding: Finding = {
    fingerprint,
    tool: input.tool,
    severity: input.severity,
    category: input.category,
    title: input.title,
    fix_available: input.fix_available ?? false,
  };
  if (input.rule_id !== undefined) finding.rule_id = input.rule_id;
  if (input.subcategory !== undefined) finding.subcategory = input.subcategory;
  if (input.message !== undefined) finding.message = input.message;
  if (input.file_path !== undefined) finding.file_path = input.file_path;
  if (input.line_start !== undefined) finding.line_start = input.line_start;
  if (input.line_end !== undefined) finding.line_end = input.line_end;
  if (snippet !== undefined) finding.snippet = snippet;
  if (input.taxonomy !== undefined) {
    const { cwe, owasp } = classifyTaxonomy(input.taxonomy);
    if (cwe !== undefined) finding.cwe = cwe;
    if (owasp !== undefined) finding.owasp = owasp;
  }
  return finding;
}

/**
 * The weakness every finding of a class is by definition, whatever its
 * scanner calls it: a known-vulnerable dependency is CWE-1395 (Dependency on
 * Vulnerable Third-Party Component), a committed secret CWE-798 (Use of
 * Hard-coded Credentials). OWASP Top 10:2025 maps them to A03 and A07.
 */
export const DEPENDENCY_CWE = 'CWE-1395';
export const SECRET_CWE = 'CWE-798';

/**
 * A known-vulnerable dependency's taxonomy: CWE-1395 plus whatever CWEs its
 * advisory names (the flaw inside the package), and OWASP A03 ONLY. The
 * advisory's CWE-79 is a flaw in someone else's code that the project
 * inherits through its supply chain, not the project's own injection bug,
 * so it is recorded in `cwe` and never counted under A05.
 */
export function dependencyTaxonomy(advisoryCwes: readonly unknown[] = []): {
  cwe: unknown[];
  owasp: string[];
  deriveOwasp: false;
} {
  return { cwe: [DEPENDENCY_CWE, ...advisoryCwes], owasp: ['A03:2025'], deriveOwasp: false };
}

/**
 * Standard scanner severity strings → canonical `Severity`. Scanners differ
 * in casing and vocabulary; this is the lookup table they all bottom out
 * through.
 */
export function normalizeSeverity(raw: string | undefined | null): Severity {
  if (!raw) return 'medium';
  const normalized = raw.toString().trim().toLowerCase();
  switch (normalized) {
    case 'info':
    case 'informational':
    case 'unknown':
    case 'note':
      return 'info';
    case 'low':
    case 'minor':
      return 'low';
    case 'medium':
    case 'moderate':
    case 'warning':
      return 'medium';
    case 'high':
    case 'error':
    case 'major':
      return 'high';
    case 'critical':
    case 'severe':
    case 'blocker':
      return 'critical';
    default:
      return 'medium';
  }
}

/**
 * Safely access a nested property without making callers wade through
 * `as Record<string, unknown>` casts.
 */
export function getProp(obj: unknown, key: string): unknown {
  if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
    return (obj as Record<string, unknown>)[key];
  }
  return undefined;
}

export function getString(obj: unknown, key: string): string | undefined {
  const v = getProp(obj, key);
  return typeof v === 'string' ? v : undefined;
}

export function getNumber(obj: unknown, key: string): number | undefined {
  const v = getProp(obj, key);
  return typeof v === 'number' && Number.isFinite(v) ? v : undefined;
}

export function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

export function parseInputAsJson(input: unknown): unknown {
  if (typeof input !== 'string') return input;
  if (input.trim() === '') return null;
  try {
    return JSON.parse(input);
  } catch {
    return null;
  }
}
