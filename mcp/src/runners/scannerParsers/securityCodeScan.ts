/**
 * Parser for `dotnet build` output enriched with security-code-scan (SCS)
 * Roslyn analyzer warnings.
 *
 * Line format:
 *   <file>(<line>,<col>): warning SCS0006: <message> [<csproj-path>]
 *   <file>(<line>,<col>): error SCS0006: <message> [<csproj-path>]
 *
 * We only extract lines that match the SCS rule id family. Non-SCS
 * build output (CSC, CA, etc.) is left to dotnet itself; we don't try
 * to be a generic dotnet warning parser.
 *
 * Severity: SCS rules are security-focused. Default to `high`. The small
 * static `LOWER_SEVERITY` set carries rule ids that are advisory.
 */

import type { Category, Finding, Severity } from '../../types.js';
import {
  makeFinding,
  toRelativeIfPossible,
  type ParserContext,
  type ParserOutput,
  type ScannerParser,
} from './index.js';

export const SCS_TOOL_NAME = 'security-code-scan';

// Lowered severity for SCS rules that are advisory rather than vulns.
const LOWER_SEVERITY = new Set<string>([
  // (placeholder — currently every SCS rule is `high`. Maintain a
  // short list if SCS adds advisory-grade rules later.)
]);

const LINE_RE =
  /^(.+?)\((\d+),(\d+)\):\s*(warning|error)\s+(SCS\d{4}):\s*(.+?)(?:\s*\[(.+)\])?$/;

export const securityCodeScanParser: ScannerParser = {
  name: SCS_TOOL_NAME,
  parse(input: unknown, ctx: ParserContext = {}): ParserOutput {
    const text = typeof input === 'string' ? input : String(input ?? '');
    const findings: Finding[] = [];

    for (const lineRaw of text.split(/\r?\n/)) {
      const line = lineRaw.trim();
      if (line.length === 0) continue;
      const m = LINE_RE.exec(line);
      if (!m) continue;

      const file = m[1]!;
      const lineNo = Number(m[2]!);
      const ruleId = m[5]!;
      const message = m[6]!.trim();
      const type = m[4]!.toLowerCase(); // 'warning' | 'error'
      const severity: Severity =
        type === 'error' ? 'critical' : LOWER_SEVERITY.has(ruleId) ? 'medium' : 'high';
      const category: Category = 'security';

      const fpInput: Parameters<typeof makeFinding>[0] = {
        tool: SCS_TOOL_NAME,
        rule_id: ruleId,
        severity,
        category,
        subcategory: subcategoryFor(ruleId),
        title: message,
        message,
        file_path: toRelativeIfPossible(file, ctx.project_path),
        line_start: lineNo,
        line_end: lineNo,
        fix_available: false,
      };
      findings.push(makeFinding(fpInput));
    }

    return { findings, cves: [] };
  },
};

function subcategoryFor(ruleId: string): string {
  // SCS0001-SCS0007  → SQL / XSS / open redirect / weak crypto
  // SCS0008-SCS0014  → cookie / certificate validation
  // SCS0015-SCS0020+ → various
  // We map a small set; the rest fall through to a generic label.
  const sql = new Set(['SCS0001', 'SCS0002', 'SCS0014', 'SCS0020', 'SCS0026', 'SCS0035']);
  const xss = new Set(['SCS0029']);
  const crypto = new Set(['SCS0006', 'SCS0010', 'SCS0011', 'SCS0013']);
  const cookie = new Set(['SCS0008', 'SCS0009']);
  const xxe = new Set(['SCS0007']);
  const path = new Set(['SCS0018']);
  const open_redirect = new Set(['SCS0027']);
  const ldap = new Set(['SCS0031']);
  if (sql.has(ruleId)) return 'sql-injection';
  if (xss.has(ruleId)) return 'xss';
  if (crypto.has(ruleId)) return 'weak-crypto';
  if (cookie.has(ruleId)) return 'cookie-misconfig';
  if (xxe.has(ruleId)) return 'xxe';
  if (path.has(ruleId)) return 'path-traversal';
  if (open_redirect.has(ruleId)) return 'open-redirect';
  if (ldap.has(ruleId)) return 'ldap-injection';
  return 'dotnet-security';
}
