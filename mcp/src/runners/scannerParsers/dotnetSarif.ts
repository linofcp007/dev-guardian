/**
 * Roslyn SARIF 2.1 (`dotnet build -p:ErrorLog=<file>%2Cversion=2.1`) → the
 * SECURITY findings of a .NET build: the SDK's own analyzers enabled by
 * `-p:AnalysisModeSecurity=All` (CA2100, CA23xx, CA3xxx, CA5xxx — the rules
 * whose SARIF metadata says `category: Security`) and, when the project
 * references it, Security Code Scan (`SCS####`).
 *
 * Replaces scraping `dotnet build --verbosity:diag` stdout, which exceeded
 * the 5 MB output cap on real projects and killed the run. The SARIF is the
 * compiler's own structured record of every diagnostic it reported; it is
 * read per project (a relative ErrorLog path lands in each project's
 * directory — MSBuild does not expand `$(…)` in a global property, measured
 * on SDK 10.0.401).
 *
 * Everything that is not security — CS compiler warnings, CA performance or
 * style rules the project already reports — is left out: `scan_sast` is a
 * security scan, and `quality_check` owns the rest.
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
import { SCS_TOOL_NAME } from './securityCodeScan.js';

/** Findings from the .NET SDK's built-in analyzers (`CA####`). */
export const DOTNET_ANALYZERS_TOOL_NAME = 'dotnet-analyzers';

/** Security-category rule ids, for a SARIF whose rule metadata is missing. */
const SECURITY_RULE_ID = /^(CA2100|CA23\d\d|CA3\d{3}|CA5\d{3})$/;

export const dotnetSarifParser: ScannerParser = {
  name: DOTNET_ANALYZERS_TOOL_NAME,
  parse(input: unknown, ctx: ParserContext = {}): ParserOutput {
    const root = parseInputAsJson(stripBom(input));
    const findings: Finding[] = [];
    for (const run of asArray(getProp(root, 'runs'))) {
      const categories = ruleCategories(run);
      for (const result of asArray(getProp(run, 'results'))) {
        const finding = mapResult(result, categories, ctx);
        if (finding) findings.push(finding);
      }
    }
    return { findings, cves: [] };
  },
};

function stripBom(input: unknown): unknown {
  return typeof input === 'string' && input.charCodeAt(0) === 0xfeff ? input.slice(1) : input;
}

/** rule id → `properties.category`, from `tool.driver.rules[]`. */
function ruleCategories(run: unknown): Map<string, string> {
  const out = new Map<string, string>();
  for (const rule of asArray(getProp(getProp(getProp(run, 'tool'), 'driver'), 'rules'))) {
    const id = getString(rule, 'id');
    const category = getString(getProp(rule, 'properties'), 'category');
    if (id !== undefined && category !== undefined) out.set(id, category);
  }
  return out;
}

function mapResult(result: unknown, categories: Map<string, string>, ctx: ParserContext): Finding | null {
  const ruleId = getString(result, 'ruleId');
  if (ruleId === undefined) return null;
  const isScs = /^SCS\d{4}$/.test(ruleId);
  const category = categories.get(ruleId);
  const isSecurity = isScs || (category !== undefined ? category.toLowerCase() === 'security' : SECURITY_RULE_ID.test(ruleId));
  if (!isSecurity) return null;
  // A diagnostic the project suppressed (`#pragma`, `[SuppressMessage]`) is
  // still written to the SARIF, with `suppressions`; it is not a finding.
  if (asArray(getProp(result, 'suppressions')).length > 0) return null;

  const message = getString(getProp(result, 'message'), 'text') ?? ruleId;
  const physical = getProp(asArray(getProp(result, 'locations'))[0], 'physicalLocation');
  const uri = getString(getProp(physical, 'artifactLocation'), 'uri');
  const region = getProp(physical, 'region');
  const lineStart = getNumber(region, 'startLine');
  const lineEnd = getNumber(region, 'endLine') ?? lineStart;

  const input: Parameters<typeof makeFinding>[0] = {
    tool: isScs ? SCS_TOOL_NAME : DOTNET_ANALYZERS_TOOL_NAME,
    rule_id: ruleId,
    severity: severityOf(getString(result, 'level')),
    category: 'security',
    subcategory: 'dotnet-security',
    title: message.length > 140 ? `${message.slice(0, 137)}…` : message,
    message,
    fix_available: false,
  };
  const file = uri === undefined ? undefined : filePathOf(uri);
  if (file !== undefined) input.file_path = toRelativeIfPossible(file, ctx.project_path);
  if (lineStart !== undefined) input.line_start = lineStart;
  if (lineEnd !== undefined) input.line_end = lineEnd;
  return makeFinding(input);
}

/** Same scale as the SCS log parser: an error is critical, a warning high. */
function severityOf(level: string | undefined): Severity {
  switch (level) {
    case 'error':
      return 'critical';
    case 'warning':
      return 'high';
    case 'note':
      return 'medium';
    default:
      return 'low';
  }
}

function filePathOf(uri: string): string {
  if (!uri.startsWith('file:')) return uri;
  try {
    return fileURLToPath(uri);
  } catch {
    return uri;
  }
}
