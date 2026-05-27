/**
 * Trivy JSON output parser.
 *
 * One parser handles three Trivy modes (the JSON layouts overlap):
 *   - `trivy fs --scanners vuln,license` → Results[].Vulnerabilities[],
 *                                         Results[].Licenses[]
 *   - `trivy config Dockerfile`          → Results[].Misconfigurations[]
 *   - `trivy config <iac>`               → Results[].Misconfigurations[]
 *
 * Vulnerabilities additionally feed the `cves` table so the
 * `guardian://cves/active` resource can serve dedicated CVE queries
 * without re-deriving them from `findings`.
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
  type ParserCveInput,
  type ParserOutput,
  type ScannerParser,
} from './index.js';

export const TRIVY_TOOL_NAME = 'trivy';

export const trivyParser: ScannerParser = {
  name: TRIVY_TOOL_NAME,
  parse(input: unknown, ctx: ParserContext = {}): ParserOutput {
    const root = parseInputAsJson(input);
    const findings: Finding[] = [];
    const cves: ParserCveInput[] = [];

    for (const result of asArray(getProp(root, 'Results'))) {
      const target = getString(result, 'Target') ?? '';

      for (const v of asArray(getProp(result, 'Vulnerabilities'))) {
        const finding = mapVulnerability(v, target, ctx);
        if (finding) findings.push(finding);
        const cve = mapVulnerabilityCve(v);
        if (cve) cves.push(cve);
      }

      for (const l of asArray(getProp(result, 'Licenses'))) {
        const finding = mapLicense(l, target, ctx);
        if (finding) findings.push(finding);
      }

      for (const m of asArray(getProp(result, 'Misconfigurations'))) {
        const finding = mapMisconfiguration(m, target, ctx);
        if (finding) findings.push(finding);
      }

      for (const s of asArray(getProp(result, 'Secrets'))) {
        const finding = mapSecret(s, target, ctx);
        if (finding) findings.push(finding);
      }
    }

    return { findings, cves };
  },
};

function mapVulnerability(raw: unknown, target: string, ctx: ParserContext): Finding | null {
  const cveId = getString(raw, 'VulnerabilityID');
  const pkg = getString(raw, 'PkgName');
  if (!cveId || !pkg) return null;
  const severity = normalizeSeverity(getString(raw, 'Severity'));
  const title = getString(raw, 'Title') ?? `${cveId} in ${pkg}`;
  const installed = getString(raw, 'InstalledVersion');
  const fixed = getString(raw, 'FixedVersion');
  const description = getString(raw, 'Description');

  const input: Parameters<typeof makeFinding>[0] = {
    tool: TRIVY_TOOL_NAME,
    rule_id: cveId,
    severity,
    category: 'security',
    subcategory: 'cve',
    title,
    fix_available: fixed !== undefined && fixed.length > 0,
    file_path: toRelativeIfPossible(target, ctx.project_path),
  };
  if (description !== undefined) input.message = description;
  // Trivy "snippet" surrogate: enough package metadata to make the
  // fingerprint unique per (cve, package, installed_version) tuple.
  input.snippet = `${pkg}@${installed ?? ''}->${fixed ?? ''}`;
  return makeFinding(input);
}

function mapVulnerabilityCve(raw: unknown): ParserCveInput | null {
  const cveId = getString(raw, 'VulnerabilityID');
  const pkg = getString(raw, 'PkgName');
  if (!cveId || !pkg) return null;
  const cve: ParserCveInput = {
    cve_id: cveId,
    package_name: pkg,
    severity: normalizeSeverity(getString(raw, 'Severity')),
  };
  const installed = getString(raw, 'InstalledVersion');
  if (installed !== undefined) cve.installed_version = installed;
  const fixed = getString(raw, 'FixedVersion');
  if (fixed !== undefined) cve.fixed_version = fixed;
  return cve;
}

function mapLicense(raw: unknown, target: string, ctx: ParserContext): Finding | null {
  const pkg = getString(raw, 'PkgName');
  const license = getString(raw, 'Name');
  if (!license) return null;
  const severity = normalizeSeverity(getString(raw, 'Severity'));
  const title = `License '${license}' on ${pkg ?? target}`;

  const input: Parameters<typeof makeFinding>[0] = {
    tool: TRIVY_TOOL_NAME,
    rule_id: `license:${license}`,
    severity,
    category: 'license',
    subcategory: license.toLowerCase(),
    title,
    file_path: toRelativeIfPossible(target, ctx.project_path),
    snippet: pkg ? `pkg:${pkg}` : `license:${license}`,
  };
  return makeFinding(input);
}

function mapMisconfiguration(raw: unknown, target: string, ctx: ParserContext): Finding | null {
  const id = getString(raw, 'ID') ?? getString(raw, 'AVDID');
  if (!id) return null;
  const severity = normalizeSeverity(getString(raw, 'Severity'));
  const title = getString(raw, 'Title') ?? id;
  const message = getString(raw, 'Description');
  const cause = getProp(raw, 'CauseMetadata');
  const lineStart = getNumber(cause, 'StartLine');
  const lineEnd = getNumber(cause, 'EndLine') ?? lineStart;
  const type = getString(raw, 'Type')?.toLowerCase();
  const category: Category = 'security';
  const subcategory = type ?? 'misconfiguration';

  const input: Parameters<typeof makeFinding>[0] = {
    tool: TRIVY_TOOL_NAME,
    rule_id: id,
    severity,
    category,
    subcategory,
    title,
    file_path: toRelativeIfPossible(target, ctx.project_path),
  };
  if (message !== undefined) input.message = message;
  if (lineStart !== undefined) input.line_start = lineStart;
  if (lineEnd !== undefined) input.line_end = lineEnd;
  const fixHint = getString(raw, 'Resolution');
  if (fixHint !== undefined) input.snippet = fixHint;
  return makeFinding(input);
}

function mapSecret(raw: unknown, target: string, ctx: ParserContext): Finding | null {
  const ruleId = getString(raw, 'RuleID') ?? getString(raw, 'Rule');
  if (!ruleId) return null;
  const severity: Severity = normalizeSeverity(getString(raw, 'Severity') ?? 'HIGH');
  const lineStart = getNumber(raw, 'StartLine');
  const lineEnd = getNumber(raw, 'EndLine') ?? lineStart;
  const input: Parameters<typeof makeFinding>[0] = {
    tool: TRIVY_TOOL_NAME,
    rule_id: ruleId,
    severity,
    category: 'security',
    subcategory: 'secret',
    title: getString(raw, 'Title') ?? ruleId,
    file_path: toRelativeIfPossible(target, ctx.project_path),
  };
  if (lineStart !== undefined) input.line_start = lineStart;
  if (lineEnd !== undefined) input.line_end = lineEnd;
  return makeFinding(input);
}
