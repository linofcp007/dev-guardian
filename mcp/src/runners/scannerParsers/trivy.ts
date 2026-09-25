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

import { readdirSync } from 'node:fs';
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
  //
  // The `->fixed` half is also in the fingerprint, so the fingerprint changes
  // when the advisory database learns of a fix — the project did not change
  // at all. It stays, byte for byte, because suppressions and v1
  // `baseline.json` files from 2.0.x name these findings by that
  // fingerprint. The line-independent identity every cross-scan comparison
  // matches on first reads only `pkg@installed` out of this string
  // (`fingerprint/findingIdentity.ts#dependencyCoordinates`, which also
  // relies on the name ending at the LAST `@` before `->`): keep that shape.
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

// ---------------------------------------------------------------- manifest coverage
//
// Task 10, item 1: a bare `.csproj` (no `packages.lock.json`) is silently
// "not scanned" by Trivy fs — reproduced against Trivy 0.69.3: the JSON
// report omits the `Results` key entirely (identical to an empty project),
// while stderr only ever logs `Number of language-specific files num=0`.
// The caller (scanDeps.ts / depsAudit.ts) used to read that as `ok`, 0
// findings — a clean bill of health for a project that was never scanned.
//
// The same silent gap exists for `package.json` without any npm/yarn/pnpm
// lockfile and for `composer.json` without `composer.lock` — confirmed the
// same way. It does NOT exist for `requirements.txt` (pip) or `go.mod`
// (go): both are scanned by Trivy from the bare manifest alone, no lockfile
// required — also confirmed against 0.69.3 — so they are deliberately
// excluded from this table; flagging them would be a false alarm.

interface EcosystemManifest {
  /** Human label used in `ManifestCoverageGap.ecosystem`. */
  ecosystem: string;
  /** Matches a top-level directory entry name against this ecosystem. */
  matches: (name: string) => boolean;
  /** Trivy `Results[].Type` values that count as this ecosystem being
   *  covered by whatever Trivy actually scanned (its lockfile, not
   *  necessarily the manifest file itself — Trivy reports the LOCKFILE as
   *  `Target`, so matching is done on `Type`, never on `Target`). */
  trivyTypes: readonly string[];
}

const ECOSYSTEM_MANIFESTS: readonly EcosystemManifest[] = [
  { ecosystem: 'npm', matches: (n) => n === 'package.json', trivyTypes: ['npm', 'yarn', 'pnpm', 'bun'] },
  { ecosystem: 'composer', matches: (n) => n === 'composer.json', trivyTypes: ['composer'] },
  {
    ecosystem: 'dotnet',
    matches: (n) => /\.(csproj|sln)$/i.test(n),
    trivyTypes: ['nuget'],
  },
  { ecosystem: 'rubygems', matches: (n) => n === 'Gemfile', trivyTypes: ['bundler'] },
  { ecosystem: 'cargo', matches: (n) => n === 'Cargo.toml', trivyTypes: ['cargo'] },
];

export interface ManifestCoverageGap {
  ecosystem: string;
  /** The manifest file(s) found at the project root for this ecosystem. */
  files: string[];
}

export interface ManifestCoverageAssessment {
  /** Ecosystems with a manifest present that Trivy's own output shows no
   *  Result for. Empty when nothing was missed. */
  gaps: ManifestCoverageGap[];
  /** Whether Trivy's `Results` array had ANY entry at all (any ecosystem,
   *  not just the ones in {@link ECOSYSTEM_MANIFESTS}) — used to tell a
   *  scan that recognised nothing whatsoever (skip the tool run entirely)
   *  from one that covered some ecosystems but missed others (still ok,
   *  reduced coverage). */
  sawAnyResults: boolean;
}

/**
 * Assess whether Trivy's fs-scan output covers every dependency manifest
 * actually present at the project's top level. Only the project ROOT is
 * checked — same shallow scope as `license_compatibility`'s manifest
 * detection — because a manifest buried in a subdirectory (a monorepo
 * package) is Trivy's own concern to find or not; this only detects the
 * specific silent gap described above (manifest present, lockfile absent,
 * `Results` never mentions it).
 */
export function assessManifestCoverage(
  projectPath: string,
  rawTrivyOutput: unknown,
): ManifestCoverageAssessment {
  let entries: string[];
  try {
    entries = readdirSync(projectPath);
  } catch {
    return { gaps: [], sawAnyResults: false };
  }

  const root = parseInputAsJson(rawTrivyOutput);
  const results = asArray(getProp(root, 'Results'));
  const coveredTypes = new Set<string>();
  for (const result of results) {
    const type = getString(result, 'Type');
    if (type) coveredTypes.add(type);
  }

  const gaps: ManifestCoverageGap[] = [];
  for (const eco of ECOSYSTEM_MANIFESTS) {
    const files = entries.filter((n) => eco.matches(n));
    if (files.length === 0) continue;
    const covered = eco.trivyTypes.some((t) => coveredTypes.has(t));
    if (!covered) gaps.push({ ecosystem: eco.ecosystem, files });
  }

  return { gaps, sawAnyResults: results.length > 0 };
}
