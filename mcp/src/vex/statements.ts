/**
 * One VEX statement per CVE of a dependency scan — which status, and why.
 * Pure: the caller reads storage, the SBOM file and the surface snapshot.
 *
 * The status rules, and the only ones:
 *
 *   - `not_affected` ONLY from a VEX suppression — `suppress_finding` with
 *     `vex_status: not_affected` and its justification — active, of this
 *     project, on every finding of the scan that reports the CVE for that
 *     package. It is the author's own statement, so it wins over
 *     reachability. A plain suppression is a "false positive" note with no
 *     VEX justification and is never read as `not_affected`.
 *   - `affected` when the dependency provider says the package is
 *     `reachable` (a file an HTTP route reaches imports it) — the one
 *     positive evidence dev-guardian has that the product loads the
 *     vulnerable code on an exposed path. (`confirmed` would count too; no
 *     provider produces it yet.)
 *   - `under_investigation` for everything else, with the reason in
 *     `status_notes`: imported only by unrouted files, no import found, no
 *     surface snapshot, an ecosystem the provider cannot match.
 *   - `fixed` never. A CVE in the newest scan is present by definition, and
 *     a fix no scan measured is a guess.
 */

import { dependencyCoordinates } from '../fingerprint/findingIdentity.js';
import { findingCveIds } from '../intel/rank.js';
import type { Cve, Finding, OpenVexJustification, Severity, Suppression } from '../types.js';
import {
  assessDependency,
  dependencySubjectOf,
  type DependencyAssessment,
  type DependencyIndex,
} from '../validate/dependencyProvider.js';
import { purlType, purlsFor, type SbomInventory } from './sbom.js';

export type VexStatus = 'not_affected' | 'affected' | 'under_investigation';

export interface VexStatement {
  /** The vulnerability id as the scan recorded it: a CVE, or a GHSA/PYSEC id. */
  vulnerability: string;
  package_name: string;
  installed_version: string | null;
  fixed_version: string | null;
  severity: Severity;
  status: VexStatus;
  /** With `not_affected`. */
  justification?: OpenVexJustification;
  impact_statement?: string;
  /** With `affected`: what to do about it. */
  action_statement?: string;
  /** How the status was decided, in one or two sentences. */
  status_notes: string;
  /** The vulnerable package's purl(s) from the SBOM; empty without one. */
  subcomponent_purls: string[];
}

export interface VexInputs {
  /** The dependency scan's CVE rows (`scan_cves`). */
  cves: readonly Cve[];
  /** The same scan's findings, suppressed ones included. */
  findings: readonly Finding[];
  /** Every suppression; the active ones of `projectPath` are the ones read. */
  suppressions: readonly Suppression[];
  projectPath: string;
  now: number;
  /** The latest surface snapshot, prepared; null when there is none. */
  dependency: DependencyIndex | null;
  sbom: SbomInventory | null;
}

export function buildVexStatements(inputs: VexInputs): VexStatement[] {
  const active = inputs.suppressions.filter(
    (s) =>
      (s.expires_at === undefined || Date.parse(s.expires_at) > inputs.now) &&
      (s.project_path === undefined || s.project_path === inputs.projectPath),
  );
  return inputs.cves.map((cve) => statementFor(cve, inputs, active));
}

function statementFor(cve: Cve, inputs: VexInputs, active: readonly Suppression[]): VexStatement {
  const installed = cve.installed_version ?? null;
  const findings = findingsOf(cve, inputs.findings);
  const subject = findings.map(dependencySubjectOf).find((s) => s !== null && s.ecosystem !== null) ?? null;
  const ecosystem = subject?.ecosystem ?? sbomEcosystem(inputs.sbom, cve.package_name, installed);
  const base = {
    vulnerability: cve.cve_id,
    package_name: cve.package_name,
    installed_version: installed,
    fixed_version: cve.fixed_version ?? null,
    severity: cve.severity,
    subcomponent_purls:
      inputs.sbom === null ? [] : purlsFor(inputs.sbom, cve.package_name, installed, ecosystem).purls,
  };
  const label = `${cve.package_name}${installed === null ? '' : `@${installed}`}`;

  const suppressions = findings.map((f) => active.find((s) => matches(s, f)));
  const vex = suppressions.map((s) => (s?.vex_status === 'not_affected' ? s : undefined));
  const first = vex[0];
  if (first !== undefined && vex.every((s) => s !== undefined) && first.vex_justification !== undefined) {
    return {
      ...base,
      status: 'not_affected',
      justification: first.vex_justification,
      ...(first.vex_impact_statement !== undefined ? { impact_statement: first.vex_impact_statement } : {}),
      status_notes: `${label}: stated not_affected (${first.vex_justification}) with suppress_finding in dev-guardian.`,
    };
  }

  const suppressedNote = suppressions.some((s) => s !== undefined)
    ? ` The finding is suppressed in dev-guardian without a VEX justification on every copy, so it is not exported as not_affected.`
    : '';

  const assessment: DependencyAssessment | null =
    inputs.dependency === null
      ? null
      : assessDependency(
          subject ?? { package_name: cve.package_name, ecosystem },
          inputs.dependency,
        );

  if (assessment?.verdict === 'reachable') {
    return {
      ...base,
      status: 'affected',
      action_statement:
        cve.fixed_version !== undefined
          ? `Upgrade ${cve.package_name}${installed === null ? '' : ` from ${installed}`} to ` +
            `${cve.fixed_version} or later.`
          : `No fixed version of ${cve.package_name} is recorded by the dependency scan; follow the ` +
            'advisory for a mitigation, or remove the dependency.',
      status_notes:
        `${label}: ${assessment.evidence[0]?.detail ?? 'imported by a file an HTTP route reaches'} ` +
        '(file-level reachability, not proof the vulnerable function runs).' +
        suppressedNote,
    };
  }

  return {
    ...base,
    status: 'under_investigation',
    status_notes: `${label}: not known to affect the product — ${whyNot(assessment)}.${suppressedNote}`,
  };
}

function whyNot(assessment: DependencyAssessment | null): string {
  if (assessment === null) {
    return 'no attack-surface snapshot, so whether the package is imported was not checked (run map_attack_surface)';
  }
  if (assessment.verdict === 'imported') {
    return (
      `imported by ${assessment.importing_files.slice(0, 5).join(', ')}, which no known HTTP route ` +
      'reaches through the import graph'
    );
  }
  return assessment.coverage_gaps[0] ?? 'nothing showed the package in use';
}

/**
 * The scan's findings about this CVE in this package: same vulnerability id,
 * same package name, and — when any of them names it — the same installed
 * version (a scan can hold two versions of one package).
 */
function findingsOf(cve: Cve, findings: readonly Finding[]): Finding[] {
  const id = cve.cve_id.toUpperCase();
  const name = cve.package_name.toLowerCase();
  const sameCve = findings.filter((f) => {
    const coordinates = dependencyCoordinates(f);
    if (coordinates === null || coordinates.name.toLowerCase() !== name) return false;
    return findingCveIds(f).includes(id) || f.rule_id?.toUpperCase() === id;
  });
  const sameVersion = sameCve.filter((f) => dependencyCoordinates(f)?.version === cve.installed_version);
  return sameVersion.length > 0 ? sameVersion : sameCve;
}

/** The same fingerprint-or-identity rule every open-set reader applies. */
function matches(s: Suppression, f: Finding): boolean {
  return s.finding_fingerprint === f.fingerprint || (f.identity !== undefined && s.finding_identity === f.identity);
}

/** The ecosystem the SBOM gives the package, when it gives exactly one. */
function sbomEcosystem(sbom: SbomInventory | null, name: string, version: string | null): string | null {
  if (sbom === null) return null;
  const { purls, ambiguous } = purlsFor(sbom, name, version, null);
  const first = purls[0];
  return ambiguous || first === undefined ? null : purlType(first);
}
