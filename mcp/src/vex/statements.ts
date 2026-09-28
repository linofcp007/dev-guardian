/**
 * One VEX statement per vulnerability of a dependency scan, in one package
 * version — which vulnerability, which status, and why. Pure: the caller
 * reads storage, the SBOM file and the surface snapshot.
 *
 * WHICH FINDINGS A STATEMENT IS ABOUT (review of the 3.0 additions, C1/M3).
 * A statement is built from the scan's CVE rows (`scan_cves`) and its
 * vulnerability findings, tied together by OWN ids only — a finding's rule
 * id and the aliases its scanner recorded (`intel/vulnIds.ts`), never an id
 * its description mentions. Two rows/findings are the same vulnerability in
 * the same package version when they share an own id, name the same package
 * and agree on the version; a finding with no exact version (npm audit's
 * vulnerable range) joins every version group it shares an id with. A
 * finding no row names — a PYSEC- or GHSA-only advisory — is a statement of
 * its own, under its own id. The statement is named by a CVE when the group
 * has one, else by its first own id, and lists every other id as an alias.
 *
 * The status rules, and the only ones:
 *
 *   - `not_affected` ONLY from a VEX suppression — `suppress_finding` with
 *     `vex_status: not_affected` and its justification — active, of this
 *     project, on EVERY finding of the group, all with one justification. It
 *     is the author's own statement, so it wins over reachability. A plain
 *     suppression is a "false positive" note with no VEX justification and
 *     is never read as `not_affected`.
 *   - `affected` when the dependency provider says the package is
 *     `reachable` — a file an HTTP route reaches imports it and loads this
 *     version — the one positive evidence dev-guardian has that the product
 *     loads the vulnerable code on an exposed path.
 *   - `under_investigation` for everything else, with the reason in
 *     `status_notes`.
 *   - `fixed` never. A vulnerability in the newest scan is present by
 *     definition, and a fix no scan measured is a guess.
 *
 * NEVER TWO STATUSES FOR ONE SUBCOMPONENT (review, I2). A statement names the
 * vulnerable package version by purl — the SBOM's, else one built from the
 * ecosystem, name and version (`sbom.ts#buildPurl`). Where no purl can be
 * built (an image target names no ecosystem), the statements of one
 * vulnerability would all be about the same (vulnerability, product): they
 * are merged into one, with the most cautious status (affected, then
 * under_investigation, then not_affected) and every version named in its
 * notes.
 */

import { dependencyCoordinates } from '../fingerprint/findingIdentity.js';
import { findingVulnIds, isCveId, vulnIdKey } from '../intel/vulnIds.js';
import { SEVERITY_ORDER, type Cve, type Finding, type OpenVexJustification, type Severity, type Suppression } from '../types.js';
import {
  assessDependency,
  dependencySubjectOf,
  type DependencyAssessment,
  type DependencyIndex,
  type DependencySubject,
} from '../validate/dependencyProvider.js';
import { buildPurl, purlType, purlsFor, type SbomInventory } from './sbom.js';

export type VexStatus = 'not_affected' | 'affected' | 'under_investigation';

export interface VexStatement {
  /** The vulnerability's id: a CVE when the group has one, else its first own id (GHSA, PYSEC, …). */
  vulnerability: string;
  /** Every other id of the same vulnerability, as the scanners gave them. */
  aliases: string[];
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
  /** The vulnerable package version's purl(s); empty when none could be told. */
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
  const members = [
    ...inputs.cves.map(memberOfRow),
    ...inputs.findings.flatMap((f) => {
      const member = memberOfFinding(f);
      return member === null ? [] : [member];
    }),
  ];
  const drafts = groupMembers(members).map((group) => statementFor(group, inputs, active));
  return mergeSameSubcomponent(drafts);
}

/* ---------------------------------------------------------------------- *
 * Rows and findings, grouped by own id, package and version
 * ---------------------------------------------------------------------- */

interface Member {
  ids: string[];
  keys: ReadonlySet<string>;
  /** Grouping key: the package name, case-folded. */
  pkg: string;
  name: string;
  /** Exact installed version, or null (a range, or none recorded). */
  version: string | null;
  row?: Cve;
  finding?: Finding;
}

function memberOfRow(row: Cve): Member {
  return {
    ids: [row.cve_id],
    keys: new Set([vulnIdKey(row.cve_id)]),
    pkg: row.package_name.toLowerCase(),
    name: row.package_name,
    version: row.installed_version ?? null,
    row,
  };
}

function memberOfFinding(finding: Finding): Member | null {
  const coordinates = dependencyCoordinates(finding);
  const subject = dependencySubjectOf(finding);
  const ids = findingVulnIds(finding);
  if (coordinates === null || subject === null || ids.length === 0) return null;
  return {
    ids,
    keys: new Set(ids.map(vulnIdKey)),
    pkg: coordinates.name.toLowerCase(),
    name: coordinates.name,
    version: subject.version,
    finding,
  };
}

interface Group {
  members: Member[];
  /** Index of the first member, for a stable order (the rows' order first). */
  first: number;
}

function groupMembers(members: readonly Member[]): Group[] {
  // Phase 1: same package, same version (or both none), a shared own id.
  const parent = members.map((_, i) => i);
  const find = (i: number): number => {
    let root = i;
    while (parent[root] !== root) root = parent[root] ?? root;
    return root;
  };
  for (let i = 0; i < members.length; i += 1) {
    for (let j = i + 1; j < members.length; j += 1) {
      const a = members[i];
      const b = members[j];
      if (a === undefined || b === undefined) continue;
      if (a.pkg === b.pkg && a.version === b.version && intersects(a.keys, b.keys)) {
        parent[find(j)] = find(i);
      }
    }
  }
  const byRoot = new Map<number, Group>();
  members.forEach((member, index) => {
    const root = find(index);
    const group = byRoot.get(root) ?? { members: [], first: index };
    group.members.push(member);
    byRoot.set(root, group);
  });

  // Phase 2: a group with no version (a range) joins every version group of
  // its package it shares an id with, rather than standing apart from them.
  const groups = [...byRoot.values()];
  const exact = groups.filter((g) => g.members[0]?.version !== null);
  const out = [...exact];
  for (const loose of groups.filter((g) => g.members[0]?.version === null)) {
    const pkg = loose.members[0]?.pkg;
    const keys = new Set(loose.members.flatMap((m) => [...m.keys]));
    const targets = exact.filter((g) => g.members[0]?.pkg === pkg && g.members.some((m) => intersects(m.keys, keys)));
    if (targets.length === 0) out.push(loose);
    for (const target of targets) target.members.push(...loose.members);
  }
  return out.sort((a, b) => a.first - b.first);
}

function intersects(a: ReadonlySet<string>, b: ReadonlySet<string>): boolean {
  for (const key of a) if (b.has(key)) return true;
  return false;
}

/* ---------------------------------------------------------------------- *
 * One group → one statement
 * ---------------------------------------------------------------------- */

function statementFor(group: Group, inputs: VexInputs, active: readonly Suppression[]): VexStatement {
  const rows = group.members.flatMap((m) => (m.row === undefined ? [] : [m.row]));
  const findings = uniqueFindings(group.members.flatMap((m) => (m.finding === undefined ? [] : [m.finding])));
  const version = group.members.find((m) => m.version !== null)?.version ?? null;
  const name = rows[0]?.package_name ?? group.members[0]?.name ?? '';
  const { vulnerability, aliases } = namesOf(group.members);
  const subjects = findings.flatMap((f) => {
    const subject = dependencySubjectOf(f);
    return subject === null ? [] : [{ ...subject, version: subject.version ?? version }];
  });
  const ecosystem =
    subjects.find((s) => s.ecosystem !== null)?.ecosystem ?? sbomEcosystem(inputs.sbom, name, version);
  const sbomPurls = inputs.sbom === null ? [] : purlsFor(inputs.sbom, name, version, ecosystem).purls;
  const built = buildPurl(ecosystem, name, version);
  const base = {
    vulnerability,
    aliases,
    package_name: name,
    installed_version: version,
    fixed_version: rows.find((r) => r.fixed_version !== undefined)?.fixed_version ?? null,
    severity: maxSeverity([...rows.map((r) => r.severity), ...findings.map((f) => f.severity)]),
    subcomponent_purls: sbomPurls.length > 0 ? sbomPurls : built === null ? [] : [built],
  };
  const label = `${name}${version === null ? '' : `@${version}`}`;

  // VEX suppressions: on every copy, with one justification.
  const vex = findings.map((f) => active.find((s) => matches(s, f) && s.vex_status === 'not_affected'));
  const justifications = new Set(vex.map((s) => s?.vex_justification));
  const first = vex[0];
  if (first !== undefined && vex.every((s) => s !== undefined) && justifications.size === 1 && first.vex_justification !== undefined) {
    return {
      ...base,
      status: 'not_affected',
      justification: first.vex_justification,
      ...(first.vex_impact_statement !== undefined ? { impact_statement: first.vex_impact_statement } : {}),
      status_notes: `${label}: stated not_affected (${first.vex_justification}) with suppress_finding in dev-guardian.`,
    };
  }
  const suppressedNote =
    findings.some((f) => active.some((s) => matches(s, f)))
      ? vex.every((s) => s !== undefined)
        ? ' Its findings are stated not_affected for different reasons, so no single justification can be published.'
        : ' The finding is suppressed in dev-guardian without a VEX justification on every copy, so it is not exported as not_affected.'
      : '';

  const assessment = assess(subjects, { package_name: name, ecosystem, version, manifest: null }, inputs.dependency);
  if (assessment?.verdict === 'reachable') {
    return {
      ...base,
      status: 'affected',
      action_statement:
        base.fixed_version !== null
          ? `Upgrade ${name}${version === null ? '' : ` from ${version}`} to ${base.fixed_version} or later.`
          : `No fixed version of ${name} is recorded by the dependency scan; follow the advisory for a ` +
            'mitigation, or remove the dependency.',
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

/** The group's name — a CVE when it has one — and every other own id once. */
function namesOf(members: readonly Member[]): { vulnerability: string; aliases: string[] } {
  const ids: string[] = [];
  const seen = new Set<string>();
  for (const member of members) {
    for (const id of member.ids) {
      if (seen.has(vulnIdKey(id))) continue;
      seen.add(vulnIdKey(id));
      ids.push(id);
    }
  }
  const vulnerability = ids.find(isCveId) ?? ids[0] ?? '';
  return { vulnerability, aliases: ids.filter((id) => vulnIdKey(id) !== vulnIdKey(vulnerability)) };
}

/** The best verdict any copy earns: reachable, then imported, then unknown. */
function assess(
  subjects: readonly DependencySubject[],
  fallback: DependencySubject,
  index: DependencyIndex | null,
): DependencyAssessment | null {
  if (index === null) return null;
  const rank = { reachable: 0, imported: 1, unknown: 2 } as const;
  const assessments = (subjects.length > 0 ? subjects : [fallback]).map((s) => assessDependency(s, index));
  return assessments.sort((a, b) => rank[a.verdict] - rank[b.verdict])[0] ?? null;
}

function whyNot(assessment: DependencyAssessment | null): string {
  if (assessment === null) {
    return 'no attack-surface snapshot, so whether the package is imported was not checked (run map_attack_surface)';
  }
  if (assessment.verdict === 'imported') {
    return (
      `imported by ${assessment.importing_files.slice(0, 5).join(', ')}, which no known HTTP route ` +
      'was shown to reach with this version'
    );
  }
  return assessment.coverage_gaps[0] ?? 'nothing showed the package in use';
}

/** The same fingerprint-or-identity rule every open-set reader applies. */
function matches(s: Suppression, f: Finding): boolean {
  return s.finding_fingerprint === f.fingerprint || (f.identity !== undefined && s.finding_identity === f.identity);
}

function uniqueFindings(findings: readonly Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => (seen.has(f.fingerprint) ? false : (seen.add(f.fingerprint), true)));
}

function maxSeverity(severities: readonly Severity[]): Severity {
  return severities.reduce<Severity>((max, s) => (SEVERITY_ORDER[s] > SEVERITY_ORDER[max] ? s : max), 'info');
}

/** The ecosystem the SBOM gives the package, when it gives exactly one. */
function sbomEcosystem(sbom: SbomInventory | null, name: string, version: string | null): string | null {
  if (sbom === null) return null;
  const { purls, ambiguous } = purlsFor(sbom, name, version, null);
  const first = purls[0];
  return ambiguous || first === undefined ? null : purlType(first);
}

/* ---------------------------------------------------------------------- *
 * One statement per (vulnerability, subcomponent)
 * ---------------------------------------------------------------------- */

const STATUS_CAUTION: Record<VexStatus, number> = { affected: 0, under_investigation: 1, not_affected: 2 };

function mergeSameSubcomponent(drafts: readonly VexStatement[]): VexStatement[] {
  const byKey = new Map<string, VexStatement[]>();
  for (const draft of drafts) {
    const key = `${vulnIdKey(draft.vulnerability)}|${[...draft.subcomponent_purls].sort().join(',')}`;
    byKey.set(key, [...(byKey.get(key) ?? []), draft]);
  }
  return [...byKey.values()].map(mergeOne);
}

function mergeOne(same: readonly VexStatement[]): VexStatement {
  const [first, ...rest] = same;
  if (first === undefined) throw new Error('mergeOne: empty group');
  if (rest.length === 0) return first;
  const status = same.map((s) => s.status).sort((a, b) => STATUS_CAUTION[a] - STATUS_CAUTION[b])[0] ?? 'under_investigation';
  const justifications = new Set(same.map((s) => s.justification));
  const agreed = status === 'not_affected' && justifications.size === 1 ? first : null;
  const one = <T>(values: readonly T[]): T | null => (new Set(values).size === 1 ? (values[0] ?? null) : null);
  const aliases = [...new Map(same.flatMap((s) => s.aliases).map((a) => [vulnIdKey(a), a])).values()]
    .filter((a) => vulnIdKey(a) !== vulnIdKey(first.vulnerability));
  const affected = same.find((s) => s.status === 'affected');
  const notes = [
    `One statement for ${same.length} package versions this document cannot tell apart ` +
      '(no purl could be built), with the most cautious status of them:',
    ...same.map((s) => s.status_notes),
  ].join(' ');
  return {
    vulnerability: first.vulnerability,
    aliases,
    package_name: one(same.map((s) => s.package_name)) ?? first.package_name,
    installed_version: one(same.map((s) => s.installed_version)),
    fixed_version: one(same.map((s) => s.fixed_version)),
    severity: maxSeverity(same.map((s) => s.severity)),
    status: status === 'not_affected' && agreed === null ? 'under_investigation' : status,
    ...(agreed?.justification !== undefined ? { justification: agreed.justification } : {}),
    ...(agreed?.impact_statement !== undefined ? { impact_statement: agreed.impact_statement } : {}),
    ...(affected?.action_statement !== undefined ? { action_statement: affected.action_statement } : {}),
    status_notes: notes,
    subcomponent_purls: first.subcomponent_purls,
  };
}
