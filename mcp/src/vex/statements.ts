/**
 * One VEX statement per vulnerability of a dependency scan, in one package
 * version — which vulnerability, which status, and why. Pure: the caller
 * reads storage, the SBOM file and the surface snapshot.
 *
 * WHICH FINDINGS A STATEMENT IS ABOUT (review of the 3.0 additions, C1/M3).
 * A statement is built from the scan's CVE rows (`scan_cves`) and its
 * vulnerability findings, tied together by OWN ids only — a finding's rule
 * id and the aliases its scanner recorded (`intel/vulnIds.ts`), never an id
 * its description mentions.
 *
 * Statements are named, then filled — MEMBERSHIP, NOT MERGING:
 *
 *   - Each CVE row names one: its id, package and version. Two rows of
 *     different ids are never one statement (final review, M-a: OSV's alias
 *     set for GHSA-35jh-r3h4-6jhm holds CVE-2026-4800 as well as
 *     CVE-2021-23337, and "any shared id" made two lodash vulnerabilities
 *     one statement; pip-audit's PYSEC-2020-96 carries CVE-2025-50460, the
 *     ms-swift RCE).
 *   - A finding that is a copy in none of those — a PYSEC- or GHSA-only
 *     advisory — names one of its own: its first CVE alias, else its own id.
 *   - Then a row or finding is a COPY in every statement one of its own ids
 *     names, in its package, at its version (a range — npm audit's — at any
 *     version). One finding may be a copy in several: pip-audit's
 *     PYSEC-2026-1794 is both CVE-2023-4863 and CVE-2023-5129 of pillow,
 *     which Trivy reports apart, and an npm audit v1 advisory is every CVE
 *     it lists. It used to join only the first, so suppressing Trivy's
 *     CVE-2023-5129 alone published it `not_affected` while pip-audit's copy
 *     of it stayed open (final review, membership ruling). `suppress_finding`
 *     names the other copies with the same rule (`isVexCopyIn`).
 *
 * A statement never lists as an alias an id that names another statement of
 * the document.
 *
 * The status rules, and the only ones:
 *
 *   - `not_affected` ONLY from a VEX suppression — `suppress_finding` with
 *     `vex_status: not_affected` and its justification — active, of this
 *     project, on EVERY copy in the statement, all with one justification. It
 *     is the author's own statement, so it wins over reachability. The
 *     copies' distinct impact statements are all said, joined and bounded
 *     (final review, M-c). A copy with none is named in the notes (M-d). A
 *     plain suppression is a "false positive" note with no VEX justification
 *     and is never read as `not_affected`.
 *   - `affected` when the dependency provider says the package is
 *     `reachable` — a file an HTTP route reaches imports it and loads this
 *     version — on a surface snapshot of the tree the dependency scan
 *     measured: the one positive evidence dev-guardian has that the product
 *     loads the vulnerable code on an exposed path. A snapshot of another
 *     tree (`staleSurface`) gives `under_investigation`, with the reach it
 *     showed and why it is not stated (final review, M-h). A `confirmed`
 *     verdict would be the other way to `affected`; no provider of this
 *     version gives one.
 *   - `under_investigation` for everything else, with the reason in
 *     `status_notes`.
 *   - `fixed` never. A vulnerability in the newest scan is present by
 *     definition, and a fix no scan measured is a guess.
 *
 * NEVER TWO STATUSES FOR ONE SUBCOMPONENT (review, I2). A statement names the
 * vulnerable package version by purl — the SBOM's, else one built from the
 * ecosystem, name and version (`sbom.ts#buildPurl`). Where no purl can be
 * built (an image target names no ecosystem), the statements of one
 * vulnerability in one package would all be about the same subcomponent:
 * they are merged into one, with the most cautious status (affected, then
 * under_investigation, then not_affected) and every version named in its
 * notes. Two packages are never merged (final review, M-e: `org.x:a` and
 * `org.x:b` sharing a GHSA were one statement).
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
  /**
   * Why that snapshot is not of the tree the dependency scan measured, or
   * null/absent when it is: then no reach it shows is stated `affected`.
   */
  staleSurface?: string | null;
  sbom: SbomInventory | null;
}

export function buildVexStatements(inputs: VexInputs): VexStatement[] {
  const active = inputs.suppressions.filter(
    (s) =>
      (s.expires_at === undefined || Date.parse(s.expires_at) > inputs.now) &&
      (s.project_path === undefined || s.project_path === inputs.projectPath),
  );
  const members = membersOf(inputs.cves, inputs.findings);
  const groups = groupMembers(members);
  const names = new Set(groups.map((g) => vulnIdKey(g.name)));
  const drafts = groups.map((group) => statementFor(group, names, inputs, active));
  const statements = mergeSameSubcomponent(drafts);
  // An id that names a statement of this document is that statement, never
  // an alias of another one (final review, M-a).
  const stated = new Set(statements.map((s) => vulnIdKey(s.vulnerability)));
  return statements.map((s) => ({ ...s, aliases: s.aliases.filter((a) => !stated.has(vulnIdKey(a))) }));
}

/* ---------------------------------------------------------------------- *
 * Rows and findings, grouped by own id, package and version
 * ---------------------------------------------------------------------- */

interface Member {
  ids: string[];
  keys: ReadonlySet<string>;
  /** The id its rule id is (a row's CVE), or null when the rule id is none (npm audit v1's number). */
  ruleId: string | null;
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
    ruleId: row.cve_id,
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
    ruleId: findingVulnIds({ ...finding, vuln_aliases: [] })[0] ?? null,
    pkg: coordinates.name.toLowerCase(),
    name: coordinates.name,
    version: subject.version,
    finding,
  };
}

/** Which statement: the id it is named by, its package (case-folded) and exact version (null: a range). */
export interface StatementKey {
  name: string;
  pkg: string;
  version: string | null;
}

/**
 * THE membership rule, shared with `suppress_finding` (`isVexCopyIn`): a row
 * or finding is a copy in a statement when one of its own ids names it, in
 * the same package, at the same version — or either has none (a range).
 */
function isMemberOf(member: Member, key: StatementKey): boolean {
  return (
    member.pkg === key.pkg &&
    (member.version === null || key.version === null || member.version === key.version) &&
    member.keys.has(vulnIdKey(key.name))
  );
}

/** Whether `finding` is a copy in the statement `key` — the rule `buildVexStatements` applies. */
export function isVexCopyIn(finding: Finding, key: StatementKey): boolean {
  const member = memberOfFinding(finding);
  return member !== null && isMemberOf(member, key);
}

/** The statements a dependency scan's rows and findings make, in document order (before any merge). */
export function vexStatementKeys(scan: { cves: readonly Cve[]; findings: readonly Finding[] }): StatementKey[] {
  return statementKeysOf(membersOf(scan.cves, scan.findings));
}

function membersOf(cves: readonly Cve[], findings: readonly Finding[]): Member[] {
  return [
    ...cves.map(memberOfRow),
    ...findings.flatMap((f) => {
      const member = memberOfFinding(f);
      return member === null ? [] : [member];
    }),
  ];
}

interface Group extends StatementKey {
  members: Member[];
}

/**
 * Which statements there are — see the header. Rows name them first; then
 * each finding a copy in none so far, fewest own ids first (so a GHSA-only
 * advisory names the statement the finding that also lists its CVE joins,
 * rather than each naming one of its own), exact versions before ranges.
 */
function statementKeysOf(members: readonly Member[]): StatementKey[] {
  const keys: Array<StatementKey & { first: number }> = [];
  const add = (member: Member, index: number): void => {
    if (keys.some((k) => isMemberOf(member, k))) return;
    const name = member.row?.cve_id ?? member.ids.find(isCveId) ?? member.ids[0] ?? '';
    keys.push({ name, pkg: member.pkg, version: member.version, first: index });
  };
  const indexed = members.map((member, index) => ({ member, index }));
  const inOrder = (rows: boolean, exact: boolean) =>
    indexed
      .filter(({ member }) => (member.row !== undefined) === rows && (member.version !== null) === exact)
      .sort((a, b) => a.member.ids.length - b.member.ids.length || a.index - b.index);
  for (const [rows, exact] of [[true, true], [false, true], [true, false], [false, false]] as const) {
    for (const { member, index } of inOrder(rows, exact)) add(member, index);
  }
  return keys.sort((a, b) => a.first - b.first).map(({ name, pkg, version }) => ({ name, pkg, version }));
}

/** Each statement with every row and finding that is a copy in it — one finding may be a copy in several. */
function groupMembers(members: readonly Member[]): Group[] {
  return statementKeysOf(members).map((key) => ({ ...key, members: members.filter((m) => isMemberOf(m, key)) }));
}

/* ---------------------------------------------------------------------- *
 * One group → one statement
 * ---------------------------------------------------------------------- */

function statementFor(
  group: Group,
  names: ReadonlySet<string>,
  inputs: VexInputs,
  active: readonly Suppression[],
): VexStatement {
  const rows = group.members.flatMap((m) => (m.row === undefined ? [] : [m.row]));
  const findings = uniqueFindings(group.members.flatMap((m) => (m.finding === undefined ? [] : [m.finding])));
  const version = group.version;
  const name = rows[0]?.package_name ?? group.members[0]?.name ?? '';
  const { vulnerability, aliases } = namesOf(group, names);
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
    const impact = joinImpacts(vex.map((s) => s?.vex_impact_statement));
    return {
      ...base,
      status: 'not_affected',
      justification: first.vex_justification,
      ...(impact !== null ? { impact_statement: impact } : {}),
      status_notes: `${label}: stated not_affected (${first.vex_justification}) with suppress_finding in dev-guardian.`,
    };
  }
  const lacking = findings.filter((_, i) => vex[i] === undefined);
  const suppressedNote =
    findings.some((f) => active.some((s) => matches(s, f)))
      ? lacking.length === 0
        ? ' Its findings are stated not_affected for different reasons, so no single justification can be published.'
        : ' The finding is suppressed in dev-guardian without a VEX justification on every copy ' +
          `(${nameCopies(lacking)} ${lacking.length === 1 ? 'has' : 'have'} none), so it is not exported as not_affected.`
      : '';

  const assessment = assess(subjects, { package_name: name, ecosystem, version, manifest: null }, inputs.dependency);
  const stale = inputs.staleSurface ?? null;
  if (assessment?.verdict === 'reachable' && stale !== null) {
    return {
      ...base,
      status: 'under_investigation',
      status_notes:
        `${label}: reachable per ${assessment.evidence[0]?.detail ?? 'a file an HTTP route reaches'} — but ` +
        `${stale}, so it is not stated affected (run map_attack_surface).${suppressedNote}`,
    };
  }
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

/**
 * The group's name, and every other own id of its members once — except
 * the ids of a copy whose rule id names ANOTHER statement: that finding is
 * about that one first, and its aliases are said there. Trivy's
 * CVE-2021-23337 carries GHSA-35jh-r3h4-6jhm and, from OSV's alias set,
 * CVE-2026-4800: it is a copy in CVE-2026-4800 (its suppression counts
 * there), but GHSA-35jh is CVE-2021-23337's alias, not CVE-2026-4800's. A
 * copy whose rule id names no statement (pip-audit's PYSEC id, npm audit
 * v1's number) gives its ids to every statement it is a copy in.
 */
function namesOf(group: Group, names: ReadonlySet<string>): { vulnerability: string; aliases: string[] } {
  const aliases: string[] = [];
  const seen = new Set<string>([vulnIdKey(group.name)]);
  for (const member of group.members) {
    const rule = member.ruleId;
    if (rule !== null && names.has(vulnIdKey(rule)) && vulnIdKey(rule) !== vulnIdKey(group.name)) continue;
    for (const id of member.ids) {
      if (seen.has(vulnIdKey(id))) continue;
      seen.add(vulnIdKey(id));
      aliases.push(id);
    }
  }
  return { vulnerability: group.name, aliases };
}

/** At most this many distinct impact statements are joined into one. */
const MAX_IMPACTS = 3;

/** The copies' distinct impact statements, joined; null when none has one. */
function joinImpacts(values: ReadonlyArray<string | undefined>): string | null {
  const distinct = [...new Set(values.flatMap((v) => (v === undefined || v.trim() === '' ? [] : [v.trim()])))];
  if (distinct.length === 0) return null;
  const shown = distinct.slice(0, MAX_IMPACTS).join('; ');
  const more = distinct.length - MAX_IMPACTS;
  return more > 0 ? `${shown}; and ${more} more on other copies of the finding` : shown;
}

/** At most this many copies are named in a note. */
const MAX_NAMED_COPIES = 5;

/** The copies, by file and fingerprint, for a note. */
function nameCopies(findings: readonly Finding[]): string {
  const named = findings
    .slice(0, MAX_NAMED_COPIES)
    .map((f) => `${f.file_path ?? '(no file)'} [${f.fingerprint.slice(0, 12)}]`)
    .join(', ');
  const more = findings.length - MAX_NAMED_COPIES;
  return more > 0 ? `${named} and ${more} more` : named;
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
    // With no purl, the package name keeps two packages apart (M-e).
    const subcomponent =
      draft.subcomponent_purls.length > 0
        ? [...draft.subcomponent_purls].sort().join(',')
        : `no-purl:${draft.package_name.toLowerCase()}`;
    const key = `${vulnIdKey(draft.vulnerability)}|${subcomponent}`;
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
  const impact = agreed === null ? null : joinImpacts(same.map((s) => s.impact_statement));
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
    ...(impact !== null ? { impact_statement: impact } : {}),
    ...(affected?.action_statement !== undefined ? { action_statement: affected.action_statement } : {}),
    status_notes: notes,
    subcomponent_purls: first.subcomponent_purls,
  };
}
