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
 * Rows are the anchors, and two rows of different ids are never one
 * statement (final review, M-a: OSV's alias set for GHSA-35jh-r3h4-6jhm holds
 * CVE-2026-4800 as well as CVE-2021-23337, so tying by "any shared id" made
 * two lodash vulnerabilities one statement; pip-audit's PYSEC-2020-96 carries
 * CVE-2025-50460, the ms-swift RCE). A finding joins the row, of its package
 * and version, that its rule id names; failing that, the first of its
 * aliases, in the scanner's order, that a row names; failing that, it is a
 * statement of its own — a PYSEC- or GHSA-only advisory — named by its first
 * CVE alias, else its own rule id, beside every other finding named the same.
 * A finding with no exact version (npm audit's vulnerable range) joins every
 * version of its package under the same name. After that, a statement never
 * lists as an alias an id that names another statement of the document.
 *
 * The status rules, and the only ones:
 *
 *   - `not_affected` ONLY from a VEX suppression — `suppress_finding` with
 *     `vex_status: not_affected` and its justification — active, of this
 *     project, on EVERY finding of the group, all with one justification. It
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
import { SEVERITY_ORDER } from '../types.js';
import { assessDependency, dependencySubjectOf, } from '../validate/dependencyProvider.js';
import { buildPurl, purlType, purlsFor } from './sbom.js';
export function buildVexStatements(inputs) {
    const active = inputs.suppressions.filter((s) => (s.expires_at === undefined || Date.parse(s.expires_at) > inputs.now) &&
        (s.project_path === undefined || s.project_path === inputs.projectPath));
    const members = [
        ...inputs.cves.map(memberOfRow),
        ...inputs.findings.flatMap((f) => {
            const member = memberOfFinding(f);
            return member === null ? [] : [member];
        }),
    ];
    const drafts = groupMembers(members).map((group) => statementFor(group, inputs, active));
    const statements = mergeSameSubcomponent(drafts);
    // An id that names a statement of this document is that statement, never
    // an alias of another one (final review, M-a).
    const names = new Set(statements.map((s) => vulnIdKey(s.vulnerability)));
    return statements.map((s) => ({ ...s, aliases: s.aliases.filter((a) => !names.has(vulnIdKey(a))) }));
}
function memberOfRow(row) {
    return {
        ids: [row.cve_id],
        keys: new Set([vulnIdKey(row.cve_id)]),
        pkg: row.package_name.toLowerCase(),
        name: row.package_name,
        version: row.installed_version ?? null,
        row,
    };
}
function memberOfFinding(finding) {
    const coordinates = dependencyCoordinates(finding);
    const subject = dependencySubjectOf(finding);
    const ids = findingVulnIds(finding);
    if (coordinates === null || subject === null || ids.length === 0)
        return null;
    return {
        ids,
        keys: new Set(ids.map(vulnIdKey)),
        pkg: coordinates.name.toLowerCase(),
        name: coordinates.name,
        version: subject.version,
        finding,
    };
}
function groupMembers(members) {
    const rows = members.filter((m) => m.row !== undefined);
    /** The id a member is stated under: see the header. */
    const nameOf = (m) => {
        if (m.row !== undefined)
            return m.row.cve_id;
        const rowKeys = new Set(rows.filter((r) => r.pkg === m.pkg && (m.version === null || r.version === m.version)).flatMap((r) => [...r.keys]));
        return m.ids.find((id) => rowKeys.has(vulnIdKey(id))) ?? m.ids.find(isCveId) ?? m.ids[0] ?? '';
    };
    // Same package, same exact version (or both none), same name.
    const byKey = new Map();
    members.forEach((member, index) => {
        const name = nameOf(member);
        const key = `${member.pkg}\u0000${member.version ?? '\u0000'}\u0000${vulnIdKey(name)}`;
        const group = byKey.get(key) ?? { name, members: [], first: index };
        group.members.push(member);
        byKey.set(key, group);
    });
    // A group with no version (a range) joins every version group of its
    // package under the same name, rather than standing apart from them.
    const groups = [...byKey.values()];
    const exact = groups.filter((g) => g.members[0]?.version !== null);
    const out = [...exact];
    for (const loose of groups.filter((g) => g.members[0]?.version === null)) {
        const pkg = loose.members[0]?.pkg;
        const targets = exact.filter((g) => g.members[0]?.pkg === pkg && vulnIdKey(g.name) === vulnIdKey(loose.name));
        if (targets.length === 0)
            out.push(loose);
        for (const target of targets)
            target.members.push(...loose.members);
    }
    return out.sort((a, b) => a.first - b.first);
}
/* ---------------------------------------------------------------------- *
 * One group → one statement
 * ---------------------------------------------------------------------- */
function statementFor(group, inputs, active) {
    const rows = group.members.flatMap((m) => (m.row === undefined ? [] : [m.row]));
    const findings = uniqueFindings(group.members.flatMap((m) => (m.finding === undefined ? [] : [m.finding])));
    const version = group.members.find((m) => m.version !== null)?.version ?? null;
    const name = rows[0]?.package_name ?? group.members[0]?.name ?? '';
    const { vulnerability, aliases } = namesOf(group);
    const subjects = findings.flatMap((f) => {
        const subject = dependencySubjectOf(f);
        return subject === null ? [] : [{ ...subject, version: subject.version ?? version }];
    });
    const ecosystem = subjects.find((s) => s.ecosystem !== null)?.ecosystem ?? sbomEcosystem(inputs.sbom, name, version);
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
    const suppressedNote = findings.some((f) => active.some((s) => matches(s, f)))
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
            status_notes: `${label}: reachable per ${assessment.evidence[0]?.detail ?? 'a file an HTTP route reaches'} — but ` +
                `${stale}, so it is not stated affected (run map_attack_surface).${suppressedNote}`,
        };
    }
    if (assessment?.verdict === 'reachable') {
        return {
            ...base,
            status: 'affected',
            action_statement: base.fixed_version !== null
                ? `Upgrade ${name}${version === null ? '' : ` from ${version}`} to ${base.fixed_version} or later.`
                : `No fixed version of ${name} is recorded by the dependency scan; follow the advisory for a ` +
                    'mitigation, or remove the dependency.',
            status_notes: `${label}: ${assessment.evidence[0]?.detail ?? 'imported by a file an HTTP route reaches'} ` +
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
/** The group's name, and every other own id of its members once. */
function namesOf(group) {
    const aliases = [];
    const seen = new Set([vulnIdKey(group.name)]);
    for (const member of group.members) {
        for (const id of member.ids) {
            if (seen.has(vulnIdKey(id)))
                continue;
            seen.add(vulnIdKey(id));
            aliases.push(id);
        }
    }
    return { vulnerability: group.name, aliases };
}
/** At most this many distinct impact statements are joined into one. */
const MAX_IMPACTS = 3;
/** The copies' distinct impact statements, joined; null when none has one. */
function joinImpacts(values) {
    const distinct = [...new Set(values.flatMap((v) => (v === undefined || v.trim() === '' ? [] : [v.trim()])))];
    if (distinct.length === 0)
        return null;
    const shown = distinct.slice(0, MAX_IMPACTS).join('; ');
    const more = distinct.length - MAX_IMPACTS;
    return more > 0 ? `${shown}; and ${more} more on other copies of the finding` : shown;
}
/** At most this many copies are named in a note. */
const MAX_NAMED_COPIES = 5;
/** The copies, by file and fingerprint, for a note. */
function nameCopies(findings) {
    const named = findings
        .slice(0, MAX_NAMED_COPIES)
        .map((f) => `${f.file_path ?? '(no file)'} [${f.fingerprint.slice(0, 12)}]`)
        .join(', ');
    const more = findings.length - MAX_NAMED_COPIES;
    return more > 0 ? `${named} and ${more} more` : named;
}
/** The best verdict any copy earns: reachable, then imported, then unknown. */
function assess(subjects, fallback, index) {
    if (index === null)
        return null;
    const rank = { reachable: 0, imported: 1, unknown: 2 };
    const assessments = (subjects.length > 0 ? subjects : [fallback]).map((s) => assessDependency(s, index));
    return assessments.sort((a, b) => rank[a.verdict] - rank[b.verdict])[0] ?? null;
}
function whyNot(assessment) {
    if (assessment === null) {
        return 'no attack-surface snapshot, so whether the package is imported was not checked (run map_attack_surface)';
    }
    if (assessment.verdict === 'imported') {
        return (`imported by ${assessment.importing_files.slice(0, 5).join(', ')}, which no known HTTP route ` +
            'was shown to reach with this version');
    }
    return assessment.coverage_gaps[0] ?? 'nothing showed the package in use';
}
/** The same fingerprint-or-identity rule every open-set reader applies. */
function matches(s, f) {
    return s.finding_fingerprint === f.fingerprint || (f.identity !== undefined && s.finding_identity === f.identity);
}
function uniqueFindings(findings) {
    const seen = new Set();
    return findings.filter((f) => (seen.has(f.fingerprint) ? false : (seen.add(f.fingerprint), true)));
}
function maxSeverity(severities) {
    return severities.reduce((max, s) => (SEVERITY_ORDER[s] > SEVERITY_ORDER[max] ? s : max), 'info');
}
/** The ecosystem the SBOM gives the package, when it gives exactly one. */
function sbomEcosystem(sbom, name, version) {
    if (sbom === null)
        return null;
    const { purls, ambiguous } = purlsFor(sbom, name, version, null);
    const first = purls[0];
    return ambiguous || first === undefined ? null : purlType(first);
}
/* ---------------------------------------------------------------------- *
 * One statement per (vulnerability, subcomponent)
 * ---------------------------------------------------------------------- */
const STATUS_CAUTION = { affected: 0, under_investigation: 1, not_affected: 2 };
function mergeSameSubcomponent(drafts) {
    const byKey = new Map();
    for (const draft of drafts) {
        // With no purl, the package name keeps two packages apart (M-e).
        const subcomponent = draft.subcomponent_purls.length > 0
            ? [...draft.subcomponent_purls].sort().join(',')
            : `no-purl:${draft.package_name.toLowerCase()}`;
        const key = `${vulnIdKey(draft.vulnerability)}|${subcomponent}`;
        byKey.set(key, [...(byKey.get(key) ?? []), draft]);
    }
    return [...byKey.values()].map(mergeOne);
}
function mergeOne(same) {
    const [first, ...rest] = same;
    if (first === undefined)
        throw new Error('mergeOne: empty group');
    if (rest.length === 0)
        return first;
    const status = same.map((s) => s.status).sort((a, b) => STATUS_CAUTION[a] - STATUS_CAUTION[b])[0] ?? 'under_investigation';
    const justifications = new Set(same.map((s) => s.justification));
    const agreed = status === 'not_affected' && justifications.size === 1 ? first : null;
    const impact = agreed === null ? null : joinImpacts(same.map((s) => s.impact_statement));
    const one = (values) => (new Set(values).size === 1 ? (values[0] ?? null) : null);
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
//# sourceMappingURL=statements.js.map