/**
 * VEX statements rendered as an OpenVEX document or a CycloneDX VEX BOM.
 * Pure: the caller supplies the document id, the clock and the product.
 *
 * ---- OpenVEX ----------------------------------------------------------------
 *
 * OpenVEX Specification v0.2.0 and its JSON schema
 * (github.com/openvex/spec, `OPENVEX-SPEC.md` and `openvex_json_schema.json`
 * at 61b5f885d0f481f48683c93345e49ef1a6e9fdff, retrieved 2026-09-28):
 * `@context` `https://openvex.dev/ns/v0.2.0`; `@id`, `author`, `timestamp`,
 * `version` required; `statements` at least one. A statement names its
 * `vulnerability` (`name` required), its `products` — here the project, with
 * the vulnerable package as a `subcomponent` identified by purl — and a
 * `status`. `not_affected` carries a `justification` (and optionally an
 * `impact_statement`); `affected` MUST carry an `action_statement`.
 *
 * ---- CycloneDX --------------------------------------------------------------
 *
 * CycloneDX 1.6 (`schema/bom-1.6.schema.json`, tag 1.6), a BOM whose
 * `vulnerabilities[].analysis` is the VEX: `state`, `justification`,
 * `response`, `detail`, and `affects[].ref` naming a component `bom-ref` in
 * the same BOM. A vulnerability's other ids go in `references`, each with its
 * source. OpenVEX → CycloneDX mapping, after the table a community member
 * (RingoDev) posted opening github.com/CycloneDX/specification discussion
 * #609 ("Mapping CycloneDX bi-directionally to Minimum Requirements for VEX",
 * March 2025), and CycloneDX maintainer Steve Springett's reply on its one
 * open row — a user's proposal and a maintainer's comment, not a mapping
 * CycloneDX publishes:
 *
 *   not_affected + component_not_present             → state false_positive
 *   not_affected + vulnerable_code_not_present        → not_affected, code_not_present
 *   not_affected + vulnerable_code_not_in_execute_path → not_affected, code_not_reachable
 *   not_affected + inline_mitigations_already_exist   → not_affected, protected_by_mitigating_control
 *   not_affected + vulnerable_code_cannot_be_controlled_by_adversary
 *                                                     → not_affected, no justification
 *     (CycloneDX splits it into five narrower reasons — requires_configuration,
 *     requires_dependency, requires_environment, protected_at_runtime,
 *     protected_at_perimeter — and nothing here says which one; the OpenVEX
 *     label is kept in `detail`)
 *   affected                                          → exploitable (+ response update when a fix exists)
 *   under_investigation                               → in_triage
 */
const OPENVEX_CONTEXT = 'https://openvex.dev/ns/v0.2.0';
/**
 * Where a vulnerability id is published: NVD for a CVE, GitHub's advisory
 * database for a GHSA id, OSV for the schemes it indexes (PYSEC, GO,
 * RUSTSEC, OSV, …). Null for an id of any other scheme — named, never linked
 * to a page that may not exist.
 */
function sourceOf(id) {
    if (/^CVE-\d{4}-\d+$/i.test(id))
        return { name: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${id.toUpperCase()}` };
    if (/^GHSA(-[0-9a-z]{4}){3}$/i.test(id))
        return { name: 'GitHub Advisories', url: `https://github.com/advisories/${id}` };
    if (/^(PYSEC|GO|RUSTSEC|OSV|GSD|MAL)-/i.test(id))
        return { name: 'OSV', url: `https://osv.dev/vulnerability/${id}` };
    return null;
}
export function renderOpenVex(statements, meta) {
    return {
        '@context': OPENVEX_CONTEXT,
        '@id': `urn:uuid:${meta.documentId}`,
        author: meta.author,
        timestamp: meta.timestamp,
        version: 1,
        tooling: `dev-guardian ${meta.toolVersion} (export_vex)`,
        statements: statements.map((s) => openVexStatement(s, meta)),
    };
}
function openVexStatement(s, meta) {
    const source = sourceOf(s.vulnerability);
    const product = {
        '@id': meta.product.id,
        identifiers: { purl: meta.product.id },
        ...(s.subcomponent_purls.length > 0
            ? { subcomponents: s.subcomponent_purls.map((purl) => ({ '@id': purl, identifiers: { purl } })) }
            : {}),
    };
    return {
        vulnerability: {
            ...(source !== null ? { '@id': source.url } : {}),
            name: s.vulnerability,
            ...(s.aliases.length > 0 ? { aliases: s.aliases } : {}),
        },
        products: [product],
        status: s.status,
        ...(s.justification !== undefined ? { justification: s.justification } : {}),
        ...(s.impact_statement !== undefined ? { impact_statement: s.impact_statement } : {}),
        ...(s.status === 'affected' && s.action_statement !== undefined
            ? { action_statement: s.action_statement }
            : {}),
        status_notes: s.status_notes,
    };
}
const CYCLONEDX_JUSTIFICATION = {
    component_not_present: null,
    vulnerable_code_not_present: 'code_not_present',
    vulnerable_code_not_in_execute_path: 'code_not_reachable',
    vulnerable_code_cannot_be_controlled_by_adversary: null,
    inline_mitigations_already_exist: 'protected_by_mitigating_control',
};
const PRODUCT_REF = 'product';
export function renderCycloneDxVex(statements, meta) {
    // One component per distinct package version; the vulnerabilities point at it.
    const components = new Map();
    const refOf = (s) => {
        const purl = s.subcomponent_purls[0];
        const ref = purl ?? `component:${s.package_name}@${s.installed_version ?? 'unknown'}`;
        if (!components.has(ref)) {
            components.set(ref, {
                type: 'library',
                'bom-ref': ref,
                name: s.package_name,
                ...(s.installed_version !== null ? { version: s.installed_version } : {}),
                ...(purl !== undefined ? { purl } : {}),
            });
        }
        return ref;
    };
    const vulnerabilities = statements.map((s) => {
        const source = sourceOf(s.vulnerability);
        const references = s.aliases.flatMap((id) => {
            const from = sourceOf(id);
            return from === null ? [] : [{ id, source: from }];
        });
        return {
            id: s.vulnerability,
            ...(source !== null ? { source } : {}),
            ...(references.length > 0 ? { references } : {}),
            analysis: cycloneDxAnalysis(s),
            ...(s.status === 'affected' && s.action_statement !== undefined
                ? { recommendation: s.action_statement }
                : {}),
            affects: [{ ref: refOf(s) }],
        };
    });
    return {
        bomFormat: 'CycloneDX',
        specVersion: '1.6',
        serialNumber: `urn:uuid:${meta.documentId}`,
        version: 1,
        metadata: {
            timestamp: meta.timestamp,
            tools: { components: [{ type: 'application', name: 'dev-guardian', version: meta.toolVersion }] },
            component: {
                type: 'application',
                'bom-ref': PRODUCT_REF,
                name: meta.product.name,
                ...(meta.product.purl !== null ? { purl: meta.product.purl } : {}),
            },
        },
        components: [...components.values()],
        vulnerabilities,
    };
}
function cycloneDxAnalysis(s) {
    switch (s.status) {
        case 'not_affected': {
            const justification = s.justification === undefined ? null : CYCLONEDX_JUSTIFICATION[s.justification];
            const label = s.justification === undefined ? '' : ` OpenVEX justification: ${s.justification}.`;
            const impact = s.impact_statement === undefined ? '' : ` ${s.impact_statement}`;
            return {
                state: s.justification === 'component_not_present' ? 'false_positive' : 'not_affected',
                ...(justification !== null ? { justification } : {}),
                detail: `${s.status_notes}${label}${impact}`,
            };
        }
        case 'affected':
            return {
                state: 'exploitable',
                ...(s.fixed_version !== null ? { response: ['update'] } : {}),
                detail: s.status_notes,
            };
        case 'under_investigation':
            return { state: 'in_triage', detail: s.status_notes };
    }
}
//# sourceMappingURL=render.js.map