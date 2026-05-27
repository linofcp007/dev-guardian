/**
 * `compliance_evidence` — assemble a Markdown evidence pack from
 * accumulated state.
 *
 * Strictly read-only. Produces a Markdown string the model can save,
 * attach to a deliverable, or hand to a client/auditor. The framework
 * tag (gdpr / soc2 / iso27001) just shapes the section labels — the data
 * sources are the same DB rows.
 */
import { z } from 'zod';
import { registerToolModule } from './index.js';
const inputSchema = {
    framework: z
        .enum(['gdpr', 'soc2', 'iso27001', 'generic'])
        .optional()
        .describe('Which framework to label the evidence under. Default: generic.'),
};
const tool = {
    name: 'compliance_evidence',
    title: 'Compliance evidence pack (Markdown)',
    description: 'Generate a Markdown evidence document from accumulated state: latest compliance scan, ' +
        'license summary, CVE counts, baseline status, suppressions, policy docs found. Tag with a ' +
        'framework (gdpr/soc2/iso27001/generic) to shape the section labels. Read-only.',
    inputSchema,
    handler: async (input, ctx) => handler(input, ctx),
};
registerToolModule(tool);
async function handler(input, ctx) {
    const inp = input;
    const framework = inp.framework ?? 'generic';
    const compliance = findLatest(ctx, 'compliance');
    const deps = findLatest(ctx, 'deps') ?? findLatest(ctx, 'security_full');
    const sbom = findLatest(ctx, 'sbom');
    const baseline = ctx.storage.baselines.getActive();
    const suppressions = ctx.storage.suppressions.listActive();
    const md = build({
        framework,
        project_path: deps?.project_path ?? compliance?.project_path ?? '(unknown)',
        generated_at: new Date().toISOString(),
        compliance,
        deps,
        sbom,
        baseline,
        suppressionsCount: suppressions.length,
        ctx,
    });
    return {
        ok: true,
        framework,
        markdown: md,
        size_bytes: Buffer.byteLength(md, 'utf8'),
        instructions_for_model: 'Save this to docs/compliance/<framework>-evidence.md or hand to the auditor directly. ' +
            'Sections without underlying scans are flagged as "(no data — run X)".',
    };
}
function build(args) {
    const out = [];
    out.push(`# Compliance evidence — ${args.framework.toUpperCase()}`);
    out.push('');
    out.push(`Generated: ${args.generated_at}`);
    out.push(`Project path: \`${args.project_path}\``);
    out.push('');
    out.push('## Scope');
    out.push(`This document compiles evidence from the dev-guardian local scan store. All data is ` +
        `produced by open-source scanners run on the developer machine — no third-party processing.`);
    out.push('');
    out.push('## Latest compliance scan');
    if (args.compliance) {
        out.push(`- Scan id: \`${args.compliance.scan_id}\``);
        out.push(`- Run at: ${args.compliance.started_at}`);
        const meta = args.compliance.meta;
        if (meta?.licenses_summary) {
            out.push(`- Licenses observed: ${meta.licenses_summary.length}`);
            const risky = meta.risky_licenses ?? [];
            out.push(`- Risky licenses: ${risky.map((l) => l.license).join(', ') || '(none)'}`);
        }
        if (meta?.policy_documents_found) {
            const docs = meta.policy_documents_found;
            out.push(`- Privacy policy doc: ${docs['privacy_policy'] ? '✓' : '✗ MISSING'}`);
            out.push(`- Terms of service doc: ${docs['terms_of_service'] ? '✓' : '✗ MISSING'}`);
            out.push(`- Cookie policy doc: ${docs['cookie_policy'] ? '✓' : '— n/a or missing'}`);
            out.push(`- Security policy doc: ${docs['security_policy'] ? '✓' : '✗ MISSING'}`);
        }
    }
    else {
        out.push('(no data — run `compliance_check` first)');
    }
    out.push('');
    out.push('## Dependency vulnerability posture');
    if (args.deps) {
        out.push(`- Scan id: \`${args.deps.scan_id}\``);
        out.push(`- Run at: ${args.deps.started_at}`);
        const cves = args.ctx.storage.cves.listActive(args.deps.scan_id);
        const bySev = cves.reduce((acc, c) => {
            acc[c.severity] = (acc[c.severity] ?? 0) + 1;
            return acc;
        }, {});
        out.push(`- Active CVEs: ${cves.length}`);
        for (const k of ['critical', 'high', 'medium', 'low']) {
            out.push(`  - ${k}: ${bySev[k] ?? 0}`);
        }
    }
    else {
        out.push('(no data — run `scan_deps` or `deps_audit` first)');
    }
    out.push('');
    out.push('## Software Bill of Materials (SBOM)');
    if (args.sbom?.meta) {
        const m = args.sbom.meta;
        out.push(`- Format: ${m.format ?? '(unknown)'}`);
        out.push(`- Components: ${m.components_count ?? '(unknown)'}`);
        out.push(`- Stored at: \`${m.file_path ?? '(unknown)'}\``);
    }
    else {
        out.push('(no data — run `generate_sbom`)');
    }
    out.push('');
    out.push('## Change-tracking / baseline');
    if (args.baseline) {
        out.push(`- Active baseline: \`${args.baseline.scan_id}\` (set at ${args.baseline.set_at})`);
        out.push(`- Suppressions active: ${args.suppressionsCount}`);
    }
    else {
        out.push(`- No baseline set. Future regressions can't be auditable without one — run \`set_baseline\`.`);
    }
    out.push('');
    out.push('## Frameworks');
    switch (args.framework) {
        case 'gdpr':
            out.push('### GDPR mapping\n- Article 5 (data minimisation): see SBOM components and license posture.\n' +
                '- Article 25 (privacy by design): privacy policy + security policy presence above.\n' +
                '- Article 32 (security of processing): CVE posture + scan cadence (see scan history).');
            break;
        case 'soc2':
            out.push('### SOC 2 trust services criteria\n- CC7.1 / CC7.2 (vulnerability mgmt): CVE counts + baseline above.\n' +
                '- CC8.1 (change mgmt): baseline + suppressions traceability.\n' +
                '- CC9.1 (risk mitigation): license posture + dep update plan.');
            break;
        case 'iso27001':
            out.push('### ISO 27001 Annex A controls\n- A.8.8 (technical vulnerabilities): scan cadence + CVE counts.\n' +
                '- A.5.20 (supplier relationships): SBOM + license posture.\n' +
                '- A.5.32 (intellectual property): license compatibility findings.');
            break;
        default:
            out.push('No framework specified. Re-run with `framework=gdpr|soc2|iso27001` for a labelled mapping.');
    }
    out.push('');
    out.push('---');
    out.push('_Generated by dev-guardian. All scans local, no telemetry._');
    return out.join('\n');
}
function findLatest(ctx, type) {
    const history = ctx.storage.scans.listHistory(50);
    const row = history.find((s) => s.scan_type === type && s.status === 'completed');
    return row ? ctx.storage.scans.getById(row.scan_id) : null;
}
//# sourceMappingURL=complianceEvidence.js.map