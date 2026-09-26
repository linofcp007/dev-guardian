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
    const deps = findLatest(ctx, 'deps_audit') ?? findLatest(ctx, 'deps') ?? findLatest(ctx, 'security_full');
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
function complianceMeta(compliance) {
    return compliance?.meta;
}
const FRAMEWORK_LABEL = {
    gdpr: 'GDPR',
    soc2: 'SOC 2',
    iso27001: 'ISO 27001',
};
/**
 * What each framework's mapping used to claim unconditionally, now gated on
 * whether a scan present in THIS document actually backs it. GDPR Article 5
 * (data minimisation) is not in this list at all: "SBOM components and
 * license posture" was never evidence of minimising personal data collected
 * — a wrong mapping, not an uncovered one, so it is dropped rather than
 * listed as missing. "Scan cadence" and "dep update plan" are dropped for
 * the same reason: neither is tracked by any scan this tool reads, so
 * claiming they were covered — or even naming them as a gap to fill — would
 * promise evidence this tool has no way to produce.
 */
function frameworkControls(framework, args) {
    const meta = complianceMeta(args.compliance);
    const hasPolicyDocs = meta?.policy_documents_found !== undefined;
    const hasLicenses = meta?.licenses_summary !== undefined;
    const hasDeps = args.deps !== null;
    const hasBaseline = args.baseline !== null;
    const hasSbom = args.sbom !== null;
    switch (framework) {
        case 'gdpr':
            return [
                {
                    id: 'Article 25',
                    description: 'privacy by design and by default',
                    evidenced: hasPolicyDocs,
                    note: hasPolicyDocs
                        ? 'privacy and security policy presence — see "Latest compliance scan" above'
                        : 'no `compliance_check` scan on file — policy-document presence was never checked',
                },
                {
                    id: 'Article 32',
                    description: 'security of processing',
                    evidenced: hasDeps,
                    note: hasDeps
                        ? 'dependency CVE posture — see "Dependency vulnerability posture" above'
                        : 'no `scan_deps`/`deps_audit` scan on file — vulnerability posture was never measured',
                },
            ];
        case 'soc2':
            return [
                {
                    id: 'CC7.1 / CC7.2',
                    description: 'vulnerability management',
                    evidenced: hasDeps,
                    note: hasDeps
                        ? 'CVE counts — see "Dependency vulnerability posture" above'
                        : 'no `scan_deps`/`deps_audit` scan on file — vulnerability posture was never measured',
                },
                {
                    id: 'CC8.1',
                    description: 'change management',
                    evidenced: hasBaseline,
                    note: hasBaseline
                        ? 'baseline + suppressions traceability — see "Change-tracking / baseline" above'
                        : 'no baseline set — run `set_baseline`',
                },
                {
                    id: 'CC9.1',
                    description: 'risk mitigation',
                    evidenced: hasLicenses,
                    note: hasLicenses
                        ? 'license posture — see "Latest compliance scan" above'
                        : 'no `compliance_check` scan on file — license posture was never measured',
                },
            ];
        case 'iso27001':
            return [
                {
                    id: 'A.8.8',
                    description: 'management of technical vulnerabilities',
                    evidenced: hasDeps,
                    note: hasDeps
                        ? 'CVE counts — see "Dependency vulnerability posture" above'
                        : 'no `scan_deps`/`deps_audit` scan on file — vulnerability posture was never measured',
                },
                {
                    id: 'A.5.20',
                    description: 'supplier relationships',
                    evidenced: hasSbom,
                    note: hasSbom
                        ? 'SBOM — see "Software Bill of Materials (SBOM)" above'
                        : 'no SBOM on file — run `generate_sbom`',
                },
                {
                    id: 'A.5.32',
                    description: 'intellectual property',
                    evidenced: hasLicenses,
                    note: hasLicenses
                        ? 'license compatibility findings — see "Latest compliance scan" above'
                        : 'no `compliance_check` scan on file — license posture was never measured',
                },
            ];
    }
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
        const meta = complianceMeta(args.compliance);
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
    if (args.framework === 'generic') {
        out.push('No framework specified. Re-run with `framework=gdpr|soc2|iso27001` for a labelled mapping.');
    }
    else {
        const label = FRAMEWORK_LABEL[args.framework] ?? args.framework.toUpperCase();
        const controls = frameworkControls(args.framework, args);
        const evidenced = controls.filter((c) => c.evidenced);
        const notCovered = controls.filter((c) => !c.evidenced);
        out.push(`### ${label} controls evidenced by this document`);
        if (evidenced.length === 0) {
            out.push('(none — see "not covered" below)');
        }
        else {
            for (const c of evidenced)
                out.push(`- ${c.id} (${c.description}): ${c.note}`);
        }
        out.push('');
        out.push(`### ${label} controls NOT covered by this document`);
        if (notCovered.length === 0) {
            out.push('(none)');
        }
        else {
            for (const c of notCovered)
                out.push(`- ${c.id} (${c.description}): NOT COVERED — ${c.note}`);
        }
    }
    out.push('');
    out.push('---');
    out.push('_Generated by dev-guardian. dev-guardian sends no telemetry of its own; ' +
        "Semgrep's registry mode sends metrics — pass `local_only: true` to avoid it._");
    return out.join('\n');
}
function findLatest(ctx, type) {
    const history = ctx.storage.scans.listHistory(50);
    const row = history.find((s) => s.scan_type === type && s.status === 'completed');
    return row ? ctx.storage.scans.getById(row.scan_id) : null;
}
//# sourceMappingURL=complianceEvidence.js.map