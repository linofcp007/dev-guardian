/**
 * `compliance_evidence` — assemble a Markdown evidence pack from
 * accumulated state.
 *
 * Strictly read-only. Produces a Markdown string the model can save,
 * attach to a deliverable, or hand to a client/auditor. The framework
 * tag (gdpr / soc2 / iso27001) just shapes the section labels — the data
 * sources are the same DB rows.
 *
 * **The evidence is ONE project's** (`project_path`, default: the server's
 * working directory — Task 24): its newest usable compliance, dependency
 * and SBOM scans, its own active baseline, and the suppressions that apply
 * to it (its own and the legacy ones scoped to no project). It used to take
 * each from the 50 newest scans of the whole database, the newest baseline
 * of any project and every active suppression — an evidence pack handed to
 * an auditor that could describe a different project than the one it named.
 *
 * `owasp-top10-2025` and `nist-csf-2.0` are evidenced per category from the
 * project's OPEN SET (`history/openSet.ts`): its open findings, and the
 * bookkeeping of the scans behind them. An OWASP category is evidenced only
 * when a scanner able to detect it ran ok in those scans
 * (`frameworks/coverage.ts`); a CSF 2.0 category only through an OWASP
 * category that was, via dev-guardian's own OWASP → CSF mapping
 * (`frameworks/nistCsf2.ts`, labelled as ours in the document). CSF
 * categories no code scan can speak for are listed as not covered, never
 * left out.
 */
import { z } from 'zod';
import { coverageRunsOf, owaspCoverage } from '../frameworks/coverage.js';
import { CSF_CATEGORIES, owaspForCsfCategory } from '../frameworks/nistCsf2.js';
import { findLatestUsable, openSetForProject } from '../history/openSet.js';
import { COVERAGE_RULE, partialReasons, testedByText, unmappedSentence } from '../report/owaspCoverage.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import { CVE_SOURCE_SCAN_TYPES } from '../types.js';
import { registerToolModule } from './index.js';
const FRAMEWORKS = ['gdpr', 'soc2', 'iso27001', 'owasp-top10-2025', 'nist-csf-2.0', 'generic'];
const inputSchema = {
    project_path: ProjectPath,
    framework: z
        .enum(FRAMEWORKS)
        .optional()
        .describe('Which framework to label the evidence under. owasp-top10-2025 and nist-csf-2.0 give per-category ' +
        'evidence from the open findings and the scanners that ran. Default: generic.'),
};
const tool = {
    name: 'compliance_evidence',
    title: 'Compliance evidence pack (Markdown)',
    description: "Generate a Markdown evidence document from one project's accumulated state (project_path, " +
        "default: the server's working directory): latest compliance scan, license summary, CVE " +
        'counts, baseline status, suppressions, policy docs found. Tag with a framework ' +
        '(gdpr/soc2/iso27001/generic) to shape the section labels, or owasp-top10-2025 / nist-csf-2.0 for ' +
        'per-category evidence: a category counts as covered only when a scanner able to detect it ran ok ' +
        '(NIST CSF via dev-guardian\'s own OWASP mapping). Read-only.',
    inputSchema,
    handler: async (input, ctx) => handler(input, ctx),
};
registerToolModule(tool);
async function handler(input, ctx) {
    const inp = input;
    const framework = inp.framework ?? 'generic';
    let projectPath;
    try {
        projectPath = resolveProjectPath(inp.project_path).path;
    }
    catch (e) {
        return { ok: false, error: { code: 'not_a_git_repo', message: e.message } };
    }
    const storage = ctx.storage;
    // Policy documents and licenses are read from files, not scanner output,
    // so a compliance run's scanner coverage does not disqualify it (risk_score
    // reads it the same way).
    const compliance = findLatestUsable(storage, projectPath, ['compliance'], { skipCoverageNone: false }).scan;
    // The newest scan that actually measured dependencies — a security_full
    // row judged on its Trivy half — the same CVE source risk_score uses.
    const deps = findLatestUsable(storage, projectPath, CVE_SOURCE_SCAN_TYPES, { slot: 'deps' }).scan;
    const sbom = findLatestUsable(storage, projectPath, ['sbom']).scan;
    const baseline = storage.baselines.getActiveForProject(projectPath);
    // Every suppression that hides a finding of THIS project: its own, and
    // the ones scoped to no project (NULL — rows written before migration
    // 011), exactly the rule `history/openSet.ts#suppressionMatcher` applies.
    const suppressions = storage.suppressions
        .listActive()
        .filter((s) => s.project_path === undefined || s.project_path === projectPath);
    // Per-category frameworks read the open set: open findings (suppressions
    // applied) and the bookkeeping of every scan behind them.
    let owasp = null;
    if (framework === 'owasp-top10-2025' || framework === 'nist-csf-2.0') {
        const open = openSetForProject(storage, projectPath);
        owasp = {
            coverage: owaspCoverage(coverageRunsOf(open.bookkeeping, open.scans), open.findings),
            findings: open.findings,
        };
    }
    const md = build({
        framework,
        project_path: projectPath,
        generated_at: new Date().toISOString(),
        compliance,
        deps,
        sbom,
        baseline,
        suppressionsCount: suppressions.length,
        owasp,
        ctx,
    });
    return {
        ok: true,
        project_path: projectPath,
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
    'owasp-top10-2025': 'OWASP Top 10:2025',
    'nist-csf-2.0': 'NIST CSF 2.0',
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
        case 'owasp-top10-2025':
            return owaspControls(args.owasp);
        case 'nist-csf-2.0':
            return csfControls(args.owasp);
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
function openFindings(n) {
    return `${n} open finding${n === 1 ? '' : 's'}`;
}
/** One control per OWASP 2025 category: evidenced only when a capable scanner ran ok. */
function owaspControls(owasp) {
    if (owasp === null)
        return [];
    return owasp.coverage.categories.map((c) => {
        const found = openFindings(c.findings);
        if (c.status === 'not_tested') {
            return {
                id: c.id,
                description: c.title,
                evidenced: false,
                note: 'no scanner able to detect it ran ok in the scans behind this document — run: ' +
                    `${c.could_be_tested_by.join('; ')}` +
                    (c.findings > 0 ? ` (${found} from other scanners)` : ''),
            };
        }
        const tested = `tested by ${testedByScans(c)}`;
        return {
            id: c.id,
            description: c.title,
            evidenced: true,
            note: c.status === 'partial'
                ? `PARTIAL — ${tested}, but ${partialReasons(c).join('; ')}; ${found}`
                : `${tested}; ${found}`,
        };
    });
}
/** `semgrep (sast, scan 1a2b3c4d)`, once per tool and scan. */
function testedByScans(c) {
    const seen = new Set();
    const out = [];
    for (const e of c.tested_by) {
        const text = `${e.tool} (${e.scan_type}, scan ${e.scan_id.slice(0, 8)})`;
        if (!seen.has(text)) {
            seen.add(text);
            out.push(text);
        }
    }
    return out.length > 0 ? out.join(', ') : testedByText(c.tested_by);
}
/**
 * One control per CSF 2.0 category (all 22), evidenced through the OWASP
 * categories dev-guardian's own mapping files under it — only those that
 * were tested. A category the mapping does not reach is a process no code
 * scan can evidence, and says so.
 */
function csfControls(owasp) {
    if (owasp === null)
        return [];
    const byId = new Map(owasp.coverage.categories.map((c) => [c.id, c]));
    return CSF_CATEGORIES.map((csf) => {
        const mapped = owaspForCsfCategory(csf.id);
        if (mapped.length === 0) {
            return {
                id: csf.id,
                description: csf.title,
                evidenced: false,
                note: 'an organisational outcome no code scan evidences — not assessable by dev-guardian',
            };
        }
        const tested = mapped.filter((m) => (byId.get(m.owasp)?.status ?? 'not_tested') !== 'not_tested');
        const subcategories = [...new Set(tested.flatMap((m) => m.subcategories))].sort();
        // Each finding once, however many of its categories this CSF category takes.
        const testedIds = new Set(tested.map((m) => m.owasp));
        const findings = owasp.findings.filter((f) => (f.owasp ?? []).some((id) => testedIds.has(id))).length;
        if (tested.length === 0) {
            return {
                id: csf.id,
                description: csf.title,
                evidenced: false,
                note: `none of the OWASP categories mapped here was tested: ${mapped.map((m) => m.owasp).join(', ')}`,
            };
        }
        const via = tested.map((m) => `${m.owasp} (${byId.get(m.owasp)?.status === 'partial' ? 'partial' : 'tested'})`);
        const untested = mapped.filter((m) => !tested.includes(m)).map((m) => m.owasp);
        return {
            id: csf.id,
            description: csf.title,
            evidenced: true,
            note: `via ${via.join(', ')} — subcategories ${subcategories.join(', ')}; ` +
                `${findings} open finding${findings === 1 ? '' : 's'} in those categories` +
                (untested.length > 0 ? `; not tested here: ${untested.join(', ')}` : ''),
        };
    });
}
/** The paragraph that heads a per-category framework's lists. */
function frameworkPreamble(framework, evidence) {
    const owasp = evidence?.coverage ?? null;
    if (framework !== 'owasp-top10-2025' && framework !== 'nist-csf-2.0')
        return [];
    const out = [];
    out.push(`${COVERAGE_RULE} Source of the categories and their CWEs: https://owasp.org/Top10/2025/.`);
    if (framework === 'nist-csf-2.0') {
        out.push('');
        out.push('CSF 2.0 function and category ids are NIST\'s (CSWP 29, https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf). ' +
            "Which OWASP categories evidence which CSF category is dev-guardian's own mapping — neither NIST nor OWASP " +
            'publishes one. A CSF category counts as evidenced only through an OWASP category a capable scanner tested.');
    }
    if (owasp !== null && owasp.findings_total > 0) {
        out.push('');
        out.push(unmappedSentence(owasp, 'open findings'));
    }
    out.push('');
    return out;
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
        out.push('No framework specified. Re-run with `framework=gdpr|soc2|iso27001` for a labelled mapping, or ' +
            '`owasp-top10-2025|nist-csf-2.0` for per-category evidence.');
    }
    else {
        const label = FRAMEWORK_LABEL[args.framework] ?? args.framework.toUpperCase();
        out.push(...frameworkPreamble(args.framework, args.owasp));
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
//# sourceMappingURL=complianceEvidence.js.map