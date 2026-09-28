/**
 * Which OWASP Top 10:2025 categories the scans behind a report actually
 * TESTED — the one rule every renderer of the taxonomy shares.
 *
 * A category is covered only when a scanner able to detect it ran `ok` in
 * one of the scans the report covers. Zero findings in a category whose
 * scanner did not run, failed, or ran a rule set that cannot see it is "not
 * tested", never clean — the product's one theme, applied to a taxonomy.
 *
 * ---- "Able to detect it" is per tools_run name AND scan type ------------
 *
 * One bookkeeping name does not mean one rule set. `semgrep` in a
 * `scan_sast` row ran the registry (unless `local_only`); `semgrep` in a
 * `bug_hunt` row ran the bugfix packs, which look for swallowed exceptions,
 * not injection; `trivy` in `scan_deps` is the vulnerability pass, in
 * `compliance_check` a license-only pass. So each claim below
 * ({@link OWASP_DETECTORS}) names the scan types it holds for, and states
 * its basis. They are deliberately conservative: a category a scanner's
 * rules reach only in one language, or with a handful of rules, is not
 * claimed for it.
 *
 * A claim is `partial` rather than `tested` when the run was ok but
 * incomplete: the scan was scoped to part of the project (a diff review, a
 * `scope` run), the tool is also in `missing_tools` (itself, or one of its
 * `tool:<gap>` sub-gaps such as `trivy:npm`), some files were only partly
 * parsed, or some rules did not load.
 *
 * Findings are counted separately and never decide coverage: a category can
 * hold findings (from a scanner with no claim here) and still read "not
 * tested", and a tested category can hold none. A finding with no `owasp`
 * field is counted as unmapped — unknown, never filed under a category.
 *
 * Pure: bookkeeping and findings in, a table out.
 */
import { OWASP_TOP10_2025 } from './owaspTop10_2025.js';
/** The registry ran: not `local_only`, and not an orchestrated parent (whose meta does not say). */
function registryRan(run) {
    if (run.meta?.['local_only'] === true)
        return false;
    return !(run.scan_type === 'security_full' && Array.isArray(run.meta?.['child_scans']));
}
export const OWASP_DETECTORS = [
    {
        id: 'semgrep-registry',
        label: 'Semgrep registry rules (scan_sast without local_only)',
        runs: ['semgrep'],
        scanTypes: ['sast', 'security_full', 'review_pr'],
        applies: registryRan,
        categories: ['A01:2025', 'A02:2025', 'A04:2025', 'A05:2025', 'A06:2025', 'A07:2025', 'A08:2025'],
        basis: 'Measured on the registry ruleset p/default (1074 rules, fetched 2026-09-28), counting rules whose CWEs ' +
            'OWASP maps to each category: A01 136, A02 55, A04 218, A05 310, A06 68, A07 92, A08 74 — each across ' +
            'eight or more languages. Not claimed: A03 (3 rules), A09 (6, Python and HCL only), A10 (4). scan_sast ' +
            'runs --config=auto, which selects registry rulesets by language; p/default is the measured proxy.',
    },
    {
        id: 'bandit',
        label: 'Bandit (scan_sast, Python)',
        runs: ['bandit'],
        scanTypes: ['sast', 'security_full', 'review_pr'],
        categories: ['A01:2025', 'A04:2025', 'A05:2025', 'A07:2025', 'A08:2025', 'A10:2025'],
        basis: "Bandit 1.9.4's own CWE assignments (bandit/core/issue.py, counted over its plugins and blacklists): " +
            'A01 path traversal, temp files, permissions (8 checks); A04 weak crypto, cleartext, randomness (22); ' +
            'A05 command, SQL and code injection, input validation (38); A07 certificate validation, hard-coded ' +
            'password (4); A08 deserialization, download without integrity check (5); A10 improper check of ' +
            'exceptional conditions (3). Python code only.',
    },
    {
        id: 'bugfix-packs',
        label: 'bug_hunt packs (configs/semgrep/bugfix-*.yml)',
        runs: ['semgrep'],
        scanTypes: ['bugs'],
        categories: ['A10:2025'],
        basis: 'The packs\' own cwe/owasp metadata: every bugfix pack except bugfix-rs carries A10 rules (empty catch, ' +
            'unchecked return, null dereference, uncaught exception). A06 appears only in bugfix-js and bugfix-py ' +
            '(CWE-362) and is not claimed.',
    },
    {
        id: 'rgpd-pack',
        label: 'RGPD pack (compliance_check, configs/semgrep/rgpd.yml)',
        runs: ['semgrep-rgpd'],
        scanTypes: ['compliance'],
        categories: ['A01:2025', 'A09:2025'],
        basis: "The pack's own metadata: personal data in logs (CWE-532, A09) in JS/TS, PHP, Python and C#, and personal " +
            'data exposed to third parties without consent (CWE-359, A01) in every rule.',
    },
    {
        id: 'trivy-vulnerabilities',
        label: 'Trivy vulnerability pass (scan_deps, deps_audit)',
        runs: ['trivy'],
        scanTypes: ['deps', 'deps_audit', 'security_full'],
        categories: ['A03:2025'],
        basis: 'Every known-vulnerable dependency it reports is CWE-1395 (Dependency on Vulnerable Third-Party ' +
            "Component), which OWASP maps to A03. compliance_check's Trivy pass is license-only and is not counted.",
    },
    {
        id: 'trivy-image',
        label: 'Trivy image pass (scan_containers with an image)',
        runs: ['trivy-image'],
        scanTypes: ['containers'],
        categories: ['A03:2025'],
        basis: 'The same vulnerability pass over an image (CWE-1395, A03).',
    },
    {
        id: 'dependency-auditors',
        label: 'npm audit, pip-audit, dotnet list package --vulnerable (deps_audit)',
        runs: ['npm', 'pip-audit', 'dotnet'],
        // 2.0.x deps_audit rows carry scan type 'deps' (types.ts `isDepsAuditScan`).
        scanTypes: ['deps_audit', 'deps'],
        categories: ['A03:2025'],
        basis: 'Each reports known-vulnerable dependencies (CWE-1395, A03).',
    },
    {
        id: 'gitleaks',
        label: 'gitleaks (scan_secrets)',
        runs: ['gitleaks', 'gitleaks-working-tree'],
        scanTypes: ['secrets', 'security_full', 'wordpress', 'review_pr'],
        categories: ['A07:2025'],
        basis: 'Every secret it reports is a hard-coded credential (CWE-798), which OWASP maps to A07.',
    },
];
function partialReason(run, t) {
    const reasons = [];
    if (run.scan_type === 'review_pr')
        reasons.push('a diff review looks only at changed files');
    const scope = run.meta?.['scope'];
    if (scope !== undefined && scope !== null)
        reasons.push('the scan was scoped to part of the project');
    const gaps = run.missing_tools.filter((m) => m === t.name || m.startsWith(`${t.name}:`));
    if (gaps.length > 0)
        reasons.push(`also listed missing (${gaps.join(', ')})`);
    if ((t.partially_parsed?.length ?? 0) > 0)
        reasons.push('some files were only partly parsed');
    if ((t.failed_rules?.length ?? 0) > 0)
        reasons.push('some rules did not load');
    return reasons.length > 0 ? reasons.join('; ') : undefined;
}
export function owaspCoverage(runs, findings) {
    const testedBy = new Map();
    for (const run of runs) {
        for (const t of run.tools_run) {
            if (t.status !== 'ok')
                continue;
            for (const d of OWASP_DETECTORS) {
                if (!d.runs.includes(t.name))
                    continue;
                if (!d.scanTypes.includes(run.scan_type))
                    continue;
                if (d.applies !== undefined && !d.applies(run))
                    continue;
                const partial = partialReason(run, t);
                const entry = { scan_id: run.scan_id, scan_type: run.scan_type, tool: t.name, detector: d.id };
                if (partial !== undefined)
                    entry.partial = partial;
                for (const id of d.categories) {
                    const list = testedBy.get(id) ?? [];
                    if (!list.some((e) => e.scan_id === entry.scan_id && e.tool === entry.tool && e.detector === entry.detector)) {
                        list.push(entry);
                    }
                    testedBy.set(id, list);
                }
            }
        }
    }
    const counts = new Map();
    let unmapped = 0;
    for (const f of findings) {
        const ids = f.owasp ?? [];
        if (ids.length === 0) {
            unmapped += 1;
            continue;
        }
        for (const id of new Set(ids)) {
            const known = OWASP_TOP10_2025.find((c) => c.id === id);
            if (known !== undefined)
                counts.set(known.id, (counts.get(known.id) ?? 0) + 1);
        }
    }
    return {
        categories: OWASP_TOP10_2025.map((c) => {
            const by = testedBy.get(c.id) ?? [];
            const status = by.some((e) => e.partial === undefined)
                ? 'tested'
                : by.length > 0
                    ? 'partial'
                    : 'not_tested';
            return {
                id: c.id,
                title: c.title,
                url: c.url,
                status,
                tested_by: by,
                findings: counts.get(c.id) ?? 0,
                could_be_tested_by: OWASP_DETECTORS.filter((d) => d.categories.includes(c.id)).map((d) => d.label),
            };
        }),
        findings_total: findings.length,
        findings_unmapped: unmapped,
    };
}
/**
 * Coverage runs from an open set's per-slot bookkeeping (`history/openSet.ts`
 * `OpenSet.bookkeeping` + `OpenSet.scans`): each view keeps its own
 * tools_run/missing_tools and takes its scan's type and meta. A view whose
 * scan is not in `scans` is dropped — it cannot be judged without its type.
 */
export function coverageRunsOf(bookkeeping, scans) {
    const byId = new Map(scans.map((s) => [s.scan_id, s]));
    const out = [];
    for (const view of bookkeeping) {
        const scan = byId.get(view.scan_id);
        if (scan === undefined)
            continue;
        const r = {
            scan_id: view.scan_id,
            scan_type: scan.scan_type,
            tools_run: view.tools_run,
            missing_tools: view.missing_tools,
        };
        if (scan.meta !== undefined)
            r.meta = scan.meta;
        out.push(r);
    }
    return out;
}
//# sourceMappingURL=coverage.js.map