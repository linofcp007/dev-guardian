/**
 * `compliance_check` — license scan + RGPD/policy-document detection.
 *
 * Strategy:
 *   - Run `trivy fs --scanners license` and feed the output to the Trivy
 *     parser. Each risky license becomes a Finding with category='license'.
 *   - Walk the project root for common policy/legal documents (PRIVACY,
 *     TERMS, COOKIE, DPA, etc.) and surface them in `extras.policy_documents_found`.
 *   - Build a per-license summary (`extras.licenses_summary`) and a list of
 *     packages carrying viral / strong-copyleft licenses
 *     (`extras.risky_licenses`).
 *
 * The Findings carry the canonical compliance signal; the extras let the
 * model answer "do we have a privacy policy?" without parsing the report.
 */
import { readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { trivyParser } from '../runners/scannerParsers/trivy.js';
import { runProcess } from '../runners/processRunner.js';
import { Force, ProjectPath } from '../schemas.js';
import { asArray, getProp, getString, } from '../runners/scannerParsers/index.js';
import { registerToolModule } from './index.js';
import { ensureReportDir, readJsonSafe, scannerAvailable, } from './scanHelpers.js';
import { makeScanTool, } from './scanToolFactory.js';
const RISKY_LICENSE_PATTERNS = [
    { pattern: /^AGPL/i, severity: 'high' },
    { pattern: /^GPL-?[23]/i, severity: 'high' },
    { pattern: /^SSPL/i, severity: 'high' },
    { pattern: /^LGPL-?[23]/i, severity: 'medium' },
    { pattern: /^BUSL/i, severity: 'medium' },
    { pattern: /commons.clause/i, severity: 'medium' },
];
const POLICY_DOC_PATTERNS = [
    { kind: 'privacy_policy', pattern: /^privacy(.policy)?\.(md|html|txt|adoc)$/i },
    { kind: 'terms_of_service', pattern: /^terms(.of.(use|service))?\.(md|html|txt|adoc)$/i },
    { kind: 'cookie_policy', pattern: /^cookies?(.policy)?\.(md|html|txt|adoc)$/i },
    { kind: 'data_processing_agreement', pattern: /^dpa\.(md|html|txt|adoc)$/i },
    { kind: 'security_policy', pattern: /^security\.(md|html|txt|adoc)$/i },
    { kind: 'code_of_conduct', pattern: /^code[-_.]of[-_.]conduct\.(md|html|txt|adoc)$/i },
];
function detectPolicyDocs(projectPath) {
    const found = {
        privacy_policy: false,
        terms_of_service: false,
        cookie_policy: false,
        data_processing_agreement: false,
        security_policy: false,
        code_of_conduct: false,
        paths: [],
    };
    const candidates = listShallowFiles(projectPath, 2);
    for (const rel of candidates) {
        const base = rel.split('/').pop() ?? rel;
        for (const { kind, pattern } of POLICY_DOC_PATTERNS) {
            if (pattern.test(base)) {
                found[kind] = true;
                found.paths.push(rel);
            }
        }
    }
    return found;
}
function listShallowFiles(root, maxDepth) {
    const out = [];
    walk(root, root, 0, maxDepth, out);
    return out;
}
function walk(root, dir, depth, maxDepth, out) {
    if (depth > maxDepth)
        return;
    let entries;
    try {
        entries = readdirSync(dir);
    }
    catch {
        return;
    }
    for (const entry of entries) {
        if (entry.startsWith('.') && entry !== '.github' && entry !== '.gitlab')
            continue;
        if (entry === 'node_modules' || entry === '.guardian' || entry === 'dist' || entry === 'build')
            continue;
        const abs = join(dir, entry);
        try {
            const s = statSync(abs);
            if (s.isDirectory()) {
                if (depth + 1 <= maxDepth)
                    walk(root, abs, depth + 1, maxDepth, out);
            }
            else if (s.isFile()) {
                out.push(abs.slice(root.length + 1).replace(/\\/g, '/'));
            }
        }
        catch {
            /* skip */
        }
    }
}
function summariseLicenses(raw) {
    let root;
    try {
        root = JSON.parse(raw);
    }
    catch {
        return { licenses_summary: [], risky_licenses: [] };
    }
    const byLicense = new Map();
    for (const result of asArray(getProp(root, 'Results'))) {
        for (const lic of asArray(getProp(result, 'Licenses'))) {
            const name = getString(lic, 'Name');
            const pkg = getString(lic, 'PkgName') ?? '(unknown)';
            if (!name)
                continue;
            if (!byLicense.has(name))
                byLicense.set(name, new Set());
            byLicense.get(name).add(pkg);
        }
    }
    const licenses_summary = [];
    for (const [license, pkgSet] of byLicense) {
        const risk = riskFor(license);
        licenses_summary.push({ license, packages: [...pkgSet].sort(), risk });
    }
    licenses_summary.sort((a, b) => riskOrder(b.risk) - riskOrder(a.risk) || a.license.localeCompare(b.license));
    const risky_licenses = licenses_summary.filter((e) => e.risk !== 'low');
    return { licenses_summary, risky_licenses };
}
function riskFor(license) {
    for (const { pattern, severity } of RISKY_LICENSE_PATTERNS) {
        if (pattern.test(license))
            return severity;
    }
    return 'low';
}
function riskOrder(r) {
    return r === 'high' ? 2 : r === 'medium' ? 1 : 0;
}
registerToolModule(makeScanTool({
    name: 'compliance_check',
    title: 'Compliance check (licenses + RGPD policy docs)',
    description: 'Run Trivy license scan and detect common policy documents (PRIVACY, TERMS, COOKIES, DPA, ' +
        'SECURITY, CODE_OF_CONDUCT) at the project root. Returns Findings for risky licenses and ' +
        'an `extras` payload with `licenses_summary`, `risky_licenses`, and `policy_documents_found`.',
    scan_type: 'compliance',
    category: 'compliance',
    supportsAutoFix: false,
    inputSchema: {
        project_path: ProjectPath,
        force: Force,
    },
    invoke: async (_input, ctx) => {
        const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'compliance');
        const tools_run = [];
        const missing_tools = [];
        const parser_inputs = [];
        let licensesSummary = {
            licenses_summary: [],
            risky_licenses: [],
        };
        const trivyBin = await scannerAvailable('trivy');
        if (trivyBin) {
            const outFile = join(reportDir, 'licenses.json');
            const result = await runProcess({
                command: 'trivy',
                args: [
                    'fs',
                    '--scanners',
                    'license',
                    '--format',
                    'json',
                    '--output',
                    outFile,
                    '--quiet',
                    ctx.projectPath,
                ],
                cwd: ctx.projectPath,
                env: ctx.scriptEnv,
                signal: ctx.signal,
                onLog: ctx.onLog,
            });
            const raw = readJsonSafe(outFile);
            if (raw) {
                parser_inputs.push({ parser: trivyParser, input: raw });
                licensesSummary = summariseLicenses(raw);
            }
            tools_run.push({
                name: 'trivy',
                status: result.outcome === 'completed' ? 'ok' : 'failed',
            });
        }
        else {
            tools_run.push({ name: 'trivy', status: 'skipped', reason: 'not_installed' });
            missing_tools.push('trivy');
        }
        const policy_documents_found = detectPolicyDocs(ctx.projectPath);
        tools_run.push({ name: 'policy-docs', status: 'ok' });
        return {
            outcome: 'completed',
            tools_run,
            missing_tools,
            parser_inputs,
            report_paths: [reportDir],
            extras: {
                licenses_summary: licensesSummary.licenses_summary,
                risky_licenses: licensesSummary.risky_licenses,
                policy_documents_found,
            },
        };
    },
}));
//# sourceMappingURL=complianceCheck.js.map