/**
 * `compliance_check` — license scan, RGPD code rules, policy-document detection.
 *
 * Strategy:
 *   - Run `trivy fs --scanners license` and feed the output to the Trivy
 *     parser. Each risky license becomes a Finding with category='license'.
 *   - Run the shipped RGPD Semgrep pack (`configs/semgrep/rgpd.yml`):
 *     Portuguese personal identifiers (NIF, NISS, Cartão de Cidadão, IBAN,
 *     phone, email) flowing into log calls in JS/TS, PHP, Python and C#, and
 *     trackers (GA4, Meta Pixel, Hotjar, youtube.com embeds) loaded by markup
 *     with no consent guard. Its findings are re-tagged category='compliance'
 *     with an `rgpd-*` subcategory. `--metrics=off`: an RGPD check sends
 *     nothing anywhere.
 *   - Walk the project root for common policy/legal documents (PRIVACY,
 *     TERMS, COOKIE, DPA, etc.) and surface them in `extras.policy_documents_found`.
 *   - Build a per-license summary (`extras.licenses_summary`) and a list of
 *     packages carrying viral / strong-copyleft licenses
 *     (`extras.risky_licenses`).
 *
 * The Findings carry the canonical compliance signal; the extras let the
 * model answer "do we have a privacy policy?" without parsing the report.
 *
 * Global Constraint 3 for the Semgrep pass, recorded as `semgrep-rgpd`:
 *
 *   - Semgrep absent: `skipped` (`not_installed`), and `semgrep` in
 *     `missing_tools` — the ONLY case that names `semgrep` there, because it
 *     is the only one where the reader's fix is "install semgrep".
 *   - A clean run that scanned no file, with the pack's rules LOADED
 *     (`--time` makes the report list them in `time.rules`): `skipped` with
 *     a "not applicable" reason and nothing in `missing_tools` — a Go-only
 *     project has nothing for the pack to read, exactly as a project with no
 *     Dockerfile has nothing for scan_containers (scanCoverage.ts). It used
 *     to list `semgrep` as missing, and the status dashboard then printed
 *     "MISSING semgrep — static-analysis findings are NOT in these numbers"
 *     beside a scan_sast that ran fine, and the CI gate "semgrep not
 *     installed" (full-review Task 20, fix round 1).
 *   - A clean run that scanned no file with NO rule loaded: `failed`. That is
 *     the silent-failure shape — `results: 0, scanned: 0, errors: 0` from a
 *     pack that did not load — and "nothing to read" cannot be told apart
 *     from it any other way.
 *   - A missing report, an abnormal exit or any entry in Semgrep's
 *     `errors[]` (a timeout, a file it could only partly parse): `failed`
 *     with the reason. The findings of a failed run are still kept: they are
 *     real, just not the whole answer.
 */
import { existsSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { resolveConfigsDir } from '../platform/configsDir.js';
import { semgrepExcludeArgs } from '../platform/guardianIgnore.js';
import { checkSemgrepReport, pythonUtf8Env } from '../runners/semgrepReport.js';
import { semgrepParser } from '../runners/scannerParsers/semgrep.js';
import { trivyParser } from '../runners/scannerParsers/trivy.js';
import { runProcess } from '../runners/processRunner.js';
import { Force, ProjectPath } from '../schemas.js';
import { asArray, getProp, getString, } from '../runners/scannerParsers/index.js';
import { registerToolModule } from './index.js';
import { ensureReportDir, readJsonSafe, scannerAvailable, } from './scanHelpers.js';
import { makeScanTool, } from './scanToolFactory.js';
/**
 * The RGPD rule pack, resolved from the plugin's own `configs/` — never from
 * `ctx.plugin.scriptsDir`, which tests (and unusual hosts) point elsewhere.
 */
export function rgpdRulesPath() {
    return join(resolveConfigsDir(), 'semgrep', 'rgpd.yml');
}
/** `rgpd-*` subcategory for a rule id, from the half of the pack it belongs to. */
export function rgpdSubcategory(ruleId) {
    const id = ruleId.split('.').pop() ?? ruleId;
    if (id.startsWith('rgpd-pii-in-log-'))
        return 'rgpd-pii-in-logs';
    if (id.startsWith('rgpd-tracker-') || id.startsWith('rgpd-youtube-'))
        return 'rgpd-tracker-without-consent';
    return undefined;
}
/**
 * The Semgrep parser, with every finding re-tagged as a compliance finding.
 * The fingerprint is untouched: it never depended on the category.
 */
const rgpdParser = {
    name: semgrepParser.name,
    parse(input, ctx) {
        const out = semgrepParser.parse(input, ctx);
        return {
            findings: out.findings.map((f) => {
                const subcategory = rgpdSubcategory(f.rule_id ?? '');
                return subcategory === undefined
                    ? { ...f, category: 'compliance' }
                    : { ...f, category: 'compliance', subcategory };
            }),
            cves: out.cves,
        };
    },
};
/**
 * How many rules the Semgrep report says it loaded (`time.rules`, present
 * with `--time`), or null when the report does not say. Entries are rule-id
 * strings in Semgrep 1.176 and objects in some older versions; either counts.
 */
export function loadedRuleCount(raw) {
    if (raw === null)
        return null;
    let root;
    try {
        root = JSON.parse(raw);
    }
    catch {
        return null;
    }
    const rules = getProp(getProp(root, 'time'), 'rules');
    return Array.isArray(rules) ? rules.length : null;
}
/** Runs the RGPD pack and records the outcome — see the module header for the verdicts. */
async function runRgpdPack(ctx, reportDir, out) {
    if (!(await scannerAvailable('semgrep'))) {
        out.tools_run.push({ name: 'semgrep-rgpd', status: 'skipped', reason: 'not_installed' });
        out.missing_tools.push('semgrep');
        return;
    }
    const pack = rgpdRulesPath();
    if (!existsSync(pack)) {
        out.tools_run.push({ name: 'semgrep-rgpd', status: 'failed', reason: `RGPD rule pack not found at ${pack}` });
        return;
    }
    const outFile = join(reportDir, 'rgpd.json');
    const result = await runProcess({
        command: 'semgrep',
        args: [
            `--config=${pack}`,
            '--metrics=off',
            // Lists the rules that loaded (`time.rules`): the only way to tell a
            // project with nothing to read from a pack that loaded nothing.
            '--time',
            ...semgrepExcludeArgs(ctx.exclusions),
            '--json',
            '--quiet',
            '--output',
            outFile,
            ctx.projectPath,
        ],
        cwd: ctx.projectPath,
        // UTF-8 mode: see runners/semgrepReport.ts.
        env: pythonUtf8Env(ctx.scriptEnv),
        signal: ctx.signal,
        onLog: ctx.onLog,
    });
    const raw = readJsonSafe(outFile);
    if (raw !== null)
        out.parser_inputs.push({ parser: rgpdParser, input: raw });
    const check = checkSemgrepReport({ raw, exitCode: result.exitCode, outcome: result.outcome, targets: 1 });
    if (check.ok) {
        out.tools_run.push({ name: 'semgrep-rgpd', status: 'ok' });
        return;
    }
    const exitClean = result.outcome === 'completed' || result.exitCode === 1;
    if (exitClean && raw !== null && check.scanned === 0 && check.errors === 0) {
        const loaded = loadedRuleCount(raw) ?? 0;
        if (loaded > 0) {
            // Not a gap, and so not in missing_tools: see the module header.
            out.tools_run.push({
                name: 'semgrep-rgpd',
                status: 'skipped',
                reason: 'not applicable: the RGPD pack loaded but found no file it reads here (JS/TS, PHP, Python, ' +
                    'C#, and HTML/JS/JSX/TSX/Vue/Twig/Razor/EJS/Handlebars templates)',
            });
            return;
        }
        out.tools_run.push({
            name: 'semgrep-rgpd',
            status: 'failed',
            reason: 'semgrep scanned 0 files and loaded no rule from the RGPD pack — a pack that failed to load, not a clean result',
        });
        return;
    }
    out.tools_run.push({ name: 'semgrep-rgpd', status: 'failed', reason: check.reason ?? 'semgrep failed' });
}
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
            let pkgs = byLicense.get(name);
            if (!pkgs) {
                pkgs = new Set();
                byLicense.set(name, pkgs);
            }
            pkgs.add(pkg);
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
    title: 'Compliance check (licenses + RGPD code rules + policy docs)',
    // Under 1500 characters (test/unit/pluginSurface/descriptionLimits.test.ts).
    description: 'Compliance scan of a project. (1) Trivy license scan: Findings for risky licenses, plus ' +
        '`licenses_summary` and `risky_licenses`. (2) The RGPD Semgrep pack configs/semgrep/rgpd.yml, ' +
        'offline (--metrics=off): Portuguese personal identifiers (NIF, NISS, Cartão de Cidadão, IBAN, ' +
        'phone, email — matched by variable/field NAME) inside log calls in JS/TS, PHP, Python and C# ' +
        '(subcategory rgpd-pii-in-logs), and trackers loaded by HTML/PHP/JS/JSX/TSX/Vue/Twig/Razor/EJS/' +
        'Handlebars markup before consent — GA4/gtag.js, Meta Pixel fbq init, Hotjar, youtube.com/embed ' +
        '(subcategory rgpd-tracker-without-consent). Consent guards: type="text/plain" scripts, a ' +
        'consent-checking block, JSX or template condition; Consent Mode v2 analytics_storage denied and ' +
        'fbq consent revoke are also accepted, as a documented legal judgement (the messages prescribe ' +
        'loading nothing before consent). Findings are category compliance, severity medium: name-based ' +
        'heuristics, not proof. (3) `policy_documents_found`: PRIVACY, TERMS, COOKIES, DPA, SECURITY, ' +
        'CODE_OF_CONDUCT near the project root. A missing or failed Trivy or Semgrep, or a Semgrep error ' +
        '(timeout, partial parse), lowers `coverage` — never a clean result; a project with no file the ' +
        'pack reads is not applicable (semgrep-rgpd skipped), not missing. ' +
        'Templates for the fixes: configs/compliance/cookie-banner/ and ' +
        'configs/compliance/privacy-policy-template.md.',
    scan_type: 'compliance',
    category: 'compliance',
    supportsAutoFix: false,
    inputSchema: {
        project_path: ProjectPath,
        force: Force,
    },
    // The pack's content joins the cache key: an edited rgpd.yml is a new scan.
    rulePacks: () => [rgpdRulesPath()],
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
        await runRgpdPack(ctx, reportDir, { tools_run, missing_tools, parser_inputs });
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