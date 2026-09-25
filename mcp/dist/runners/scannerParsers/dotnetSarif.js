/**
 * Roslyn SARIF 2.1 (`dotnet build -p:ErrorLog=<file>%2Cversion=2.1`) → the
 * SECURITY findings of a .NET build: the SDK's own analyzers enabled by
 * `-p:AnalysisModeSecurity=All` (CA2100, CA23xx, CA3xxx, CA5xxx — the rules
 * whose SARIF metadata says `category: Security`) and, when the project
 * references it, Security Code Scan (`SCS####`).
 *
 * Replaces scraping `dotnet build --verbosity:diag` stdout, which exceeded
 * the 5 MB output cap on real projects and killed the run. The SARIF is the
 * compiler's own structured record of every diagnostic it reported; it is
 * read per project (a relative ErrorLog path lands in each project's
 * directory — MSBuild does not expand `$(…)` in a global property, measured
 * on SDK 10.0.401).
 *
 * Everything that is not security — CS compiler warnings, CA performance or
 * style rules the project already reports — is left out: `scan_sast` is a
 * security scan, and `quality_check` owns the rest.
 */
import { fileURLToPath } from 'node:url';
import { asArray, getNumber, getProp, getString, makeFinding, parseInputAsJson, toRelativeIfPossible, } from './index.js';
import { SCS_TOOL_NAME } from './securityCodeScan.js';
/** Findings from the .NET SDK's built-in analyzers (`CA####`). */
export const DOTNET_ANALYZERS_TOOL_NAME = 'dotnet-analyzers';
/** Security-category rule ids, for a SARIF whose rule metadata is missing. */
const SECURITY_RULE_ID = /^(CA2100|CA23\d\d|CA3\d{3}|CA5\d{3})$/;
/**
 * Takes one SARIF document, or an ARRAY of them — every project and target
 * framework of one build. A multi-targeted project compiles the same source
 * once per framework and each SARIF carries the same result; they are one
 * finding, so a result is kept once per (rule, file, region) across the set
 * (Task 11 fix round 2: the copies became occurrences 0 and 1 — two findings
 * for one line).
 */
export const dotnetSarifParser = {
    name: DOTNET_ANALYZERS_TOOL_NAME,
    parse(input, ctx = {}) {
        const findings = [];
        const seen = new Set();
        for (const document of Array.isArray(input) ? input : [input]) {
            const root = parseInputAsJson(stripBom(document));
            for (const run of asArray(getProp(root, 'runs'))) {
                const categories = ruleCategories(run);
                for (const result of asArray(getProp(run, 'results'))) {
                    const key = resultKey(result);
                    if (seen.has(key))
                        continue;
                    seen.add(key);
                    const finding = mapResult(result, categories, ctx);
                    if (finding)
                        findings.push(finding);
                }
            }
        }
        return { findings, cves: [] };
    },
};
/** A result's rule, file and exact region — the same across target frameworks. */
function resultKey(result) {
    const physical = getProp(asArray(getProp(result, 'locations'))[0], 'physicalLocation');
    const region = getProp(physical, 'region');
    return JSON.stringify([
        getString(result, 'ruleId') ?? '',
        getString(getProp(physical, 'artifactLocation'), 'uri') ?? '',
        getNumber(region, 'startLine') ?? null,
        getNumber(region, 'startColumn') ?? null,
        getNumber(region, 'endLine') ?? null,
        getNumber(region, 'endColumn') ?? null,
    ]);
}
/**
 * How many security rules the SARIF says its analyzers loaded — rules whose
 * metadata category is `Security`, plus any Security Code Scan rule. Zero
 * means the security analyzers did not run at all (measured: a netstandard2.0
 * build without `EnableNETAnalyzers` lists none and reports nothing), which
 * must read as a gap, never as a clean project. Unparseable input counts 0.
 */
export function sarifSecurityRuleCount(input) {
    const root = parseInputAsJson(stripBom(input));
    let count = 0;
    for (const run of asArray(getProp(root, 'runs'))) {
        for (const rule of asArray(getProp(getProp(getProp(run, 'tool'), 'driver'), 'rules'))) {
            const id = getString(rule, 'id') ?? '';
            const category = getString(getProp(rule, 'properties'), 'category') ?? '';
            if (category.toLowerCase() === 'security' || /^SCS\d{4}$/.test(id))
                count += 1;
        }
    }
    return count;
}
function stripBom(input) {
    return typeof input === 'string' && input.charCodeAt(0) === 0xfeff ? input.slice(1) : input;
}
/** rule id → `properties.category`, from `tool.driver.rules[]`. */
function ruleCategories(run) {
    const out = new Map();
    for (const rule of asArray(getProp(getProp(getProp(run, 'tool'), 'driver'), 'rules'))) {
        const id = getString(rule, 'id');
        const category = getString(getProp(rule, 'properties'), 'category');
        if (id !== undefined && category !== undefined)
            out.set(id, category);
    }
    return out;
}
function mapResult(result, categories, ctx) {
    const ruleId = getString(result, 'ruleId');
    if (ruleId === undefined)
        return null;
    const isScs = /^SCS\d{4}$/.test(ruleId);
    const category = categories.get(ruleId);
    const isSecurity = isScs || (category !== undefined ? category.toLowerCase() === 'security' : SECURITY_RULE_ID.test(ruleId));
    if (!isSecurity)
        return null;
    // A diagnostic the project suppressed (`#pragma`, `[SuppressMessage]`) is
    // still written to the SARIF, with `suppressions`; it is not a finding.
    if (asArray(getProp(result, 'suppressions')).length > 0)
        return null;
    const message = getString(getProp(result, 'message'), 'text') ?? ruleId;
    const physical = getProp(asArray(getProp(result, 'locations'))[0], 'physicalLocation');
    const uri = getString(getProp(physical, 'artifactLocation'), 'uri');
    const region = getProp(physical, 'region');
    const lineStart = getNumber(region, 'startLine');
    const lineEnd = getNumber(region, 'endLine') ?? lineStart;
    const input = {
        tool: isScs ? SCS_TOOL_NAME : DOTNET_ANALYZERS_TOOL_NAME,
        rule_id: ruleId,
        severity: severityOf(getString(result, 'level')),
        category: 'security',
        subcategory: 'dotnet-security',
        title: message.length > 140 ? `${message.slice(0, 137)}…` : message,
        message,
        fix_available: false,
    };
    const file = uri === undefined ? undefined : filePathOf(uri);
    if (file !== undefined)
        input.file_path = toRelativeIfPossible(file, ctx.project_path);
    if (lineStart !== undefined)
        input.line_start = lineStart;
    if (lineEnd !== undefined)
        input.line_end = lineEnd;
    return makeFinding(input);
}
/** Same scale as the SCS log parser: an error is critical, a warning high. */
function severityOf(level) {
    switch (level) {
        case 'error':
            return 'critical';
        case 'warning':
            return 'high';
        case 'note':
            return 'medium';
        default:
            return 'low';
    }
}
function filePathOf(uri) {
    if (!uri.startsWith('file:'))
        return uri;
    try {
        return fileURLToPath(uri);
    }
    catch {
        return uri;
    }
}
//# sourceMappingURL=dotnetSarif.js.map