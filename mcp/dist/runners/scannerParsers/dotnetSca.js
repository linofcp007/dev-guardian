/**
 * `dotnet list <target> package --vulnerable --include-transitive --format
 * json` output parser.
 *
 * Schema (.NET SDK 8+; confirmed against 10.0.401):
 *
 *   { "version": 1, "parameters": "--vulnerable --include-transitive",
 *     "projects": [
 *       { "path": "…/Test.csproj", "frameworks": [
 *           { "framework": "net8.0",
 *             "topLevelPackages": [
 *               { "id": "Newtonsoft.Json", "requestedVersion": "12.0.1",
 *                 "resolvedVersion": "12.0.1",
 *                 "vulnerabilities": [
 *                   { "severity": "High",
 *                     "advisoryurl": "https://github.com/advisories/GHSA-…" }
 *                 ] }
 *             ],
 *             "transitivePackages": [ (same per-package shape, no
 *                requestedVersion) ] }
 *       ] }
 *     ] }
 *
 * `transitivePackages` (documented by `dotnet list package`, same shape as
 * `--outdated --include-transitive`'s own array in `depsUpdatePlan.ts`) is
 * only present on a framework object that actually has a vulnerable
 * transitive dependency; both arrays are read the same way here.
 *
 * There is no CVE id in this output — only an advisory URL and a severity
 * label. The last path segment of a GitHub Security Advisory URL (a GHSA
 * id) becomes `rule_id`; no `cves[]` row is emitted, the same choice
 * `npmAudit.ts` makes for its own v2 (GHSA-only) advisories — Trivy remains
 * the canonical CVE source across stacks.
 */
import { asArray, DEPENDENCY_CWE, getProp, getString, makeFinding, normalizeSeverity, parseInputAsJson, toRelativeIfPossible, } from './index.js';
export const DOTNET_SCA_TOOL_NAME = 'dotnet-list-package';
export const dotnetScaParser = {
    name: DOTNET_SCA_TOOL_NAME,
    parse(input, ctx = {}) {
        const root = parseInputAsJson(input);
        const findings = [];
        for (const project of asArray(getProp(root, 'projects'))) {
            const projectPath = getString(project, 'path') ?? '';
            for (const fw of asArray(getProp(project, 'frameworks'))) {
                const framework = getString(fw, 'framework') ?? '';
                const packages = [
                    ...asArray(getProp(fw, 'topLevelPackages')),
                    ...asArray(getProp(fw, 'transitivePackages')),
                ];
                for (const pkg of packages) {
                    findings.push(...mapPackage(pkg, projectPath, framework, ctx));
                }
            }
        }
        return { findings, cves: [] };
    },
};
function mapPackage(raw, projectPath, framework, ctx) {
    const id = getString(raw, 'id');
    if (!id)
        return [];
    const resolved = getString(raw, 'resolvedVersion');
    const relPath = toRelativeIfPossible(projectPath, ctx.project_path);
    const out = [];
    for (const vuln of asArray(getProp(raw, 'vulnerabilities'))) {
        const severity = normalizeSeverity(getString(vuln, 'severity'));
        const url = getString(vuln, 'advisoryurl');
        const ruleId = url ? advisoryIdFromUrl(url) : `${id}@${resolved ?? ''}`;
        const findingInput = {
            tool: DOTNET_SCA_TOOL_NAME,
            rule_id: ruleId,
            severity,
            category: 'security',
            subcategory: 'dependency',
            title: `Vulnerable NuGet package '${id}'${resolved ? ` ${resolved}` : ''} (${framework})`,
            fix_available: false,
            file_path: relPath,
            snippet: `${id}@${resolved ?? ''}`,
            taxonomy: { cwe: [DEPENDENCY_CWE] },
        };
        if (url !== undefined)
            findingInput.message = url;
        out.push(makeFinding(findingInput));
    }
    return out;
}
function advisoryIdFromUrl(url) {
    const m = /\/advisories\/([A-Za-z0-9-]+)/i.exec(url);
    return m?.[1] ?? url;
}
//# sourceMappingURL=dotnetSca.js.map