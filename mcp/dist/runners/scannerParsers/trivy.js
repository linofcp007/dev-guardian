/**
 * Trivy JSON output parser.
 *
 * One parser handles three Trivy modes (the JSON layouts overlap):
 *   - `trivy fs --scanners vuln,license` → Results[].Vulnerabilities[],
 *                                         Results[].Licenses[]
 *   - `trivy config Dockerfile`          → Results[].Misconfigurations[]
 *   - `trivy config <iac>`               → Results[].Misconfigurations[]
 *
 * Vulnerabilities additionally feed the `cves` table so the
 * `guardian://cves/active` resource can serve dedicated CVE queries
 * without re-deriving them from `findings`.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { asArray, getNumber, getProp, getString, makeFinding, normalizeSeverity, parseInputAsJson, toRelativeIfPossible, } from './index.js';
export const TRIVY_TOOL_NAME = 'trivy';
export const trivyParser = {
    name: TRIVY_TOOL_NAME,
    parse(input, ctx = {}) {
        const root = parseInputAsJson(input);
        const findings = [];
        const cves = [];
        for (const result of asArray(getProp(root, 'Results'))) {
            const target = getString(result, 'Target') ?? '';
            for (const v of asArray(getProp(result, 'Vulnerabilities'))) {
                const finding = mapVulnerability(v, target, ctx);
                if (finding)
                    findings.push(finding);
                const cve = mapVulnerabilityCve(v);
                if (cve)
                    cves.push(cve);
            }
            for (const l of asArray(getProp(result, 'Licenses'))) {
                const finding = mapLicense(l, target, ctx);
                if (finding)
                    findings.push(finding);
            }
            for (const m of asArray(getProp(result, 'Misconfigurations'))) {
                const finding = mapMisconfiguration(m, target, ctx);
                if (finding)
                    findings.push(finding);
            }
            for (const s of asArray(getProp(result, 'Secrets'))) {
                const finding = mapSecret(s, target, ctx);
                if (finding)
                    findings.push(finding);
            }
        }
        return { findings, cves };
    },
};
function mapVulnerability(raw, target, ctx) {
    const cveId = getString(raw, 'VulnerabilityID');
    const pkg = getString(raw, 'PkgName');
    if (!cveId || !pkg)
        return null;
    const severity = normalizeSeverity(getString(raw, 'Severity'));
    const title = getString(raw, 'Title') ?? `${cveId} in ${pkg}`;
    const installed = getString(raw, 'InstalledVersion');
    const fixed = getString(raw, 'FixedVersion');
    const description = getString(raw, 'Description');
    const input = {
        tool: TRIVY_TOOL_NAME,
        rule_id: cveId,
        severity,
        category: 'security',
        subcategory: 'cve',
        title,
        fix_available: fixed !== undefined && fixed.length > 0,
        file_path: toRelativeIfPossible(target, ctx.project_path),
    };
    if (description !== undefined)
        input.message = description;
    // Trivy "snippet" surrogate: enough package metadata to make the
    // fingerprint unique per (cve, package, installed_version) tuple.
    //
    // The `->fixed` half is also in the fingerprint, so the fingerprint changes
    // when the advisory database learns of a fix — the project did not change
    // at all. It stays, byte for byte, because suppressions and v1
    // `baseline.json` files from 2.0.x name these findings by that
    // fingerprint. The line-independent identity every cross-scan comparison
    // matches on first reads only `pkg@installed` out of this string
    // (`fingerprint/findingIdentity.ts#dependencyCoordinates`, which also
    // relies on the name ending at the LAST `@` before `->`): keep that shape.
    input.snippet = `${pkg}@${installed ?? ''}->${fixed ?? ''}`;
    return makeFinding(input);
}
function mapVulnerabilityCve(raw) {
    const cveId = getString(raw, 'VulnerabilityID');
    const pkg = getString(raw, 'PkgName');
    if (!cveId || !pkg)
        return null;
    const cve = {
        cve_id: cveId,
        package_name: pkg,
        severity: normalizeSeverity(getString(raw, 'Severity')),
    };
    const installed = getString(raw, 'InstalledVersion');
    if (installed !== undefined)
        cve.installed_version = installed;
    const fixed = getString(raw, 'FixedVersion');
    if (fixed !== undefined)
        cve.fixed_version = fixed;
    return cve;
}
function mapLicense(raw, target, ctx) {
    const pkg = getString(raw, 'PkgName');
    const license = getString(raw, 'Name');
    if (!license)
        return null;
    const severity = normalizeSeverity(getString(raw, 'Severity'));
    const title = `License '${license}' on ${pkg ?? target}`;
    const input = {
        tool: TRIVY_TOOL_NAME,
        rule_id: `license:${license}`,
        severity,
        category: 'license',
        subcategory: license.toLowerCase(),
        title,
        file_path: toRelativeIfPossible(target, ctx.project_path),
        snippet: pkg ? `pkg:${pkg}` : `license:${license}`,
    };
    return makeFinding(input);
}
function mapMisconfiguration(raw, target, ctx) {
    const id = getString(raw, 'ID') ?? getString(raw, 'AVDID');
    if (!id)
        return null;
    const severity = normalizeSeverity(getString(raw, 'Severity'));
    const title = getString(raw, 'Title') ?? id;
    const message = getString(raw, 'Description');
    const cause = getProp(raw, 'CauseMetadata');
    const lineStart = getNumber(cause, 'StartLine');
    const lineEnd = getNumber(cause, 'EndLine') ?? lineStart;
    const type = getString(raw, 'Type')?.toLowerCase();
    const category = 'security';
    const subcategory = type ?? 'misconfiguration';
    const input = {
        tool: TRIVY_TOOL_NAME,
        rule_id: id,
        severity,
        category,
        subcategory,
        title,
        file_path: toRelativeIfPossible(target, ctx.project_path),
    };
    if (message !== undefined)
        input.message = message;
    if (lineStart !== undefined)
        input.line_start = lineStart;
    if (lineEnd !== undefined)
        input.line_end = lineEnd;
    const fixHint = getString(raw, 'Resolution');
    if (fixHint !== undefined)
        input.snippet = fixHint;
    return makeFinding(input);
}
function mapSecret(raw, target, ctx) {
    const ruleId = getString(raw, 'RuleID') ?? getString(raw, 'Rule');
    if (!ruleId)
        return null;
    const severity = normalizeSeverity(getString(raw, 'Severity') ?? 'HIGH');
    const lineStart = getNumber(raw, 'StartLine');
    const lineEnd = getNumber(raw, 'EndLine') ?? lineStart;
    const input = {
        tool: TRIVY_TOOL_NAME,
        rule_id: ruleId,
        severity,
        category: 'security',
        subcategory: 'secret',
        title: getString(raw, 'Title') ?? ruleId,
        file_path: toRelativeIfPossible(target, ctx.project_path),
    };
    if (lineStart !== undefined)
        input.line_start = lineStart;
    if (lineEnd !== undefined)
        input.line_end = lineEnd;
    return makeFinding(input);
}
const ECOSYSTEM_MANIFESTS = [
    {
        ecosystem: 'npm',
        matches: (n) => n === 'package.json',
        trivyTypes: ['npm', 'yarn', 'pnpm', 'bun'],
        lockfiles: ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock'],
        declaresNothing: npmManifestDeclaresNothing,
    },
    { ecosystem: 'composer', matches: (n) => n === 'composer.json', trivyTypes: ['composer'], lockfiles: ['composer.lock'] },
    {
        ecosystem: 'dotnet',
        matches: (n) => /\.(csproj|sln)$/i.test(n),
        trivyTypes: ['nuget'],
        lockfiles: ['packages.lock.json', 'packages.config'],
    },
    { ecosystem: 'rubygems', matches: (n) => n === 'Gemfile', trivyTypes: ['bundler'], lockfiles: ['Gemfile.lock'] },
    { ecosystem: 'cargo', matches: (n) => n === 'Cargo.toml', trivyTypes: ['cargo'], lockfiles: ['Cargo.lock'] },
];
/** Every ecosystem the coverage check can report a gap for (`ManifestCoverageGap.ecosystem`). */
export const MANIFEST_ECOSYSTEMS = ECOSYSTEM_MANIFESTS.map((e) => e.ecosystem);
/** Each ecosystem with the lock file names Trivy reports its Results under. */
export const MANIFEST_ECOSYSTEM_LOCKFILES = ECOSYSTEM_MANIFESTS.map((e) => ({ ecosystem: e.ecosystem, lockfiles: e.lockfiles }));
/**
 * The ecosystem whose lock file a Trivy Result `Target` (a finding's
 * `file_path`) names, at any depth, or null — an OS package in an image, a
 * `go.mod`, a `requirements.txt`: nothing the coverage check reports on.
 */
export function manifestEcosystemOfTarget(target) {
    const base = target.slice(Math.max(target.lastIndexOf('/'), target.lastIndexOf('\\')) + 1).toLowerCase();
    const eco = ECOSYSTEM_MANIFESTS.find((e) => e.lockfiles.some((l) => l.toLowerCase() === base));
    return eco?.ecosystem ?? null;
}
/** npm dependency fields; `workspaces` because the members declare theirs. */
const NPM_DECLARING_FIELDS = [
    'dependencies',
    'devDependencies',
    'optionalDependencies',
    'peerDependencies',
    'bundleDependencies',
    'bundledDependencies',
    'workspaces',
];
/**
 * A `package.json` that parses to an object and whose every dependency field
 * (and `workspaces`) is absent, `{}` or `[]`. Anything else — a field with
 * entries, `bundleDependencies: true`, a manifest that does not parse — may
 * declare something, and stays a gap.
 */
function npmManifestDeclaresNothing(path) {
    let manifest;
    try {
        manifest = JSON.parse(readFileSync(path, 'utf8').replace(/^\uFEFF/, ''));
    }
    catch {
        return false;
    }
    if (typeof manifest !== 'object' || manifest === null || Array.isArray(manifest))
        return false;
    const fields = manifest;
    return NPM_DECLARING_FIELDS.every((k) => {
        const v = fields[k];
        if (v === undefined)
            return true;
        if (Array.isArray(v))
            return v.length === 0;
        return typeof v === 'object' && v !== null && Object.keys(v).length === 0;
    });
}
/**
 * Assess whether Trivy's fs-scan output covers every dependency manifest
 * actually present at the project's top level. Only the project ROOT is
 * checked — same shallow scope as `license_compatibility`'s manifest
 * detection — because a manifest buried in a subdirectory (a monorepo
 * package) is Trivy's own concern to find or not; this only detects the
 * specific silent gap described above (manifest present, lockfile absent,
 * `Results` never mentions it).
 */
export function assessManifestCoverage(projectPath, rawTrivyOutput) {
    let entries;
    try {
        entries = readdirSync(projectPath);
    }
    catch {
        return { gaps: [], sawAnyResults: false };
    }
    const root = parseInputAsJson(rawTrivyOutput);
    const results = asArray(getProp(root, 'Results'));
    const coveredTypes = new Set();
    for (const result of results) {
        const type = getString(result, 'Type');
        if (type)
            coveredTypes.add(type);
    }
    const gaps = [];
    for (const eco of ECOSYSTEM_MANIFESTS) {
        const files = entries.filter((n) => eco.matches(n) && !(eco.declaresNothing?.(join(projectPath, n)) ?? false));
        if (files.length === 0)
            continue;
        const covered = eco.trivyTypes.some((t) => coveredTypes.has(t));
        if (!covered)
            gaps.push({ ecosystem: eco.ecosystem, files });
    }
    return { gaps, sawAnyResults: results.length > 0 };
}
//# sourceMappingURL=trivy.js.map