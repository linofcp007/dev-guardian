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
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { asArray, dependencyTaxonomy, getNumber, getProp, getString, makeFinding, SECRET_CWE, normalizeSeverity, parseInputAsJson, toRelativeIfPossible, } from './index.js';
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
        // A vulnerable dependency is CWE-1395 and A03 whatever the flaw inside
        // it; the advisory's own CweIDs name that flaw, in `cwe` only.
        taxonomy: dependencyTaxonomy(asArray(getProp(raw, 'CweIDs'))),
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
        taxonomy: { cwe: [SECRET_CWE] },
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
        fix: 'commit the lock file your package manager writes (package-lock.json, yarn.lock, pnpm-lock.yaml or bun.lock)',
    },
    {
        ecosystem: 'composer',
        matches: (n) => n === 'composer.json',
        trivyTypes: ['composer'],
        lockfiles: ['composer.lock'],
        fix: 'commit composer.lock (composer update writes it)',
    },
    {
        ecosystem: 'dotnet',
        matches: (n) => /\.(csproj|sln)$/i.test(n),
        trivyTypes: ['nuget'],
        lockfiles: ['packages.lock.json', 'packages.config'],
        fix: 'set RestorePackagesWithLockFile to true, run dotnet restore and commit packages.lock.json',
    },
    {
        ecosystem: 'rubygems',
        matches: (n) => n === 'Gemfile',
        trivyTypes: ['bundler'],
        lockfiles: ['Gemfile.lock'],
        fix: 'commit Gemfile.lock (bundle lock writes it)',
    },
    {
        ecosystem: 'cargo',
        matches: (n) => n === 'Cargo.toml',
        trivyTypes: ['cargo'],
        lockfiles: ['Cargo.lock'],
        fix: 'commit Cargo.lock (cargo generate-lockfile writes it)',
    },
    {
        ecosystem: 'gradle',
        matches: (n) => n === 'build.gradle' || n === 'build.gradle.kts',
        trivyTypes: ['gradle'],
        lockfiles: ['gradle.lockfile'],
        // `--write-locks` writes nothing until locking is switched on in the build.
        fix: 'enable dependencyLocking { lockAllConfigurations() } in the build, then run ' +
            'gradle dependencies --write-locks and commit gradle.lockfile',
    },
    {
        ecosystem: 'python',
        matches: (n) => n === 'pyproject.toml' ||
            n === 'Pipfile' ||
            n === 'setup.py' ||
            n === 'setup.cfg' ||
            /^requirements.*\.txt$/i.test(n),
        trivyTypes: ['pip', 'pipenv', 'poetry', 'uv'],
        lockfiles: ['requirements.txt', 'Pipfile.lock', 'poetry.lock', 'uv.lock'],
        declaresNothing: pythonManifestDeclaresNothing,
        fix: 'commit poetry.lock, uv.lock or Pipfile.lock (poetry lock, uv lock, pipenv lock), ' +
            'or pin every dependency (==) in requirements.txt',
    },
];
/** Every ecosystem the coverage check can report a gap for (`ManifestCoverageGap.ecosystem`). */
export const MANIFEST_ECOSYSTEMS = ECOSYSTEM_MANIFESTS.map((e) => e.ecosystem);
/** How to give Trivy a file it reads for `ecosystem`, or null for one this table does not know. */
export function lockFileAdvice(ecosystem) {
    return ECOSYSTEM_MANIFESTS.find((e) => e.ecosystem === ecosystem)?.fix ?? null;
}
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
/** `undefined`, `{}` and `[]`; anything else (`null`, `true`, entries) may hold something. */
function isEmptyField(v) {
    if (v === undefined)
        return true;
    if (Array.isArray(v))
        return v.length === 0;
    return typeof v === 'object' && v !== null && Object.keys(v).length === 0;
}
/** Parsed JSON, BOM tolerated, or `undefined` when the file does not parse. */
function readJsonFile(path) {
    try {
        return JSON.parse(readFileSync(path, 'utf8').replace(/^\uFEFF/, ''));
    }
    catch {
        return undefined;
    }
}
/** Root npm lock files this code reads: they lock nothing when every `packages` key is the root (`''`) and v1's `dependencies` is empty. */
const NPM_JSON_LOCKFILES = ['package-lock.json', 'npm-shrinkwrap.json'];
/** Root npm lock files this code does not read: present, each may lock something. */
const NPM_UNREAD_LOCKFILES = ['pnpm-lock.yaml', 'bun.lock', 'bun.lockb'];
/**
 * Whether every npm lock file at the root of `dir` is absent or locks
 * nothing. A lock file that does not parse, or one this code does not read,
 * may lock something: see the module comment on this exclusion's boundary.
 */
function npmLockFilesLockNothing(dir) {
    for (const name of NPM_UNREAD_LOCKFILES)
        if (existsSync(join(dir, name)))
            return false;
    for (const name of NPM_JSON_LOCKFILES) {
        const path = join(dir, name);
        if (!existsSync(path))
            continue;
        const lock = readJsonFile(path);
        if (typeof lock !== 'object' || lock === null || Array.isArray(lock))
            return false;
        const { packages, dependencies } = lock;
        if (packages !== undefined) {
            if (typeof packages !== 'object' || packages === null || Array.isArray(packages))
                return false;
            if (Object.keys(packages).some((k) => k !== ''))
                return false;
        }
        if (!isEmptyField(dependencies))
            return false;
    }
    const yarnLock = join(dir, 'yarn.lock');
    if (existsSync(yarnLock)) {
        let text;
        try {
            text = readFileSync(yarnLock, 'utf8');
        }
        catch {
            return false;
        }
        // Only the `# ...` header and blank lines: what yarn writes with nothing to lock.
        if (text.split(/\r?\n/).some((line) => line.trim() !== '' && !line.trimStart().startsWith('#')))
            return false;
    }
    return true;
}
/**
 * A `package.json` that parses to an object, whose every dependency field
 * (and `workspaces`) is absent, `{}` or `[]`, and beside which no root lock
 * file locks anything. Anything else (a field with entries,
 * `bundleDependencies: true`, a manifest that does not parse, a stale lock
 * file still locking packages) may declare something, and stays a gap.
 */
function npmManifestDeclaresNothing(path) {
    const manifest = readJsonFile(path);
    if (typeof manifest !== 'object' || manifest === null || Array.isArray(manifest))
        return false;
    const fields = manifest;
    return NPM_DECLARING_FIELDS.every((k) => isEmptyField(fields[k])) && npmLockFilesLockNothing(dirname(path));
}
/** A TOML value that is literally empty: `[]` or `{}`, an optional trailing comment. */
const EMPTY_TOML_VALUE = /^(\[\s*\]|\{\s*\})\s*(#.*)?$/;
/** Key names that declare dependencies in whatever table they sit in (setuptools' dynamic ones included). */
const PY_DEPENDENCY_KEYS = new Set(['dependencies', 'optional-dependencies', 'dev-dependencies']);
/** Tables whose every key is a dependency (Poetry's `python` constraint aside). */
const PY_DEPENDENCY_TABLES = /^(project\.optional-dependencies(\..+)?|dependency-groups|tool\.poetry\.(dependencies|dev-dependencies|group\.[^.]+\.dependencies)|tool\.pdm\.dev-dependencies|packages|dev-packages)$/;
/**
 * Python's "declares nothing" — nothing Trivy could have missed, so no gap:
 * a `requirements*.txt` with no line but blanks and comments; a `setup.py`
 * / `setup.cfg` that never mentions `install_requires` / `extras_require`;
 * a `Pipfile` with no entry under `[packages]` / `[dev-packages]`; a `pyproject.toml`
 * that declares no dependency — the common tool-config-only file (`[tool.ruff]`,
 * `[build-system]`), or a `[project]` without `dependencies`. Read line by
 * line, conservatively: a dependency key whose value is not literally `[]` /
 * `{}` (a multi-line array included), an entry in a dependency table
 * (Poetry's lone `python` constraint aside), a table header this reader
 * cannot parse, or a file it cannot read — each may declare something, and
 * stays a gap.
 */
function pythonManifestDeclaresNothing(path) {
    let text;
    try {
        text = readFileSync(path, 'utf8').replace(/^﻿/, '');
    }
    catch {
        return false;
    }
    const lines = text
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => l !== '' && !l.startsWith('#'));
    if (/\.txt$/i.test(path))
        return lines.length === 0;
    // setuptools: Trivy reads neither file. `install_requires` / `extras_require`
    // anywhere (a keyword argument in setup.py, a key or an
    // `[options.extras_require]` section in setup.cfg) may declare something.
    if (/(^|[\\/])setup\.py$/i.test(path))
        return !/\b(install_requires|extras_require)\b/.test(text);
    if (/(^|[\\/])setup\.cfg$/i.test(path)) {
        return !/^\s*(install_requires|extras_require)\s*=/m.test(text) && !/^\s*\[options\.extras_require\]/m.test(text);
    }
    let table = '';
    for (const line of lines) {
        if (line.startsWith('[')) {
            const header = /^\[\[?\s*([^\]]+?)\s*\]\]?\s*(#.*)?$/.exec(line);
            if (header?.[1] === undefined)
                return false;
            table = header[1].replace(/["'\s]/g, '');
            continue;
        }
        const kv = /^["']?([A-Za-z0-9_.-]+)["']?\s*=\s*(.*)$/.exec(line);
        // Not a key: the continuation of a value whose key was already judged.
        if (kv?.[1] === undefined || kv[2] === undefined)
            continue;
        const key = kv[1];
        const empty = EMPTY_TOML_VALUE.test(kv[2]);
        const lastSegment = key.slice(key.lastIndexOf('.') + 1);
        if (PY_DEPENDENCY_KEYS.has(lastSegment) && !empty)
            return false;
        if (PY_DEPENDENCY_TABLES.test(table) && !empty && !(table.startsWith('tool.poetry.') && key === 'python')) {
            return false;
        }
    }
    return true;
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