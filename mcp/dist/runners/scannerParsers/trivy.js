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
 *
 * The manifest-coverage check reads the scanned repository's manifests,
 * lock files and workspace declarations, every one through
 * `platform/projectFs.ts` (review of 3.0, W2E): a `yarn.lock` linked to
 * `/dev/zero` OOM-killed the MCP server. A file that is refused reads as
 * "may declare something" — the conservative answer — so a manifest it
 * belongs to stays a gap, named.
 */
import { dirname, join, relative, sep } from 'node:path';
import { parseYamlBounded } from '../../platform/boundedParse.js';
import { listProjectDirOrNull, presentInProject, PROJECT_FILE_MAX_BYTES, linkNotFollowed, ReadBudget, } from '../../platform/projectFs.js';
import { textLines } from '../../platform/textLines.js';
import { PROJECT_WALK_EXCLUDE, SCANNER_WALK_EXCLUDE } from '../projectFiles.js';
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
    // The advisory's other ids as Trivy's database gives them (the GHSA id of
    // a CVE, for a language package) — never the CVEs its description names.
    input.vuln_aliases = asArray(getProp(raw, 'VendorIDs'));
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
        declaresOnlyDev: npmManifestDeclaresOnlyDev,
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
        // A project file, never a `.sln`: a solution only lists projects, and the
        // walk judges each of them in its own directory — where its
        // packages.lock.json is (review I1). Judged at the solution's directory,
        // every solution with its projects below it would read as a gap.
        matches: (n) => /\.(csproj|fsproj|vbproj)$/i.test(n),
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
    {
        // Trivy reads go.mod itself (measured on 0.69.3: a `gomod` Result for a
        // go.mod with or without `require` lines). One it cannot parse gets no
        // Result at all — `Number of language-specific files num=0`, exit 0 —
        // which used to read full (review I1).
        ecosystem: 'go',
        matches: (n) => n === 'go.mod',
        trivyTypes: ['gomod'],
        lockfiles: ['go.mod', 'go.sum'],
        fix: 'Trivy read nothing from it: make go.mod parse (go mod tidy reports why it does not) and re-run',
    },
];
/** Every ecosystem the coverage check can report a gap for (`ManifestCoverageGap.ecosystem`). */
export const MANIFEST_ECOSYSTEMS = ECOSYSTEM_MANIFESTS.map((e) => e.ecosystem);
/** How to give Trivy a file it reads for `ecosystem`, or null for one this table does not know. */
export function lockFileAdvice(ecosystem) {
    return ECOSYSTEM_MANIFESTS.find((e) => e.ecosystem === ecosystem)?.fix ?? null;
}
/**
 * Why a `ManifestCoverageGap.dev_only` manifest has no Result: its lock file
 * was there, and Trivy skips dev dependencies by default (measured on 0.69.3:
 * a lock holding only `dev: true` packages gets no Result; `--include-dev-deps`
 * brings it back, and dev-guardian does not pass it).
 */
export const DEV_ONLY_ADVICE = 'only devDependencies, which Trivy skips by default';
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
// ---------------------------------------------------------------- bounded reads
//
// Review of 3.0, W2E: a cap on bytes READ is not a bound on memory. A 30 MiB
// `yarn.lock` of newlines, under the 64 MiB lock-file cap, became a
// 31-million-string array in `.split(/\r?\n/)` and hit the heap limit; a
// 30 MiB `package-lock.json` of `[{},{},…]` took `JSON.parse` past 768 MB (60
// MiB: 1.35 GB of heap and a 20 s synchronous block). What coverage needs
// from those files is tiny — does the lock lock anything, does the manifest
// declare anything, which members a workspace names — so:
//
//   - text is scanned line by line (`platform/textLines.ts`), never split;
//   - JSON and YAML are parsed only under small caps of their own: a lock
//     that locks nothing is a few hundred bytes, a manifest that declares
//     nothing or a workspace declaration a few KB. Above the cap the file is
//     not parsed, and the answer is the conservative one — it "may declare
//     something", so the manifest stays a named gap;
//   - one {@link ReadBudget} covers the whole assessment, and a workspace
//     declaration is read once per directory, not once per member;
//   - a workspace pattern is compiled only when short and simple — a
//     repository's `**a**a**…` would otherwise backtrack for ever on a
//     member's path.
/** `package.json` is parsed up to this size; a real one is a few KB. */
const MANIFEST_JSON_PARSE_MAX = 1024 * 1024;
/** A lock file is parsed only to learn it locks nothing — such a lock is a few hundred bytes. */
const LOCK_PARSE_MAX = 256 * 1024;
/** `yarn.lock` is scanned only to learn it holds nothing but its `#` header. */
const YARN_LOCK_SCAN_MAX = 64 * 1024;
/** A workspace declaration in YAML (`pnpm-workspace.yaml`). */
const WORKSPACE_YAML_MAX = 256 * 1024;
/** A TOML manifest read for a workspace table or a dependency key, line by line. */
const TOML_SCAN_MAX = 1024 * 1024;
/** What the whole assessment may read. */
export const COVERAGE_BUDGET_BYTES = 64 * 1024 * 1024;
export const COVERAGE_BUDGET_FILES = 5_000;
/** Workspace patterns considered per declaration, their length, and their wildcards. */
const MAX_WORKSPACE_PATTERNS = 1_000;
const MAX_WORKSPACE_PATTERN_LENGTH = 256;
const MAX_WORKSPACE_PATTERN_STARS = 6;
/** A project file's text within the budget and `maxBytes`, or null when it is absent or was refused. */
function readText(r, path, maxBytes) {
    const read = r.budget.readText(r.root, path, maxBytes);
    return read.status === 'ok' ? read.text : null;
}
/** Parsed JSON under `maxBytes`, or `undefined`: absent, refused, too large to parse, or not JSON. */
function readJsonFile(r, path, maxBytes) {
    const text = readText(r, path, maxBytes);
    if (text === null)
        return undefined;
    try {
        return JSON.parse(text);
    }
    catch {
        return undefined;
    }
}
/** Anything at `path` — a dangling link, a FIFO included — judged without following a link. */
function present(r, path) {
    return presentInProject(r.root, path);
}
/** Root npm lock files this code reads: they lock nothing when every `packages` key is the root (`''`) and v1's `dependencies` is empty. */
const NPM_JSON_LOCKFILES = ['package-lock.json', 'npm-shrinkwrap.json'];
/** Root npm lock files this code does not read: present, each may lock something. */
const NPM_UNREAD_LOCKFILES = ['pnpm-lock.yaml', 'bun.lock', 'bun.lockb'];
/**
 * Whether every npm lock file at the root of `dir` is absent or locks
 * nothing. A lock file that does not parse, is larger than a lock locking
 * nothing ever is, or is one this code does not read, may lock something:
 * see the module comment on this exclusion's boundary.
 */
function npmLockFilesLockNothing(r, dir) {
    for (const name of NPM_UNREAD_LOCKFILES)
        if (present(r, join(dir, name)))
            return false;
    for (const name of NPM_JSON_LOCKFILES) {
        const path = join(dir, name);
        if (!present(r, path))
            continue;
        const lock = readJsonFile(r, path, LOCK_PARSE_MAX);
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
    if (present(r, yarnLock)) {
        const text = readText(r, yarnLock, YARN_LOCK_SCAN_MAX);
        if (text === null)
            return false;
        // Only the `# ...` header and blank lines: what yarn writes with nothing to lock.
        for (const line of textLines(text))
            if (line.trim() !== '' && !line.trimStart().startsWith('#'))
                return false;
    }
    return true;
}
/**
 * A `package.json` that parses to an object, whose every dependency field
 * (and `workspaces`) is absent, `{}` or `[]`, and beside which no root lock
 * file locks anything. Anything else (a field with entries,
 * `bundleDependencies: true`, a manifest that does not parse or is too large
 * to, a stale lock file still locking packages) may declare something, and
 * stays a gap.
 */
function npmManifestDeclaresNothing(r, path) {
    const manifest = readJsonFile(r, path, MANIFEST_JSON_PARSE_MAX);
    if (typeof manifest !== 'object' || manifest === null || Array.isArray(manifest))
        return false;
    const fields = manifest;
    return NPM_DECLARING_FIELDS.every((k) => isEmptyField(fields[k])) && npmLockFilesLockNothing(r, dirname(path));
}
/**
 * A `package.json` that parses to an object with no production dependency
 * (every field but `devDependencies` and `workspaces` absent, `{}` or `[]`)
 * and `devDependencies` or `workspaces` with entries — all it locks itself
 * is what Trivy skips by default. A workspace root with no Result of its
 * own is one whose members lock nothing else either: a member's production
 * dependency is in the root's lock file, and Trivy reports that file.
 */
function npmManifestDeclaresOnlyDev(r, path) {
    const manifest = readJsonFile(r, path, MANIFEST_JSON_PARSE_MAX);
    if (typeof manifest !== 'object' || manifest === null || Array.isArray(manifest))
        return false;
    const fields = manifest;
    return (NPM_DECLARING_FIELDS.every((k) => k === 'devDependencies' || k === 'workspaces' || isEmptyField(fields[k])) &&
        (!isEmptyField(fields['devDependencies']) || !isEmptyField(fields['workspaces'])));
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
function pythonManifestDeclaresNothing(r, path) {
    // Refused (a link out, a FIFO, over the cap, past the budget): it may declare something.
    const text = readText(r, path, PROJECT_FILE_MAX_BYTES);
    if (text === null)
        return false;
    const meaningful = function* () {
        for (const raw of textLines(text)) {
            const line = raw.trim();
            if (line !== '' && !line.startsWith('#'))
                yield line;
        }
    };
    if (/\.txt$/i.test(path))
        return meaningful().next().done === true;
    // setuptools: Trivy reads neither file. `install_requires` / `extras_require`
    // anywhere (a keyword argument in setup.py, a key or an
    // `[options.extras_require]` section in setup.cfg) may declare something.
    if (/(^|[\\/])setup\.py$/i.test(path))
        return !/\b(install_requires|extras_require)\b/.test(text);
    if (/(^|[\\/])setup\.cfg$/i.test(path)) {
        return !/^\s*(install_requires|extras_require)\s*=/m.test(text) && !/^\s*\[options\.extras_require\]/m.test(text);
    }
    let table = '';
    for (const line of meaningful()) {
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
/** The ceiling detect_stack's manifest walk and the project-languages walk use. */
const MAX_MANIFEST_WALK_DIRS = 20_000;
/** The directory part of a `/`- or `\`-separated path, `/`-separated (`''` at the top). */
function dirOf(path) {
    const posix = path.replace(/\\/g, '/').replace(/^\.\//, '');
    const i = posix.lastIndexOf('/');
    return i < 0 ? '' : posix.slice(0, i);
}
/**
 * Every manifest of a {@link ECOSYSTEM_MANIFESTS} ecosystem under the
 * project, bounded: the directories no scan of the project's own files
 * reads (`node_modules`, `vendor`, build output, virtualenvs, caches — the
 * `PROJECT_WALK_EXCLUDE` every other walk uses), `SCANNER_WALK_EXCLUDE`
 * (version control, package-manager caches, bower's and jspm's dependency
 * directories) and `.guardianignore` entries are not entered, and at most
 * `maxDirs` directories are read.
 *
 * Every other hidden directory IS walked (round 4, item 4): Trivy reads
 * them, and a GitHub composite action's `.github/actions/notify/
 * package.json` with no lock read full while the walk skipped `.github`.
 * Examples, docs and fixtures are walked too — whether one ships is the
 * project's to say, in `.guardianignore` (the coverage warning says so).
 *
 * A manifest's NAME is what counts (review of 3.0, W2E): a `package.json`
 * that is a link or a FIFO is found, and — unread — may declare something,
 * so without a Result it is a gap; it used to be skipped as "not a file" and
 * read clean. A directory link is not followed; one that leads out of the
 * project (or cannot be resolved) makes the walk incomplete, naming it.
 */
function walkManifests(projectPath, opts) {
    const maxDirs = opts.maxDirs ?? MAX_MANIFEST_WALK_DIRS;
    const ignores = opts.ignores ?? null;
    const found = [];
    const stack = [''];
    let visited = 0;
    let rootRead = false;
    const unreadable = [];
    const linksOut = [];
    while (stack.length > 0) {
        const rel = stack.pop();
        if (rel === undefined)
            break;
        if (visited >= maxDirs) {
            return { found, incomplete: `the manifest walk stopped after ${maxDirs} directories` };
        }
        visited += 1;
        const abs = rel === '' ? projectPath : join(projectPath, ...rel.split('/'));
        const entries = listProjectDirOrNull(projectPath, abs);
        if (entries === null) {
            if (rel === '')
                return null;
            unreadable.push(`${rel}/`);
            continue;
        }
        if (rel === '')
            rootRead = true;
        for (const e of entries) {
            const child = rel === '' ? e.name : `${rel}/${e.name}`;
            if (e.kind === 'directory' || e.kind === 'link') {
                if (PROJECT_WALK_EXCLUDE.has(e.name) || SCANNER_WALK_EXCLUDE.has(e.name))
                    continue;
                if (ignores !== null && ignores(child, true))
                    continue;
            }
            if (e.kind === 'directory') {
                stack.push(child);
                continue;
            }
            const eco = ECOSYSTEM_MANIFESTS.find((m) => m.matches(e.name));
            if (eco !== undefined) {
                if (ignores !== null && ignores(child, false))
                    continue;
                found.push({ rel: child, dir: rel, abs: join(abs, e.name), eco });
                continue;
            }
            const out = e.kind === 'link' ? linkNotFollowed(projectPath, join(abs, e.name)) : null;
            if (out !== null)
                linksOut.push(`${child}${out.kind === 'directory' ? '/' : ''} (${out.says})`);
        }
    }
    if (!rootRead)
        return null;
    const parts = [];
    if (unreadable.length > 0) {
        const shown = unreadable.slice(0, 3).join(', ');
        parts.push(`could not read ${shown}${unreadable.length > 3 ? ` and ${unreadable.length - 3} more` : ''}`);
    }
    if (linksOut.length > 0) {
        const shown = linksOut.slice(0, 3).join(', ');
        parts.push(`did not follow ${shown}${linksOut.length > 3 ? ` and ${linksOut.length - 3} more` : ''}`);
    }
    return parts.length > 0 ? { found, incomplete: parts.join('; ') } : { found };
}
// ---------------------------------------------------------------- workspaces
//
// A workspace member has no lock file of its own: the workspace root's lock
// file locks it, and Trivy reports that one file (`package-lock.json`,
// `Cargo.lock`, `uv.lock`, measured on 0.69.3 for npm). So a member is
// covered by a Result of its ecosystem at an ancestor that DECLARES it a
// member — never by any ancestor's lock: a root lock file says nothing about
// a separate project below it that has none (the reproduction). Only what
// the root declares counts: npm / yarn `workspaces` (an array, or
// `{ packages: [...] }`), `pnpm-workspace.yaml` `packages`, Cargo
// `[workspace] members` / `exclude`, uv `[tool.uv.workspace] members` /
// `exclude`. Gradle and .NET lock per project, so no workspace applies.
/** A workspace glob, relative to its root: `*` one segment, `**` any depth. Null: not one this code compiles. */
function workspaceGlob(pattern) {
    const p = pattern.trim().replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/+$/, '');
    if (p === '' || p.startsWith('/') || p.split('/').includes('..'))
        return null;
    // Bounded: a long pattern, or one with many wildcards, backtracks without
    // end on a member's path. Such a pattern declares no member here — the
    // member stays a gap, the conservative answer.
    if (p.length > MAX_WORKSPACE_PATTERN_LENGTH || (p.match(/\*/g) ?? []).length > MAX_WORKSPACE_PATTERN_STARS)
        return null;
    let re = '';
    for (let i = 0; i < p.length; i++) {
        const c = p.charAt(i);
        if (c === '*') {
            if (p.charAt(i + 1) === '*') {
                re += '.*';
                i += 1;
            }
            else {
                re += '[^/]*';
            }
        }
        else if (c === '?') {
            re += '[^/]';
        }
        else {
            re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
        }
    }
    return new RegExp(`^${re}$`);
}
/** The quoted strings of a TOML array `key = [ … ]` inside `table` (possibly multi-line), line by line. */
function tomlArrayIn(text, table, key) {
    const keyRe = new RegExp(`^${key}\\s*=\\s*(\\[.*)$`);
    let inTable = false;
    let collecting = false;
    let buf = '';
    for (const raw of textLines(text)) {
        const line = raw.replace(/#.*$/, '').trim();
        if (!collecting && line.startsWith('[')) {
            const header = /^\[\s*([^\]]+?)\s*\]$/.exec(line);
            inTable = header?.[1]?.replace(/["'\s]/g, '') === table;
            continue;
        }
        if (!inTable)
            continue;
        if (!collecting) {
            const m = keyRe.exec(line);
            if (m?.[1] === undefined)
                continue;
            collecting = true;
            buf = m[1];
        }
        else {
            buf += ` ${line}`;
        }
        if (buf.includes(']')) {
            const items = [];
            for (const x of buf.matchAll(/"([^"]*)"|'([^']*)'/g)) {
                items.push(x[1] ?? x[2] ?? '');
                if (items.length >= MAX_WORKSPACE_PATTERNS)
                    break;
            }
            return items;
        }
        // An array that never closes within the read: not a declaration this code can read.
        if (buf.length > TOML_SCAN_MAX)
            return null;
    }
    return null;
}
/** Compiled include/exclude patterns, or null when none includes anything. */
function compileDecl(include, exclude) {
    const compile = (ps) => ps.slice(0, MAX_WORKSPACE_PATTERNS).flatMap((p) => {
        const re = workspaceGlob(p);
        return re === null ? [] : [re];
    });
    const inc = compile(include);
    return inc.length > 0 ? { include: inc, exclude: compile(exclude) } : null;
}
/**
 * The workspace `rootAbs` declares for `ecosystem`, or null — read once per
 * directory and ecosystem. A declaration file that is refused, or too large
 * to parse, declares no member — the conservative answer: the member stays a
 * gap.
 */
function workspaceOf(r, rootAbs, ecosystem) {
    const key = `${rootAbs}\0${ecosystem}`;
    const known = r.workspaces.get(key);
    if (known !== undefined)
        return known;
    const decl = readWorkspace(r, rootAbs, ecosystem);
    r.workspaces.set(key, decl);
    return decl;
}
function readWorkspace(r, rootAbs, ecosystem) {
    if (ecosystem === 'npm') {
        const include = [];
        const exclude = [];
        const add = (p) => {
            if (include.length + exclude.length >= MAX_WORKSPACE_PATTERNS)
                return;
            if (p.startsWith('!'))
                exclude.push(p.slice(1));
            else
                include.push(p);
        };
        if (present(r, join(rootAbs, 'package.json'))) {
            const manifest = readJsonFile(r, join(rootAbs, 'package.json'), MANIFEST_JSON_PARSE_MAX);
            if (typeof manifest === 'object' && manifest !== null && !Array.isArray(manifest)) {
                const ws = manifest['workspaces'];
                const list = Array.isArray(ws)
                    ? ws
                    : typeof ws === 'object' && ws !== null
                        ? ws['packages']
                        : undefined;
                if (Array.isArray(list))
                    for (const p of list)
                        if (typeof p === 'string')
                            add(p);
            }
        }
        if (present(r, join(rootAbs, 'pnpm-workspace.yaml'))) {
            const pnpm = readText(r, join(rootAbs, 'pnpm-workspace.yaml'), WORKSPACE_YAML_MAX);
            // Not a workspace we can read (or too dense to parse — boundedParse): no member.
            const parsed = pnpm === null ? null : parseYamlBounded(pnpm);
            if (parsed?.ok === true) {
                const doc = parsed.value;
                const pkgs = typeof doc === 'object' && doc !== null ? doc['packages'] : undefined;
                if (Array.isArray(pkgs))
                    for (const p of pkgs)
                        if (typeof p === 'string')
                            add(p);
            }
        }
        return compileDecl(include, exclude);
    }
    if (ecosystem === 'cargo' || ecosystem === 'python') {
        const file = join(rootAbs, ecosystem === 'cargo' ? 'Cargo.toml' : 'pyproject.toml');
        if (!present(r, file))
            return null;
        const text = readText(r, file, TOML_SCAN_MAX);
        if (text === null)
            return null;
        const table = ecosystem === 'cargo' ? 'workspace' : 'tool.uv.workspace';
        const include = tomlArrayIn(text, table, 'members');
        if (include === null || include.length === 0)
            return null;
        return compileDecl(include, tomlArrayIn(text, table, 'exclude') ?? []);
    }
    return null;
}
function declaredMember(decl, relFromRoot) {
    return decl.include.some((re) => re.test(relFromRoot)) && !decl.exclude.some((re) => re.test(relFromRoot));
}
/**
 * Assess whether Trivy's fs-scan output covers every dependency manifest in
 * the project (review I1). Every manifest the walk finds
 * ({@link walkManifests}) is judged in its own DIRECTORY: covered when a
 * Result of its ecosystem's Types has its `Target` in that directory, or in
 * an ancestor whose workspace declares it a member (see "workspaces"
 * above). Never by `Type` alone: a root `package-lock.json` said nothing
 * about a `web/package.json` that has no lock of its own, and that is the
 * gap this used to hide — Trivy 0.69.3 skips such a manifest in silence
 * (no `Results` key, exit 0), and the check used to read the root only.
 */
export function assessManifestCoverage(projectPath, rawTrivyOutput, opts = {}) {
    const walked = walkManifests(projectPath, opts);
    if (walked === null)
        return { gaps: [], sawAnyResults: false };
    const reader = {
        root: projectPath,
        budget: new ReadBudget(COVERAGE_BUDGET_BYTES, COVERAGE_BUDGET_FILES),
        workspaces: new Map(),
    };
    const root = parseInputAsJson(rawTrivyOutput);
    const results = asArray(getProp(root, 'Results'));
    /** Type → the directories its Results name. */
    const dirsByType = new Map();
    for (const result of results) {
        const type = getString(result, 'Type');
        const target = getString(result, 'Target');
        if (type === undefined || target === undefined)
            continue;
        const set = dirsByType.get(type) ?? new Set();
        set.add(dirOf(target));
        dirsByType.set(type, set);
    }
    const resultDirs = (eco) => {
        const out = new Set();
        for (const t of eco.trivyTypes)
            for (const d of dirsByType.get(t) ?? [])
                out.add(d);
        return out;
    };
    const abs = (rel) => (rel === '' ? projectPath : join(projectPath, ...rel.split('/')));
    const covered = (eco, dir, dirs) => {
        if (dirs.has(dir))
            return true;
        // Ancestors, nearest first: a workspace root with a Result that declares this directory.
        const segments = dir === '' ? [] : dir.split('/');
        for (let n = segments.length - 1; n >= 0; n--) {
            const ancestor = segments.slice(0, n).join('/');
            if (!dirs.has(ancestor))
                continue;
            const decl = workspaceOf(reader, abs(ancestor), eco.ecosystem);
            if (decl !== null && declaredMember(decl, segments.slice(n).join('/')))
                return true;
        }
        return false;
    };
    /** A lock file of `eco` in `dir`, or at an ancestor whose workspace declares `dir` a member. */
    const hasLockFile = (eco, dir) => {
        const lockIn = (rel) => eco.lockfiles.some((name) => present(reader, join(abs(rel), name)));
        if (lockIn(dir))
            return true;
        const segments = dir === '' ? [] : dir.split('/');
        for (let n = segments.length - 1; n >= 0; n--) {
            const ancestor = segments.slice(0, n).join('/');
            const decl = workspaceOf(reader, abs(ancestor), eco.ecosystem);
            if (decl !== null && declaredMember(decl, segments.slice(n).join('/')) && lockIn(ancestor))
                return true;
        }
        return false;
    };
    const gapFiles = new Map();
    const devOnlyFiles = new Map();
    const dirsOf = new Map();
    const push = (m, k, v) => {
        const list = m.get(k);
        if (list === undefined)
            m.set(k, [v]);
        else
            list.push(v);
    };
    for (const m of walked.found) {
        if (m.eco.declaresNothing?.(reader, m.abs) ?? false)
            continue;
        let dirs = dirsOf.get(m.eco.ecosystem);
        if (dirs === undefined) {
            dirs = resultDirs(m.eco);
            dirsOf.set(m.eco.ecosystem, dirs);
        }
        if (covered(m.eco, m.dir, dirs))
            continue;
        push(gapFiles, m.eco.ecosystem, m.rel);
        if ((m.eco.declaresOnlyDev?.(reader, m.abs) ?? false) && hasLockFile(m.eco, m.dir))
            push(devOnlyFiles, m.eco.ecosystem, m.rel);
    }
    const gaps = [];
    for (const eco of ECOSYSTEM_MANIFESTS) {
        const files = gapFiles.get(eco.ecosystem);
        if (files === undefined)
            continue;
        const devOnly = devOnlyFiles.get(eco.ecosystem);
        gaps.push({ ecosystem: eco.ecosystem, files: [...files].sort(), ...(devOnly !== undefined ? { dev_only: [...devOnly].sort() } : {}) });
    }
    const out = { gaps, sawAnyResults: results.length > 0 };
    if (walked.incomplete !== undefined)
        out.walkIncomplete = walked.incomplete;
    const unread = reader.budget.refused;
    if (unread.length > 0) {
        const shown = unread.slice(0, 3).map((p) => relative(projectPath, p).split(sep).join('/')).join(', ');
        out.readNote =
            `the manifest checks spent their read budget (${reader.budget.describe()}): ${shown}` +
                `${unread.length > 3 ? ` and ${unread.length - 3} more` : ''} were not read and count as declaring something`;
    }
    return out;
}
//# sourceMappingURL=trivy.js.map