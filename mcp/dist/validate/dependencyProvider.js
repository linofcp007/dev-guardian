/**
 * The `dependency` evidence provider: is a vulnerable PACKAGE imported by the
 * project's own code — and is the file that imports it one an HTTP route
 * reaches?
 *
 * The static provider asks that about the file a finding lives in. A
 * dependency finding lives in a lockfile, which no route imports, so the
 * static answer for every CVE is `unknown`. This provider answers from the
 * package's side instead: `map_attack_surface` persists the import specifiers
 * that name a package (`AttackSurfaceSnapshot.external_imports`), and a CVE's
 * package is matched against them.
 *
 * Three verdicts, and never a fourth:
 *
 *   - `reachable` — a project file imports the package, and the import graph
 *     connects that file to a route file (0 hops when the route file itself
 *     imports it). File-level, like the static provider: it says a route
 *     reaches code that loads the package, never that the vulnerable function
 *     is called.
 *   - `imported` — a project file imports it, and no route was shown to reach
 *     any such file. Not "unreachable": the graph misses dynamic imports, CLI
 *     and queue entry points, and anything past its edge cap.
 *   - `unknown` — everything else, each with the reason in `coverage_gaps`.
 *
 * `unreachable` is never produced. "No file imports this package" is absence
 * of evidence: a transitive dependency is never imported by the project's own
 * code, `import(expr)` / `require(variable)` / `importlib.import_module(name)`
 * match no rule, and a package reached through another package's re-export
 * is invisible. Each of those is a common way for a vulnerable package to be
 * very much in use.
 *
 * Matching, per ecosystem:
 *
 *   - npm — a JS/TS specifier equal to the package name or under it
 *     (`lodash`, `lodash/merge`, `@babel/core/lib/x`), never a Node built-in:
 *     Node resolves `require('punycode')` to the core module even when the
 *     npm package of that name is installed (`punycode/` reaches the package).
 *   - PyPI — only through {@link PYPI_MODULES}, a table of distributions whose
 *     import names are known. A distribution's import name is not derivable
 *     from its name (PyYAML → `yaml`, Pillow → `PIL`, scikit-learn →
 *     `sklearn`); matching "same name" would claim an import on a
 *     coincidence, so a distribution not in the table is `unknown`.
 *   - anything else (Go, Maven, NuGet, Cargo, …) — `unknown`, naming the
 *     ecosystem. Not because it is impossible, but because it is not built.
 *
 * Which ecosystem a finding's package belongs to comes from the scanner
 * (`npm-audit`, `pip-audit`) or from the manifest Trivy named as the target
 * ({@link ecosystemOfManifest}). A name alone is never enough: npm and PyPI
 * both have a `requests`.
 *
 * Pure: no I/O, no clock. The caller passes the snapshot, its graph, the
 * project root and the timestamp.
 */
import { isBuiltin } from 'node:module';
import { dependencyCoordinates } from '../fingerprint/findingIdentity.js';
import { expandExternalImports } from '../surface/moduleEdges.js';
import { reachFrom } from './importGraph.js';
import { groupRoutesByRelFile, hopWord, mostInformative, routeLabel } from './staticProvider.js';
export function prepareDependencyIndex(input) {
    const routesByFile = groupRoutesByRelFile(input.snapshot.routes, input.projectPath);
    return {
        external: input.snapshot.external_imports === undefined ? undefined : expandExternalImports(input.snapshot.external_imports),
        graph: input.graph,
        roots: [...routesByFile.keys()],
        routesByFile,
        partiallyParsed: input.snapshot.partially_parsed?.length ?? 0,
        reachCache: new Map(),
    };
}
const PREDATES_GAP = 'the surface snapshot was mapped before third-party imports were recorded (it has no ' +
    'external_imports), so no package can be matched — re-run map_attack_surface with force: true';
/** How far the answer reaches, said beside every positive verdict. */
const FILE_LEVEL_GAP = 'file-level only: a file importing the package is not proof that the vulnerable function is ' +
    'called, or called with attacker-controlled input';
export function assessDependency(subject, index) {
    const name = subject.package_name;
    if (index.external === undefined)
        return unknown([PREDATES_GAP]);
    const matcher = matcherFor(subject);
    if ('gap' in matcher)
        return unknown([matcher.gap]);
    const importing = [
        ...new Set(index.external.entries
            .filter((entry) => matcher.languages.has(entry.language) && matcher.matches(entry.specifier))
            .map((entry) => entry.file)),
    ].sort();
    const parseGap = index.partiallyParsed > 0
        ? [
            `${index.partiallyParsed} file(s) were only partly parsed when the surface was mapped; an ` +
                'import inside an unparsed span is missing',
        ]
        : [];
    // The snapshot caps each package's file list (MAX_FILES_PER_PACKAGE): an
    // unrecorded importer may be the one a route reaches.
    const capped = index.external.truncated.filter((t) => matcher.languages.has(t.language) && matcher.matches(t.specifier));
    if (capped.length > 0) {
        parseGap.push('the snapshot records at most ' +
            `${capped.map((t) => `${t.recorded} of the ${t.total} files importing '${t.specifier}'`).join(', ')}; ` +
            'an unrecorded importer may be one a route reaches');
    }
    if (importing.length === 0) {
        return unknown([
            `no project file imports '${name}' directly. That is absence of evidence, not of use: a ` +
                'transitive dependency is never imported by the project itself, a dynamic import ' +
                '(import(expr), require(variable), importlib) matches no rule, and a package used ' +
                "through another package's re-export is invisible",
            ...parseGap,
        ]);
    }
    let nearest = null;
    for (const file of importing) {
        const reach = cachedReach(index, file);
        const root = reach.reachingRoots[0];
        if (reach.hops === null || root === undefined)
            continue;
        if (nearest === null || reach.hops < nearest.hops)
            nearest = { file, hops: reach.hops, root };
    }
    const importedBy = `'${name}' is imported by ${importing.length} project file(s): ${sample(importing)}`;
    if (nearest !== null) {
        const route = mostInformative(index.routesByFile.get(nearest.root));
        const via = route === undefined ? nearest.root : `${routeLabel(route)} (${nearest.root})`;
        return {
            verdict: 'reachable',
            confidence: 'medium',
            evidence: [
                { detail: `${nearest.file} imports '${name}' and is reachable in ${hopWord(nearest.hops)} via ${via}` },
                { detail: importedBy },
            ],
            coverage_gaps: [FILE_LEVEL_GAP, ...parseGap],
            importing_files: importing,
        };
    }
    return {
        verdict: 'imported',
        confidence: 'medium',
        evidence: [{ detail: `${importedBy} — none of them is reached from a known route through the import graph` }],
        coverage_gaps: [FILE_LEVEL_GAP, ...graphGaps(index), ...parseGap],
        importing_files: importing,
    };
}
/**
 * Why "no route reaches an importer" is weaker than it reads — said on every
 * `imported`, since that verdict is exactly the one a reader is tempted to
 * treat as "safe".
 */
function graphGaps(index) {
    const gaps = [
        'only HTTP routes are entry points: a file run by a CLI, a cron job or a queue consumer, or ' +
            'loaded by a dynamic import, reads as reached by no route',
    ];
    if (index.graph.truncated) {
        gaps.push('the import graph was truncated at its edge cap, so a path from a route may be missing');
    }
    if (index.roots.length === 0)
        gaps.push('the surface snapshot holds no code route to start from');
    return gaps;
}
function cachedReach(index, file) {
    const cached = index.reachCache.get(file);
    if (cached !== undefined)
        return cached;
    const result = reachFrom(index.graph, index.roots, file);
    index.reachCache.set(file, result);
    return result;
}
function unknown(gaps) {
    return { verdict: 'unknown', confidence: 'low', evidence: [], coverage_gaps: gaps, importing_files: [] };
}
function sample(files) {
    const shown = files.slice(0, 5).join(', ');
    return files.length > 5 ? `${shown}, … (${files.length - 5} more)` : shown;
}
const JS_LANGUAGES = new Set(['javascript', 'typescript']);
const PYTHON_LANGUAGES = new Set(['python']);
function matcherFor(subject) {
    const name = subject.package_name;
    switch (subject.ecosystem) {
        case null:
            return {
                gap: `could not tell which ecosystem '${name}' belongs to (the finding's target is not a ` +
                    'known lockfile or manifest), and a name alone matches packages of every ecosystem',
            };
        case 'npm':
            return { languages: JS_LANGUAGES, matches: (specifier) => npmSpecifierMatches(specifier, name) };
        case 'pypi': {
            const modules = PYPI_MODULES[normalizePypiName(name)];
            if (modules === undefined) {
                return {
                    gap: `no known distribution-to-module mapping for the PyPI package '${name}': its import ` +
                        'name cannot be derived from its name (PyYAML is imported as yaml), so no import is matched',
                };
            }
            return {
                languages: PYTHON_LANGUAGES,
                matches: (specifier) => modules.some((m) => specifier === m || specifier.startsWith(`${m}.`)),
            };
        }
        default:
            return {
                gap: `import matching is implemented for npm and PyPI packages only, and '${name}' is a ` +
                    `${subject.ecosystem} package`,
            };
    }
}
function npmSpecifierMatches(specifier, name) {
    if (specifier.startsWith('node:') || isBuiltin(specifier))
        return false;
    return specifier === name || specifier.startsWith(`${name}/`);
}
/** PEP 503 normalisation: case-folded, every run of `-`, `_`, `.` a single `-`. */
function normalizePypiName(name) {
    return name.toLowerCase().replace(/[-_.]+/g, '-');
}
/**
 * PyPI distributions whose top-level import names are known, keyed by the
 * PEP 503 normalised name. Deliberately a table, not a rule: the whole point
 * is that the mapping is not derivable. Widely used and security-relevant
 * packages first; a missing entry costs an `unknown`, a wrong one a false
 * `imported`, so an entry goes in only when its import name is certain.
 */
export const PYPI_MODULES = {
    aiohttp: ['aiohttp'],
    attrs: ['attr', 'attrs'],
    babel: ['babel'],
    beautifulsoup4: ['bs4'],
    bleach: ['bleach'],
    celery: ['celery'],
    certifi: ['certifi'],
    cryptography: ['cryptography'],
    django: ['django'],
    djangorestframework: ['rest_framework'],
    dnspython: ['dns'],
    ecdsa: ['ecdsa'],
    fastapi: ['fastapi'],
    flask: ['flask'],
    gitpython: ['git'],
    gunicorn: ['gunicorn'],
    httplib2: ['httplib2'],
    httpx: ['httpx'],
    idna: ['idna'],
    jinja2: ['jinja2'],
    jsonpickle: ['jsonpickle'],
    lxml: ['lxml'],
    mako: ['mako'],
    markdown: ['markdown'],
    mysqlclient: ['MySQLdb'],
    numpy: ['numpy'],
    'opencv-python': ['cv2'],
    'opencv-python-headless': ['cv2'],
    pandas: ['pandas'],
    paramiko: ['paramiko'],
    pillow: ['PIL'],
    pip: ['pip'],
    protobuf: ['google.protobuf'],
    psycopg2: ['psycopg2'],
    'psycopg2-binary': ['psycopg2'],
    pyasn1: ['pyasn1'],
    pycryptodome: ['Crypto'],
    pycryptodomex: ['Cryptodome'],
    pydantic: ['pydantic'],
    pyjwt: ['jwt'],
    pymongo: ['pymongo', 'bson', 'gridfs'],
    pymysql: ['pymysql'],
    pyopenssl: ['OpenSSL'],
    'python-dateutil': ['dateutil'],
    'python-jose': ['jose'],
    'python-multipart': ['multipart', 'python_multipart'],
    pyyaml: ['yaml'],
    redis: ['redis'],
    requests: ['requests'],
    rsa: ['rsa'],
    'scikit-learn': ['sklearn'],
    scipy: ['scipy'],
    setuptools: ['setuptools', 'pkg_resources'],
    sqlalchemy: ['sqlalchemy'],
    starlette: ['starlette'],
    tornado: ['tornado'],
    twisted: ['twisted'],
    ujson: ['ujson'],
    urllib3: ['urllib3'],
    waitress: ['waitress'],
    werkzeug: ['werkzeug'],
    wheel: ['wheel'],
};
/* ---------------------------------------------------------------------- *
 * Which package, from which ecosystem, a finding is about
 * ---------------------------------------------------------------------- */
/** Scanners that only ever audit one ecosystem. */
const TOOL_ECOSYSTEMS = {
    'npm-audit': 'npm',
    'pip-audit': 'pypi',
    wpscan: 'wordpress',
};
/**
 * The package a dependency finding is about, and its ecosystem — or `null`
 * for a finding that is not about a dependency. The package comes from the
 * snippet every dependency scanner writes (`fingerprint/findingIdentity.ts
 * #dependencyCoordinates`); the ecosystem from the scanner, else from the
 * manifest the finding names.
 */
export function dependencySubjectOf(finding) {
    const coordinates = dependencyCoordinates(finding);
    if (coordinates === null || coordinates.name === '')
        return null;
    return { package_name: coordinates.name, ecosystem: ecosystemOf(finding) };
}
function ecosystemOf(finding) {
    const byTool = TOOL_ECOSYSTEMS[finding.tool.toLowerCase()];
    if (byTool !== undefined)
        return byTool;
    return finding.file_path === undefined ? null : ecosystemOfManifest(finding.file_path);
}
/** Lockfiles and manifests by exact basename, as purl types. */
const MANIFEST_ECOSYSTEMS = {
    'package-lock.json': 'npm',
    'npm-shrinkwrap.json': 'npm',
    'yarn.lock': 'npm',
    'pnpm-lock.yaml': 'npm',
    'package.json': 'npm',
    'bun.lock': 'npm',
    'bun.lockb': 'npm',
    'pipfile.lock': 'pypi',
    pipfile: 'pypi',
    'poetry.lock': 'pypi',
    'uv.lock': 'pypi',
    'pdm.lock': 'pypi',
    'pyproject.toml': 'pypi',
    'setup.py': 'pypi',
    'setup.cfg': 'pypi',
    'go.mod': 'golang',
    'go.sum': 'golang',
    'cargo.lock': 'cargo',
    'cargo.toml': 'cargo',
    'composer.lock': 'composer',
    'composer.json': 'composer',
    'pom.xml': 'maven',
    'gradle.lockfile': 'maven',
    'build.gradle': 'maven',
    'build.gradle.kts': 'maven',
    'packages.lock.json': 'nuget',
    'packages.config': 'nuget',
    'gemfile.lock': 'gem',
    gemfile: 'gem',
    'mix.lock': 'hex',
    'pubspec.lock': 'pub',
};
/** Suffix rules for names that vary: `requirements-dev.txt`, `App.csproj`. */
const MANIFEST_PATTERNS = [
    [/^requirements.*\.txt$/, 'pypi'],
    [/\.(cs|fs|vb)proj$/, 'nuget'],
    [/\.sln$/, 'nuget'],
    [/\.deps\.json$/, 'nuget'],
    [/\.gemspec$/, 'gem'],
];
/** The ecosystem a lockfile or manifest path belongs to, or `null` for anything else. */
export function ecosystemOfManifest(path) {
    const base = (path.split(/[\\/]/).pop() ?? '').toLowerCase();
    const exact = MANIFEST_ECOSYSTEMS[base];
    if (exact !== undefined)
        return exact;
    for (const [pattern, ecosystem] of MANIFEST_PATTERNS) {
        if (pattern.test(base))
            return ecosystem;
    }
    return null;
}
/**
 * One `dependency` verdict per dependency finding in the batch; a finding
 * that is not about a package gets none (the provider does not apply to it,
 * which is not the same as `unknown`).
 */
export function validateDependencies(input) {
    const index = prepareDependencyIndex(input);
    const out = [];
    for (const finding of input.findings) {
        const subject = dependencySubjectOf(finding);
        if (subject === null)
            continue;
        const assessment = assessDependency(subject, index);
        out.push({
            fingerprint: finding.fingerprint,
            provider: 'dependency',
            verdict: assessment.verdict,
            confidence: assessment.confidence,
            evidence: assessment.evidence,
            coverage_gaps: assessment.coverage_gaps,
            snapshot_id: input.snapshotId,
            tree_hash: input.treeHash,
            computed_at: input.computedAt,
        });
    }
    return out;
}
//# sourceMappingURL=dependencyProvider.js.map