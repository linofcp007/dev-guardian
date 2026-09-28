/**
 * The `dependency` evidence provider: is a vulnerable PACKAGE — the exact
 * copy the finding is about — imported by the project's own code, and is the
 * file that imports it one an HTTP route reaches?
 *
 * The static provider asks that about the file a finding lives in. A
 * dependency finding lives in a lockfile, which no route imports, so the
 * static answer for every CVE is `unknown`. This provider answers from the
 * package's side instead: `map_attack_surface` persists the import specifiers
 * that name a package (`AttackSurfaceSnapshot.external_imports`), and the
 * finding's package is matched against them.
 *
 * Three verdicts, and never a fourth:
 *
 *   - `reachable` — a project file under the finding's manifest imports the
 *     package, LOADS THE VULNERABLE VERSION (npm: read from the lockfile or
 *     `node_modules`, see below), and the import graph connects it to a route
 *     file (0 hops when the route file itself imports it). File-level, like
 *     the static provider: a route reaches code that loads the package, not
 *     necessarily the vulnerable function.
 *   - `imported` — such a file imports it, and either no route was shown to
 *     reach it or which version it loads could not be told.
 *   - `unknown` — everything else, each with the reason in `coverage_gaps`.
 *
 * `unreachable` is never produced. "No file imports this package" is absence
 * of evidence: a transitive dependency is never imported by the project's own
 * code, `import(expr)` / `require(variable)` / `importlib.import_module(name)`
 * match no rule, and a package reached through another package's re-export
 * is invisible. Each of those is a common way for a vulnerable package to be
 * very much in use.
 *
 * WHICH COPY (review of the 3.0 additions, I1). A package name alone said
 * nothing about which install the finding is about, and two defects came of
 * it, both reproduced with real Trivy and Semgrep:
 *   - a monorepo: `packages/tool` holds lodash 4.17.20 (vulnerable) and no
 *     code; `packages/api` holds 4.17.21 and a route importing it — the CVE
 *     read `reachable`, citing `packages/api`. Importers now count only under
 *     the directory of the manifest the finding came from.
 *   - a nested copy: `node_modules/x/node_modules/lodash` is 4.17.20 while the
 *     project's code resolves `node_modules/lodash` 4.17.21. For npm, each
 *     importing file's resolved version is now read — Node's own lookup,
 *     `node_modules` from the file's directory up to the manifest's, from the
 *     lockfile or the installed tree (`npmResolve.ts`) — and only a file that
 *     resolves exactly the vulnerable version counts. When the version cannot
 *     be read (no `package-lock.json`, nothing installed, a finding that gives
 *     a vulnerable range rather than a version), the answer is at most
 *     `imported`, never `reachable`. A Python environment holds one version
 *     of a distribution, so PyPI needs no such check.
 *
 * Matching, per ecosystem:
 *
 *   - npm — a JS/TS specifier equal to the package name or under it
 *     (`lodash`, `lodash/merge`, `@babel/core/lib/x`), never a Node built-in:
 *     Node resolves `require('punycode')` to the core module even when the
 *     npm package of that name is installed (`punycode/` reaches the package).
 *   - PyPI — only through {@link PYPI_MODULES}, a table of distributions whose
 *     import names are known and unique. A distribution's import name is not
 *     derivable from its name (PyYAML → `yaml`, Pillow → `PIL`, scikit-learn
 *     → `sklearn`); matching "same name" would claim an import on a
 *     coincidence, so a distribution not in the table is `unknown`, and so is
 *     one whose module another distribution also installs
 *     ({@link PYPI_AMBIGUOUS}: an import of `jwt` does not say whether PyJWT
 *     or the `jwt` distribution is loaded).
 *   - anything else (Go, Maven, NuGet, Cargo, …) — `unknown`, naming the
 *     ecosystem. Not because it is impossible, but because it is not built.
 *
 * Which ecosystem a finding's package belongs to comes from the scanner
 * (`npm-audit`, `pip-audit`) or from the manifest Trivy named as the target
 * ({@link ecosystemOfManifest}). A name alone is never enough: npm and PyPI
 * both have a `requests`.
 *
 * Gap sentences name no package — the finding already does — so a batch
 * summary can say each kind of gap once (`summary.ts`).
 *
 * Pure: no I/O, no clock. The caller passes the snapshot, its graph, the
 * project root, the timestamp and the npm version lookup.
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
        npmResolver: input.npmResolver,
    };
}
const PREDATES_GAP = 'the surface snapshot was mapped before third-party imports were recorded (it has no ' +
    'external_imports), so no package can be matched — re-run map_attack_surface with force: true';
/** How far the answer reaches, said beside every positive verdict. */
const FILE_LEVEL_GAP = 'file-level only: a file importing the package is not proof that the vulnerable function is ' +
    'called, or called with attacker-controlled input';
const NO_IMPORT_GAP = 'no project file imports the package directly. That is absence of evidence, not of use: a ' +
    'transitive dependency is never imported by the project itself, a dynamic import ' +
    '(import(expr), require(variable), importlib) matches no rule, and a package used ' +
    "through another package's re-export is invisible";
const NO_MANIFEST_GAP = 'the finding names no manifest, so an import anywhere in the project counts — it may load ' +
    'another install of the package than the one the finding is about';
const RANGE_GAP = 'the finding gives a vulnerable version range, not the installed version, so whether the ' +
    'importing files load a vulnerable copy could not be told — no route is claimed to reach it';
const UNVERIFIED_GAP = 'which version the importing files load could not be read (no package-lock.json or ' +
    'npm-shrinkwrap.json beside the manifest, and no installed node_modules copy), so none is ' +
    'claimed to reach the vulnerable one';
export function assessDependency(subject, index) {
    const name = subject.package_name;
    if (index.external === undefined)
        return unknown([PREDATES_GAP]);
    const matcher = matcherFor(subject);
    if ('gap' in matcher)
        return unknown([matcher.gap]);
    const scopeDir = subject.manifest === null ? null : dirOf(subject.manifest);
    const matching = index.external.entries.filter((entry) => matcher.languages.has(entry.language) && matcher.matches(entry.specifier) && !insideNodeModules(entry.file));
    const inScope = unique(matching.filter((e) => scopeDir === null || isUnder(e.file, scopeDir)).map((e) => e.file));
    const outOfScope = unique(matching.map((e) => e.file)).filter((f) => !inScope.includes(f));
    const gaps = [];
    if (subject.manifest === null)
        gaps.push(NO_MANIFEST_GAP);
    if (index.partiallyParsed > 0) {
        gaps.push(`${index.partiallyParsed} file(s) were only partly parsed when the surface was mapped; an ` +
            'import inside an unparsed span is missing');
    }
    // The snapshot caps each package's file list (MAX_FILES_PER_PACKAGE): an
    // unrecorded importer may be the one a route reaches.
    const capped = index.external.truncated.filter((t) => matcher.languages.has(t.language) && matcher.matches(t.specifier));
    if (capped.length > 0) {
        gaps.push('the snapshot records at most ' +
            `${capped.map((t) => `${t.recorded} of the ${t.total} files importing '${t.specifier}'`).join(', ')}; ` +
            'an unrecorded importer may be one a route reaches');
    }
    if (inScope.length === 0) {
        if (outOfScope.length > 0 && scopeDir !== null) {
            return unknown([
                `the package is imported only by files outside '${scopeDir === '' ? '.' : scopeDir}', the directory ` +
                    "of the manifest this finding came from — they load another install's copy",
                ...gaps,
            ]);
        }
        return unknown([NO_IMPORT_GAP, ...gaps]);
    }
    // Which of them load the vulnerable copy.
    const loads = [];
    const unverified = [];
    const others = new Map(); // resolved version → source
    if (subject.ecosystem === 'npm') {
        for (const file of inScope) {
            const resolved = subject.version === null ? null : (index.npmResolver?.(dirOf(file), scopeDir ?? '', name) ?? null);
            if (resolved === null)
                unverified.push(file);
            else if (resolved.version === subject.version)
                loads.push({ file, source: resolved.source });
            else
                others.set(resolved.version, resolved.source);
        }
        if (unverified.length > 0)
            gaps.push(subject.version === null ? RANGE_GAP : UNVERIFIED_GAP);
    }
    else {
        // One environment, one version of a distribution.
        for (const file of inScope)
            loads.push({ file, source: null });
    }
    if (loads.length === 0 && unverified.length === 0) {
        const resolvedTo = [...others].map(([version, source]) => `${version} (${source})`).join(', ');
        return unknown([
            `the project's code resolves '${name}' ${resolvedTo}, not the vulnerable ${subject.version ?? '?'}: that ` +
                'copy is installed under another package and loaded through it, which the import graph does not follow',
            ...gaps,
        ]);
    }
    let nearest = null;
    for (const load of loads) {
        const reach = cachedReach(index, load.file);
        const root = reach.reachingRoots[0];
        if (reach.hops === null || root === undefined)
            continue;
        if (nearest === null || reach.hops < nearest.hops)
            nearest = { ...load, hops: reach.hops, root };
    }
    const importing = [...loads.map((l) => l.file), ...unverified].sort();
    const importedBy = `'${name}' is imported by ${importing.length} project file(s): ${sample(importing)}`;
    if (nearest !== null) {
        const route = mostInformative(index.routesByFile.get(nearest.root));
        const via = route === undefined ? nearest.root : `${routeLabel(route)} (${nearest.root})`;
        const version = subject.version === null ? '' : ` ${subject.version}`;
        const source = nearest.source === null ? '' : `, per ${nearest.source}`;
        return {
            verdict: 'reachable',
            confidence: 'medium',
            evidence: [
                {
                    detail: `${nearest.file} imports '${name}'${version}${source} and is reachable in ` +
                        `${hopWord(nearest.hops)} via ${via}`,
                },
                { detail: importedBy },
            ],
            coverage_gaps: [FILE_LEVEL_GAP, ...gaps],
            importing_files: loads.map((l) => l.file).sort(),
        };
    }
    const why = loads.length === 0
        ? ' — which version they load could not be told'
        : ' — none of them is reached from a known route through the import graph';
    return {
        verdict: 'imported',
        confidence: 'medium',
        evidence: [{ detail: `${importedBy}${why}` }],
        coverage_gaps: [FILE_LEVEL_GAP, ...graphGaps(index), ...gaps],
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
function unique(values) {
    return [...new Set(values)].sort();
}
/** The directory of a project-relative POSIX path; `''` for the project root. */
function dirOf(path) {
    const posix = path.replace(/\\/g, '/');
    const at = posix.lastIndexOf('/');
    return at === -1 ? '' : posix.slice(0, at);
}
function isUnder(file, dir) {
    return dir === '' || file.startsWith(`${dir}/`);
}
function insideNodeModules(file) {
    return /(^|\/)node_modules\//.test(file);
}
const JS_LANGUAGES = new Set(['javascript', 'typescript']);
const PYTHON_LANGUAGES = new Set(['python']);
function matcherFor(subject) {
    const name = subject.package_name;
    switch (subject.ecosystem) {
        case null:
            return {
                gap: "could not tell which ecosystem the package belongs to (the finding's target is not a " +
                    'known lockfile or manifest), and a name alone matches packages of every ecosystem',
            };
        case 'npm':
            return { languages: JS_LANGUAGES, matches: (specifier) => npmSpecifierMatches(specifier, name) };
        case 'pypi': {
            const normalized = normalizePypiName(name);
            const ambiguous = PYPI_AMBIGUOUS[normalized];
            if (ambiguous !== undefined) {
                return {
                    gap: `the module of this PyPI distribution is ambiguous — ${ambiguous} — so an import of it does not say which one is loaded`,
                };
            }
            const modules = PYPI_MODULES[normalized];
            if (modules === undefined) {
                return {
                    gap: 'no known distribution-to-module mapping for this PyPI package: its import name cannot ' +
                        'be derived from its name (PyYAML is imported as yaml), so no import is matched',
                };
            }
            return {
                languages: PYTHON_LANGUAGES,
                matches: (specifier) => modules.some((m) => specifier === m || specifier.startsWith(`${m}.`)),
            };
        }
        default:
            return {
                gap: `import matching is implemented for npm and PyPI packages only; this is a ${subject.ecosystem} package`,
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
 * PyPI distributions whose top-level import names are known AND unique,
 * keyed by the PEP 503 normalised name. Deliberately a table, not a rule: the
 * whole point is that the mapping is not derivable. A missing entry costs an
 * `unknown`, a wrong one a false `imported`, so an entry goes in only when
 * its import name is certain and no other distribution is known to install
 * the same module (review of the 3.0 additions, M10: `multipart` and `bson`
 * were listed for python-multipart and pymongo, and are also the modules of
 * the `multipart` and `bson` distributions). Two exceptions, kept on
 * purpose: Pillow's `PIL` and mysqlclient's `MySQLdb` are also the modules
 * of `PIL` and `MySQL-python`, which never supported Python 3.
 * A fork can still install a listed module under another name (`redis3`
 * for `redis`); the table cannot know every fork.
 */
export const PYPI_MODULES = {
    aiohttp: ['aiohttp'],
    attrs: ['attrs'],
    babel: ['babel'],
    beautifulsoup4: ['bs4'],
    bleach: ['bleach'],
    celery: ['celery'],
    certifi: ['certifi'],
    cryptography: ['cryptography'],
    django: ['django'],
    djangorestframework: ['rest_framework'],
    ecdsa: ['ecdsa'],
    fastapi: ['fastapi'],
    flask: ['flask'],
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
    pandas: ['pandas'],
    paramiko: ['paramiko'],
    pillow: ['PIL'],
    pip: ['pip'],
    protobuf: ['google.protobuf'],
    pyasn1: ['pyasn1'],
    pycryptodomex: ['Cryptodome'],
    pydantic: ['pydantic'],
    pymongo: ['pymongo', 'gridfs'],
    pymysql: ['pymysql'],
    pyopenssl: ['OpenSSL'],
    'python-dateutil': ['dateutil'],
    'python-multipart': ['python_multipart'],
    pyyaml: ['yaml'],
    redis: ['redis'],
    requests: ['requests'],
    rsa: ['rsa'],
    'scikit-learn': ['sklearn'],
    scipy: ['scipy'],
    setuptools: ['setuptools'],
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
/**
 * Distributions whose module another distribution also installs — checked
 * against PyPI on 2026-09-28 (each named distribution exists). An import of
 * the module does not say which one is loaded, so these answer `unknown`.
 */
export const PYPI_AMBIGUOUS = {
    pyjwt: "its module 'jwt' is also installed by the 'jwt' distribution",
    'python-jose': "its module 'jose' is also installed by the 'jose' distribution",
    pycryptodome: "its module 'Crypto' is also installed by 'pycrypto'",
    dnspython: "its module 'dns' is also installed by 'dnspython3'",
    psycopg2: "its module 'psycopg2' is also installed by 'psycopg2-binary'",
    'psycopg2-binary': "its module 'psycopg2' is also installed by 'psycopg2'",
    'opencv-python': "its module 'cv2' is also installed by the other OpenCV distributions",
    'opencv-python-headless': "its module 'cv2' is also installed by the other OpenCV distributions",
    'opencv-contrib-python': "its module 'cv2' is also installed by the other OpenCV distributions",
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
 * The package a dependency finding is about — its name, ecosystem, exact
 * installed version and manifest — or `null` for a finding that is not about
 * a dependency. The package and version come from the snippet every
 * dependency scanner writes (`fingerprint/findingIdentity.ts
 * #dependencyCoordinates`); the ecosystem from the scanner, else from the
 * manifest the finding names.
 */
export function dependencySubjectOf(finding) {
    const coordinates = dependencyCoordinates(finding);
    if (coordinates === null || coordinates.name === '')
        return null;
    const manifest = finding.file_path !== undefined && ecosystemOfManifest(finding.file_path) !== null
        ? finding.file_path.replace(/\\/g, '/')
        : null;
    return {
        package_name: coordinates.name,
        ecosystem: ecosystemOf(finding),
        version: isExactVersion(coordinates.version) ? coordinates.version : null,
        manifest,
    };
}
/** `4.17.20`, `v0.1.0`, `1.0.0-rc.1` — not `<4.17.21`, `^1.2`, `1.2.x` or `*`. */
function isExactVersion(version) {
    return /^v?\d[\w.+-]*$/.test(version) && !/(^|\.)[xX*](\.|$)/.test(version);
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