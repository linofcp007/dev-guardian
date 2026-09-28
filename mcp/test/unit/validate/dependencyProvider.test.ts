/**
 * The `dependency` evidence provider: is a vulnerable PACKAGE imported by the
 * project's own code, and by a file an HTTP route reaches?
 *
 * The asymmetry every test below leans on: an import found is evidence; an
 * import NOT found is not. A transitive dependency is never imported by the
 * project's code, a dynamic `import(expr)` / `importlib` call matches no rule,
 * and a package used through another package's re-export is invisible — so
 * "no import found" answers `unknown`, and `unreachable` is never produced.
 */
import { describe, expect, it } from 'vitest';
import {
  assessDependency,
  dependencySubjectOf,
  ecosystemOfManifest,
  PYPI_AMBIGUOUS,
  PYPI_MODULES,
  prepareDependencyIndex,
  validateDependencies,
  type DependencySubject,
  type NpmResolver,
  type PypiPinResolver,
} from '../../../src/validate/dependencyProvider.js';
import { buildImportGraph } from '../../../src/validate/importGraph.js';
import { MAX_FILES_PER_PACKAGE, externalImports } from '../../../src/surface/moduleEdges.js';
import type { AttackSurfaceSnapshot, Finding, RouteRecord } from '../../../src/types.js';

const PROJECT = '/proj';

function route(over: Partial<RouteRecord> = {}): RouteRecord {
  return {
    method: 'GET', provenance: 'code', path_raw: '/users', path_resolved: '/users',
    path_partial: false, file: `${PROJECT}/src/routes.ts`, line: 1, framework: 'express',
    language: 'typescript', auth_hint: 'unknown', params: [], confidence: 'high',
    ...over,
  };
}

type External = { file: string; specifier: string; language: string };

function ext(file: string, specifier: string, language = 'typescript'): External {
  return { file, specifier, language };
}

function snapshotOf(over: Partial<AttackSurfaceSnapshot> = {}): AttackSurfaceSnapshot {
  return {
    routes: [route()],
    env_vars: [],
    ports: [],
    webhooks: [],
    coverage: [],
    tools_run: [],
    missing_tools: [],
    spec_files: [],
    spec_diff: null,
    // routes.ts -> db.ts; cli.ts is imported by nothing a route reaches.
    imports: [{ file: 'src/routes.ts', module_file: 'src/db.ts' }],
    external_imports: externalImports([]),
    ...over,
  };
}

/**
 * A stand-in for the lockfile/node_modules lookup (validate/npmResolve.ts):
 * every package resolves to the version the finding is about unless
 * `resolved` says otherwise for a (directory, name).
 */
function resolverOf(resolved: Record<string, string | null> = {}): NpmResolver {
  return (fromDir, _rootDir, name) => {
    const key = `${fromDir}|${name}`;
    const hit = key in resolved ? resolved[key] : name in resolved ? resolved[name] : undefined;
    if (hit === null) return { version: null, reason: 'package-lock.json is not valid JSON' };
    return { version: hit ?? '1.0.0', source: 'package-lock.json' };
  };
}

function assess(
  subject: DependencySubject,
  over: Partial<AttackSurfaceSnapshot> = {},
  npmResolver: NpmResolver | null = resolverOf(),
  // The pins the project's requirement files hold; by default none but the finding's own.
  pypiPins: PypiPinResolver | null = () => [],
) {
  const snapshot = snapshotOf(over);
  const index = prepareDependencyIndex({
    snapshot,
    graph: buildImportGraph(snapshot.imports),
    projectPath: PROJECT,
    ...(npmResolver === null ? {} : { npmResolver }),
    ...(pypiPins === null ? {} : { pypiPins }),
  });
  return assessDependency(subject, index);
}

const npm = (name: string, over: Partial<DependencySubject> = {}): DependencySubject => ({
  package_name: name, ecosystem: 'npm', version: '1.0.0', manifest: 'package-lock.json', ...over,
});
const pypi = (name: string, over: Partial<DependencySubject> = {}): DependencySubject => ({
  package_name: name, ecosystem: 'pypi', version: '1.0.0', manifest: 'requirements.txt', ...over,
});

describe('assessDependency — npm', () => {
  it('reads reachable when a file a route reaches imports the package, naming the route and the hops', () => {
    const a = assess(npm('lodash'), { external_imports: externalImports([ext('src/db.ts', 'lodash')]) });
    expect(a.verdict).toBe('reachable');
    expect(a.importing_files).toEqual(['src/db.ts']);
    const details = a.evidence.map((e) => e.detail).join(' | ');
    expect(details).toMatch(/src\/db\.ts/);
    expect(details).toMatch(/1 hop/);
    expect(details).toMatch(/GET \/users/);
  });

  it('reads reachable at 0 hops when the route file itself imports it', () => {
    const a = assess(npm('express'), { external_imports: externalImports([ext('src/routes.ts', 'express')]) });
    expect(a.verdict).toBe('reachable');
    expect(a.evidence.map((e) => e.detail).join(' | ')).toMatch(/0 hops/);
  });

  it('reads imported when only a file no route reaches imports it', () => {
    const a = assess(npm('lodash'), { external_imports: externalImports([ext('src/cli.ts', 'lodash')]) });
    expect(a.verdict).toBe('imported');
    expect(a.importing_files).toEqual(['src/cli.ts']);
  });

  it('matches a subpath and a scoped name, and nothing that merely starts with the name', () => {
    expect(assess(npm('lodash'), { external_imports: externalImports([ext('src/db.ts', 'lodash/merge')]) }).verdict)
      .toBe('reachable');
    expect(assess(npm('@babel/core'), { external_imports: externalImports([ext('src/db.ts', '@babel/core')]) }).verdict)
      .toBe('reachable');
    expect(assess(npm('lodash'), { external_imports: externalImports([ext('src/db.ts', 'lodash-es')]) }).verdict)
      .toBe('unknown');
    expect(assess(npm('@babel/core'), { external_imports: externalImports([ext('src/db.ts', '@babel/core-js')]) }).verdict)
      .toBe('unknown');
  });

  it('never matches a Node built-in, which is what a bare `punycode` import loads', () => {
    // Node resolves a core module name before node_modules, so
    // `require('punycode')` is the built-in even with the npm package
    // installed; `punycode/` is how code reaches the package.
    expect(assess(npm('punycode'), { external_imports: externalImports([ext('src/db.ts', 'punycode')]) }).verdict)
      .toBe('unknown');
    expect(assess(npm('punycode'), { external_imports: externalImports([ext('src/db.ts', 'node:punycode')]) }).verdict)
      .toBe('unknown');
    expect(assess(npm('punycode'), { external_imports: externalImports([ext('src/db.ts', 'punycode/')]) }).verdict)
      .toBe('reachable');
  });

  it('only counts JavaScript/TypeScript imports for an npm package', () => {
    const a = assess(npm('requests'), { external_imports: externalImports([ext('app/views.py', 'requests', 'python')]) });
    expect(a.verdict).toBe('unknown');
  });
});

describe('assessDependency — absence is never evidence', () => {
  it('answers unknown, never unreachable, when no file imports the package', () => {
    const a = assess(npm('minimist'), { external_imports: externalImports([ext('src/db.ts', 'lodash')]) });
    expect(a.verdict).toBe('unknown');
    expect(a.evidence).toEqual([]);
    const gaps = a.coverage_gaps.join(' | ');
    expect(gaps).toMatch(/transitive/);
    expect(gaps).toMatch(/dynamic/);
  });

  it('answers unknown when the snapshot predates external imports, and says to re-run', () => {
    const a = assess(npm('lodash'), { external_imports: undefined });
    expect(a.verdict).toBe('unknown');
    expect(a.coverage_gaps.join(' | ')).toMatch(/before third-party imports were recorded.*map_attack_surface/);
  });

  it('answers unknown for an ecosystem it cannot match, naming it', () => {
    const a = assess({ package_name: 'github.com/gin-gonic/gin', ecosystem: 'golang', version: 'v1.9.0', manifest: 'go.mod' }, {
      external_imports: externalImports([ext('main.go', 'github.com/gin-gonic/gin', 'go')]),
    });
    expect(a.verdict).toBe('unknown');
    expect(a.coverage_gaps.join(' | ')).toMatch(/golang/);
  });

  it('answers unknown when the ecosystem could not be determined', () => {
    const a = assess({ package_name: 'lodash', ecosystem: null, version: '4.17.20', manifest: null }, {
      external_imports: externalImports([ext('src/db.ts', 'lodash')]),
    });
    expect(a.verdict).toBe('unknown');
    expect(a.coverage_gaps.join(' | ')).toMatch(/ecosystem/);
  });

  it('says the graph was cut when an importer is not shown reachable from a truncated graph', () => {
    const snapshot = snapshotOf({ external_imports: externalImports([ext('src/cli.ts', 'lodash')]) });
    const graph = { ...buildImportGraph(snapshot.imports), truncated: true };
    const a = assessDependency(npm('lodash'), prepareDependencyIndex({ snapshot, graph, projectPath: PROJECT, npmResolver: resolverOf() }));
    expect(a.verdict).toBe('imported');
    expect(a.coverage_gaps.join(' | ')).toMatch(/truncated/);
  });
});

describe('assessDependency — which copy the project’s code loads (review I1)', () => {
  it('counts only importers under the directory of the finding’s manifest (a monorepo)', () => {
    // packages/api has lodash 4.17.21 and a route importing it; the CVE is in
    // packages/tool's lodash 4.17.20, which no code imports. Reproduced with
    // real Trivy + Semgrep: it read `reachable`, citing packages/api.
    const a = assess(npm('lodash', { version: '4.17.20', manifest: 'packages/tool/package-lock.json' }), {
      routes: [route({ file: `${PROJECT}/packages/api/src/app.js`, language: 'javascript' })],
      external_imports: externalImports([ext('packages/api/src/app.js', 'lodash', 'javascript')]),
    });
    expect(a.verdict).toBe('unknown');
    expect(a.importing_files).toEqual([]);
    expect(a.coverage_gaps.join(' | ')).toMatch(/outside .*packages\/tool/);
  });

  it('never reads reachable when the code resolves another version than the vulnerable one (a nested copy)', () => {
    // node_modules/lodash is 4.17.21; the vulnerable 4.17.20 lives at
    // node_modules/x/node_modules/lodash and is loaded only through x.
    const a = assess(
      npm('lodash', { version: '4.17.20' }),
      { external_imports: externalImports([ext('src/db.ts', 'lodash')]) },
      resolverOf({ lodash: '4.17.21' }),
    );
    expect(a.verdict).toBe('unknown');
    expect(a.coverage_gaps.join(' | ')).toMatch(/resolves .*4\.17\.21.*not the vulnerable 4\.17\.20/);
  });

  it('reads reachable when a routed file resolves exactly the vulnerable version, per importing directory', () => {
    const a = assess(
      npm('lodash', { version: '4.17.20' }),
      {
        imports: [{ file: 'src/routes.ts', module_file: 'src/db.ts' }],
        external_imports: externalImports([ext('src/db.ts', 'lodash'), ext('tools/cli.ts', 'lodash')]),
      },
      resolverOf({ 'src|lodash': '4.17.20', 'tools|lodash': '4.17.21' }),
    );
    expect(a.verdict).toBe('reachable');
    expect(a.importing_files).toEqual(['src/db.ts']);
    expect(a.evidence[0]?.detail).toMatch(/src\/db\.ts .*4\.17\.20/);
  });

  it('claims no more than imported when the installed version could not be read', () => {
    const a = assess(
      npm('lodash', { version: '4.17.20' }),
      { external_imports: externalImports([ext('src/db.ts', 'lodash')]) },
      resolverOf({ lodash: null }),
    );
    expect(a.verdict).toBe('imported');
    // The resolver's own reason, not a guess at one (review M-f).
    expect(a.coverage_gaps.join(' | ')).toContain('could not be read: package-lock.json is not valid JSON');
  });

  it('claims no more than imported for a vulnerable range (npm audit), not an installed version', () => {
    const a = assess(npm('lodash', { version: null }), {
      external_imports: externalImports([ext('src/db.ts', 'lodash')]),
    });
    expect(a.verdict).toBe('imported');
    expect(a.coverage_gaps.join(' | ')).toMatch(/range/);
  });

  it('claims no more than imported with no resolver at all', () => {
    const a = assess(npm('lodash'), { external_imports: externalImports([ext('src/db.ts', 'lodash')]) }, null);
    expect(a.verdict).toBe('imported');
  });

  it('ignores imports from inside node_modules', () => {
    const a = assess(npm('lodash'), {
      external_imports: externalImports([ext('node_modules/x/index.js', 'lodash', 'javascript')]),
    });
    expect(a.verdict).toBe('unknown');
  });
});

describe('the PyPI table (review M10)', () => {
  it('maps every module to exactly one distribution', () => {
    const owners = new Map<string, string[]>();
    for (const [dist, modules] of Object.entries(PYPI_MODULES)) {
      for (const module of modules) owners.set(module, [...(owners.get(module) ?? []), dist]);
    }
    expect([...owners].filter(([, dists]) => dists.length > 1)).toEqual([]);
  });

  it('has no module another known distribution also installs', () => {
    const modules = new Set(Object.values(PYPI_MODULES).flat());
    for (const clash of ['multipart', 'bson', 'attr', 'jwt', 'jose', 'Crypto', 'dns', 'psycopg2', 'cv2']) {
      expect(modules.has(clash), clash).toBe(false);
    }
  });

  it('answers unknown for a distribution whose module is ambiguous, naming the other distribution', () => {
    const a = assess(pypi('PyJWT'), {
      routes: [route({ file: `${PROJECT}/app/views.py`, language: 'python' })],
      external_imports: externalImports([ext('app/views.py', 'jwt', 'python')]),
    });
    expect(a.verdict).toBe('unknown');
    expect(a.coverage_gaps.join(' | ')).toMatch(/'jwt' distribution/);
    expect(Object.keys(PYPI_AMBIGUOUS)).toContain('pyjwt');
  });

  it('matches python-multipart only through python_multipart, and pymongo never through bson', () => {
    const routes = [route({ file: `${PROJECT}/app/views.py`, language: 'python' })];
    expect(assess(pypi('python-multipart'), { routes, external_imports: externalImports([ext('app/views.py', 'multipart', 'python')]) }).verdict)
      .toBe('unknown');
    expect(assess(pypi('python-multipart'), { routes, external_imports: externalImports([ext('app/views.py', 'python_multipart', 'python')]) }).verdict)
      .toBe('reachable');
    expect(assess(pypi('pymongo'), { routes, external_imports: externalImports([ext('app/views.py', 'bson', 'python')]) }).verdict)
      .toBe('unknown');
  });

  it('names the candidates when the only import is of a module another distribution also installs (review M-g)', () => {
    const routes = [route({ file: `${PROJECT}/app/views.py`, language: 'python' })];
    for (const [dist, module, other] of [
      ['attrs', 'attr', 'attr'], ['pymongo', 'bson', 'bson'], ['python-multipart', 'multipart', 'multipart'],
    ] as const) {
      const a = assess(pypi(dist), { routes, external_imports: externalImports([ext('app/views.py', module, 'python')]) });
      expect(a.verdict, dist).toBe('unknown');
      const gaps = a.coverage_gaps.join(' | ');
      expect(gaps).toMatch(new RegExp(`import name '${module}' is ambiguous`));
      expect(gaps).toMatch(new RegExp(`'${other}' distribution`));
      expect(gaps).not.toMatch(/no project file imports the package/);
    }
  });
});

describe('assessDependency — a Python environment is not directory-scoped (review N1)', () => {
  // deploy/requirements.txt pins pyyaml==5.3; app/web.py, which a Flask route
  // declares, imports yaml. It read "imported only by files outside
  // 'deploy' … another install's copy" — a not_affected-sounding reason
  // for a package the route loads.
  const routes = [route({ file: `${PROJECT}/app/web.py`, language: 'python' })];
  const importsYaml = externalImports([ext('app/web.py', 'yaml', 'python')]);

  it('reads reachable when the project pins only one version, wherever the requirements file sits', () => {
    const a = assess(
      pypi('pyyaml', { version: '5.3', manifest: 'deploy/requirements.txt' }),
      { routes, external_imports: importsYaml },
      resolverOf(),
      () => [{ manifest: 'deploy/requirements.txt', version: '5.3' }],
    );
    expect(a.verdict).toBe('reachable');
    expect(a.coverage_gaps.join(' | ')).not.toMatch(/another install/);
  });

  it('answers unknown, naming the other pin, when manifests pin different versions', () => {
    const a = assess(
      pypi('pyyaml', { version: '5.3', manifest: 'deploy/requirements.txt' }),
      { routes, external_imports: importsYaml },
      resolverOf(),
      () => [
        { manifest: 'deploy/requirements.txt', version: '5.3' },
        { manifest: 'services/b/requirements.txt', version: '6.0.1' },
      ],
    );
    expect(a.verdict).toBe('unknown');
    const gaps = a.coverage_gaps.join(' | ');
    expect(gaps).toContain('may load a different pin (services/b/requirements.txt: 6.0.1)');
    expect(gaps).not.toMatch(/another install/);
  });

  it('claims no more than imported when the project’s pins could not be read', () => {
    const a = assess(
      pypi('pyyaml', { version: '5.3', manifest: 'deploy/requirements.txt' }),
      { routes, external_imports: importsYaml },
      resolverOf(),
      null,
    );
    expect(a.verdict).toBe('imported');
  });
});

describe('assessDependency — a capped importer list', () => {
  it('says an unrecorded importer may be the reachable one when the package list was capped', () => {
    const many = Array.from({ length: MAX_FILES_PER_PACKAGE + 1 }, (_, i) =>
      ext(`tools/t${String(i).padStart(5, '0')}.ts`, 'lodash'));
    const a = assess(npm('lodash'), { external_imports: externalImports(many) });
    expect(a.verdict).toBe('imported');
    expect(a.coverage_gaps.join(' | ')).toMatch(new RegExp(`${MAX_FILES_PER_PACKAGE} of the ${MAX_FILES_PER_PACKAGE + 1} files`));
  });
});

describe('assessDependency — PyPI', () => {
  it('matches a distribution through its known module name', () => {
    const a = assess(pypi('PyYAML'), {
      routes: [route({ file: `${PROJECT}/app/views.py`, language: 'python' })],
      external_imports: externalImports([ext('app/views.py', 'yaml', 'python')]),
    });
    expect(a.verdict).toBe('reachable');
  });

  it('matches a submodule of the known module, and not a module that merely starts with it', () => {
    const routes = [route({ file: `${PROJECT}/app/views.py`, language: 'python' })];
    expect(assess(pypi('pyyaml'), { routes, external_imports: externalImports([ext('app/views.py', 'yaml.constructor', 'python')]) }).verdict)
      .toBe('reachable');
    expect(assess(pypi('pyyaml'), { routes, external_imports: externalImports([ext('app/views.py', 'yamllint', 'python')]) }).verdict)
      .toBe('unknown');
  });

  it('normalises the distribution name the way PyPI does', () => {
    const routes = [route({ file: `${PROJECT}/app/views.py`, language: 'python' })];
    expect(assess(pypi('Python_DateUtil'), { routes, external_imports: externalImports([ext('app/views.py', 'dateutil.parser', 'python')]) }).verdict)
      .toBe('reachable');
  });

  it('answers unknown for a distribution with no known module mapping, even when a same-named module is imported', () => {
    // A distribution's import name is not derivable from its name
    // (PyYAML -> yaml, Pillow -> PIL). Guessing "same name" would claim an
    // import on a coincidence, so an unmapped one is unknown.
    const a = assess(pypi('some-obscure-dist'), {
      external_imports: externalImports([ext('app/views.py', 'some_obscure_dist', 'python')]),
    });
    expect(a.verdict).toBe('unknown');
    expect(a.coverage_gaps.join(' | ')).toMatch(/mapping/);
  });
});

function finding(over: Partial<Finding> = {}): Finding {
  return {
    fingerprint: 'fp1',
    tool: 'trivy',
    rule_id: 'CVE-2021-23337',
    severity: 'high',
    category: 'security',
    subcategory: 'cve',
    title: 'lodash: command injection',
    file_path: 'package-lock.json',
    snippet: 'lodash@4.17.20->4.17.21',
    fix_available: true,
    ...over,
  };
}

describe('dependencySubjectOf', () => {
  it('reads the package from the snippet and the ecosystem from the manifest Trivy named', () => {
    expect(dependencySubjectOf(finding()))
      .toEqual({ package_name: 'lodash', ecosystem: 'npm', version: '4.17.20', manifest: 'package-lock.json' });
    expect(dependencySubjectOf(finding({ file_path: 'api/requirements.txt', snippet: 'PyYAML@5.3->5.4' })))
      .toEqual({ package_name: 'PyYAML', ecosystem: 'pypi', version: '5.3', manifest: 'api/requirements.txt' });
    expect(dependencySubjectOf(finding({ file_path: 'go.sum', snippet: 'golang.org/x/net@v0.1.0->v0.7.0' })))
      .toEqual({ package_name: 'golang.org/x/net', ecosystem: 'golang', version: 'v0.1.0', manifest: 'go.sum' });
  });

  it('keeps a scoped npm name whole', () => {
    expect(dependencySubjectOf(finding({ snippet: '@babel/traverse@7.22.0->7.23.2' })))
      .toEqual({ package_name: '@babel/traverse', ecosystem: 'npm', version: '7.22.0', manifest: 'package-lock.json' });
  });

  it('knows the ecosystem of npm-audit and pip-audit by the tool', () => {
    expect(dependencySubjectOf(finding({ tool: 'npm-audit', subcategory: 'dependency', snippet: 'lodash@<4.17.21' })))
      // A vulnerable RANGE, not the installed version: no version at all.
      .toEqual({ package_name: 'lodash', ecosystem: 'npm', version: null, manifest: 'package-lock.json' });
    expect(dependencySubjectOf(finding({ tool: 'pip-audit', subcategory: 'dependency', file_path: 'x', snippet: 'jinja2@2.10' })))
      .toEqual({ package_name: 'jinja2', ecosystem: 'pypi', version: '2.10', manifest: null });
  });

  it('leaves the ecosystem unknown for a target that is not a manifest (an image)', () => {
    expect(dependencySubjectOf(finding({ file_path: 'alpine:3.18 (alpine 3.18.4)', snippet: 'openssl@3.1.2->3.1.4' })))
      .toEqual({ package_name: 'openssl', ecosystem: null, version: '3.1.2', manifest: null });
  });

  it('is null for a finding that is not about a dependency', () => {
    expect(dependencySubjectOf(finding({ tool: 'semgrep', subcategory: undefined, line_start: 3, snippet: 'eval(x)' })))
      .toBeNull();
  });
});

describe('ecosystemOfManifest', () => {
  it('maps lockfiles and manifests by basename, at any depth', () => {
    expect(ecosystemOfManifest('web/yarn.lock')).toBe('npm');
    expect(ecosystemOfManifest('pnpm-lock.yaml')).toBe('npm');
    expect(ecosystemOfManifest('svc/poetry.lock')).toBe('pypi');
    expect(ecosystemOfManifest('requirements-dev.txt')).toBe('pypi');
    expect(ecosystemOfManifest('Cargo.lock')).toBe('cargo');
    expect(ecosystemOfManifest('src/App/App.csproj')).toBe('nuget');
    expect(ecosystemOfManifest('README.md')).toBeNull();
  });

  it('recognises the requirement-file layouts pip users keep (review N1)', () => {
    expect(ecosystemOfManifest('requirements/base.txt')).toBe('pypi');
    expect(ecosystemOfManifest('api/requirements/prod.txt')).toBe('pypi');
    expect(ecosystemOfManifest('dev-requirements.txt')).toBe('pypi');
    expect(ecosystemOfManifest('deploy/requirements-prod.txt')).toBe('pypi');
    expect(ecosystemOfManifest('docs/notes.txt')).toBeNull();
  });

  it('maps a Java archive Trivy scanned to maven (review M-e)', () => {
    expect(ecosystemOfManifest('app/lib/service.jar')).toBe('maven');
    expect(ecosystemOfManifest('target/app.war')).toBe('maven');
  });
});

describe('dependencySubjectOf — a requirements/ file is a manifest', () => {
  it('keeps requirements/base.txt as the manifest instead of claiming there is none', () => {
    expect(dependencySubjectOf(finding({
      tool: 'pip-audit', subcategory: 'dependency', file_path: 'requirements/base.txt', snippet: 'pyyaml@5.3',
    }))).toEqual({ package_name: 'pyyaml', ecosystem: 'pypi', version: '5.3', manifest: 'requirements/base.txt' });
  });
});

describe('validateDependencies', () => {
  it('returns one dependency-provider verdict per dependency finding, and none for the rest', () => {
    const snapshot = snapshotOf({ external_imports: externalImports([ext('src/db.ts', 'lodash')]) });
    const out = validateDependencies({
      snapshot,
      snapshotId: 9,
      treeHash: 'tree-a',
      graph: buildImportGraph(snapshot.imports),
      findings: [
        finding(),
        finding({ fingerprint: 'fp-sast', tool: 'semgrep', subcategory: undefined, line_start: 4, snippet: 'x' }),
      ],
      computedAt: '2026-09-28T00:00:00.000Z',
      projectPath: PROJECT,
      npmResolver: resolverOf({ lodash: '4.17.20' }),
    });
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({
      fingerprint: 'fp1',
      provider: 'dependency',
      verdict: 'reachable',
      snapshot_id: 9,
      tree_hash: 'tree-a',
      computed_at: '2026-09-28T00:00:00.000Z',
    });
  });
});
