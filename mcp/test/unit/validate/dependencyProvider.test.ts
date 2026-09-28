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
  prepareDependencyIndex,
  validateDependencies,
  type DependencySubject,
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

function assess(subject: DependencySubject, over: Partial<AttackSurfaceSnapshot> = {}) {
  const snapshot = snapshotOf(over);
  const index = prepareDependencyIndex({
    snapshot,
    graph: buildImportGraph(snapshot.imports),
    projectPath: PROJECT,
  });
  return assessDependency(subject, index);
}

const npm = (name: string): DependencySubject => ({ package_name: name, ecosystem: 'npm' });
const pypi = (name: string): DependencySubject => ({ package_name: name, ecosystem: 'pypi' });

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
    const a = assess({ package_name: 'github.com/gin-gonic/gin', ecosystem: 'golang' }, {
      external_imports: externalImports([ext('main.go', 'github.com/gin-gonic/gin', 'go')]),
    });
    expect(a.verdict).toBe('unknown');
    expect(a.coverage_gaps.join(' | ')).toMatch(/golang/);
  });

  it('answers unknown when the ecosystem could not be determined', () => {
    const a = assess({ package_name: 'lodash', ecosystem: null }, {
      external_imports: externalImports([ext('src/db.ts', 'lodash')]),
    });
    expect(a.verdict).toBe('unknown');
    expect(a.coverage_gaps.join(' | ')).toMatch(/ecosystem/);
  });

  it('says the graph was cut when an importer is not shown reachable from a truncated graph', () => {
    const snapshot = snapshotOf({ external_imports: externalImports([ext('src/cli.ts', 'lodash')]) });
    const graph = { ...buildImportGraph(snapshot.imports), truncated: true };
    const a = assessDependency(npm('lodash'), prepareDependencyIndex({ snapshot, graph, projectPath: PROJECT }));
    expect(a.verdict).toBe('imported');
    expect(a.coverage_gaps.join(' | ')).toMatch(/truncated/);
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
    expect(dependencySubjectOf(finding())).toEqual({ package_name: 'lodash', ecosystem: 'npm' });
    expect(dependencySubjectOf(finding({ file_path: 'api/requirements.txt', snippet: 'PyYAML@5.3->5.4' })))
      .toEqual({ package_name: 'PyYAML', ecosystem: 'pypi' });
    expect(dependencySubjectOf(finding({ file_path: 'go.sum', snippet: 'golang.org/x/net@v0.1.0->v0.7.0' })))
      .toEqual({ package_name: 'golang.org/x/net', ecosystem: 'golang' });
  });

  it('keeps a scoped npm name whole', () => {
    expect(dependencySubjectOf(finding({ snippet: '@babel/traverse@7.22.0->7.23.2' })))
      .toEqual({ package_name: '@babel/traverse', ecosystem: 'npm' });
  });

  it('knows the ecosystem of npm-audit and pip-audit by the tool', () => {
    expect(dependencySubjectOf(finding({ tool: 'npm-audit', subcategory: 'dependency', snippet: 'lodash@<4.17.21' })))
      .toEqual({ package_name: 'lodash', ecosystem: 'npm' });
    expect(dependencySubjectOf(finding({ tool: 'pip-audit', subcategory: 'dependency', file_path: 'x', snippet: 'jinja2@2.10' })))
      .toEqual({ package_name: 'jinja2', ecosystem: 'pypi' });
  });

  it('leaves the ecosystem unknown for a target that is not a manifest (an image)', () => {
    expect(dependencySubjectOf(finding({ file_path: 'alpine:3.18 (alpine 3.18.4)', snippet: 'openssl@3.1.2->3.1.4' })))
      .toEqual({ package_name: 'openssl', ecosystem: null });
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
