import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { assessManifestCoverage, manifestEcosystemOfTarget, trivyParser } from '../../../../src/runners/scannerParsers/trivy.js';
import { makeTempDir, cleanupTempDirs } from '../../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const here = dirname(fileURLToPath(import.meta.url));
const FS_FIXTURE = resolve(here, '../../../fixtures/scanners/trivy-fs.json');
const DOCKERFILE_FIXTURE = resolve(here, '../../../fixtures/scanners/trivy-dockerfile.json');

function read(path: string): string {
  return readFileSync(path, 'utf8');
}

describe('trivyParser — the vulnerability’s own aliases', () => {
  const json = JSON.stringify({
    Results: [{
      Target: 'package-lock.json',
      Vulnerabilities: [
        {
          VulnerabilityID: 'CVE-2026-4800', VendorIDs: ['GHSA-r5fr-rjxr-66jc'], PkgName: 'lodash',
          InstalledVersion: '4.17.20', FixedVersion: '4.18.0', Severity: 'HIGH',
          Description: 'This is due to an incomplete fix for CVE-2021-23337.',
        },
        { VulnerabilityID: 'GHSA-xxxx-yyyy-zzzz', PkgName: 'minimist', InstalledVersion: '1.2.5', Severity: 'LOW' },
      ],
    }],
  });

  it('records VendorIDs as aliases — never the CVE a description mentions — outside the fingerprint', () => {
    const { findings } = trivyParser.parse(json);
    expect(findings[0]?.vuln_aliases).toEqual(['GHSA-r5fr-rjxr-66jc']);
    expect(findings[1]?.vuln_aliases).toBeUndefined();
    const withoutAliases = trivyParser.parse(json.replace(',"VendorIDs":["GHSA-r5fr-rjxr-66jc"]', ''));
    expect(withoutAliases.findings[0]?.fingerprint).toBe(findings[0]?.fingerprint);
  });
});

describe('trivyParser (fs scan)', () => {
  it('emits one Finding per Vulnerability and one Finding per License', () => {
    const { findings, cves } = trivyParser.parse(read(FS_FIXTURE));
    expect(findings).toHaveLength(3); // 2 vulns + 1 license
    expect(cves).toHaveLength(2);
  });

  it('maps Trivy severities to canonical Severity', () => {
    const { findings } = trivyParser.parse(read(FS_FIXTURE));
    const medium = findings.find((f) => f.rule_id === 'CVE-2023-26136');
    const high = findings.find((f) => f.rule_id === 'CVE-2022-25883');
    expect(medium?.severity).toBe('medium');
    expect(high?.severity).toBe('high');
  });

  it('emits a ParserCveInput per Vulnerability', () => {
    const { cves } = trivyParser.parse(read(FS_FIXTURE));
    const cve = cves.find((c) => c.cve_id === 'CVE-2022-25883');
    expect(cve?.package_name).toBe('semver');
    expect(cve?.installed_version).toBe('5.7.1');
    expect(cve?.fixed_version).toBe('7.5.2');
  });

  it('sets fix_available=true when FixedVersion is present', () => {
    const { findings } = trivyParser.parse(read(FS_FIXTURE));
    expect(findings.every((f) => (f.rule_id?.startsWith('CVE-') ? f.fix_available === true : true))).toBe(
      true,
    );
  });

  it('maps Licenses to category=license', () => {
    const { findings } = trivyParser.parse(read(FS_FIXTURE));
    const license = findings.find((f) => f.category === 'license');
    expect(license?.subcategory).toBe('agpl-3.0-or-later');
    expect(license?.severity).toBe('high');
  });
});

describe('assessManifestCoverage', () => {
  // Reproduced against Trivy 0.69.3: a bare .csproj (no packages.lock.json)
  // produces a report with NO `Results` key at all.
  const NO_RESULTS_OUTPUT = JSON.stringify({ SchemaVersion: 2, ArtifactType: 'filesystem' });

  it('flags a bare .csproj as a dotnet coverage gap when Trivy saw nothing', () => {
    const project = makeTempDir('trivy-manifest-');
    writeFileSync(join(project, 'Test.csproj'), '<Project></Project>', 'utf8');

    const { gaps, sawAnyResults } = assessManifestCoverage(project, NO_RESULTS_OUTPUT);

    expect(sawAnyResults).toBe(false);
    expect(gaps).toEqual([{ ecosystem: 'dotnet', files: ['Test.csproj'] }]);
  });

  it('flags a bare package.json (no lockfile) as an npm coverage gap', () => {
    const project = makeTempDir('trivy-manifest-');
    writeFileSync(join(project, 'package.json'), '{"name":"x","dependencies":{"lodash":"4.17.4"}}', 'utf8');

    const { gaps } = assessManifestCoverage(project, NO_RESULTS_OUTPUT);
    expect(gaps).toEqual([{ ecosystem: 'npm', files: ['package.json'] }]);
  });

  // Measured against Trivy 0.69.3: a package.json that declares no
  // dependency produces no `Results` key — WITH a package-lock.json as much
  // as without one — so the report is identical to the bare-manifest gap
  // above. It is not one: there is nothing for Trivy to have missed, and no
  // lockfile a user could add would make Trivy say anything else.
  it.each([
    ['no dependency fields at all', '{"name":"x","version":"1.0.0","private":true}'],
    ['empty dependency fields', '{"name":"x","dependencies":{},"devDependencies":{},"workspaces":[]}'],
    ['a byte-order mark before an empty manifest', '\uFEFF{"name":"x"}'],
  ])('does not flag a package.json that declares nothing to audit (%s)', (_label, body) => {
    const project = makeTempDir('trivy-manifest-');
    writeFileSync(join(project, 'package.json'), body, 'utf8');

    const { gaps, sawAnyResults } = assessManifestCoverage(project, NO_RESULTS_OUTPUT);
    expect(sawAnyResults).toBe(false);
    expect(gaps).toEqual([]);
  });

  // The exclusion answers "is there anything to audit?", so a lock file that
  // still locks packages — a stale one, left behind when a dependency was
  // deleted from package.json — is something to audit. The exclusion must
  // not apply then, and the ordinary "did Trivy cover it?" question decides.
  // (Trivy 0.69.3 does cover every shape below: see
  // test/e2e/trivyManifestCoverage.test.ts. These use a report with no
  // Results so that the exclusion's own answer is what is tested.)
  const EMPTY_MANIFEST = '{"name":"x","version":"1.0.0","private":true}';
  const LODASH = { version: '4.17.4', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.4.tgz' };
  it.each([
    [
      'package-lock.json v3 whose root still lists the dependency',
      'package-lock.json',
      JSON.stringify({
        lockfileVersion: 3,
        packages: { '': { name: 'x', dependencies: { lodash: '4.17.4' } }, 'node_modules/lodash': LODASH },
      }),
    ],
    [
      'package-lock.json v3 with only a locked package entry',
      'package-lock.json',
      JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'x' }, 'node_modules/lodash': LODASH } }),
    ],
    ['package-lock.json v1', 'package-lock.json', JSON.stringify({ lockfileVersion: 1, dependencies: { lodash: LODASH } })],
    ['npm-shrinkwrap.json', 'npm-shrinkwrap.json', JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/lodash': LODASH } })],
    ['a package-lock.json that does not parse', 'package-lock.json', '{"lockfileVersion": 3, '],
    ['a yarn.lock that locks a package', 'yarn.lock', '# yarn lockfile v1\n\n\nlodash@4.17.4:\n  version "4.17.4"\n'],
    ['any pnpm-lock.yaml (not read: it may lock something)', 'pnpm-lock.yaml', "lockfileVersion: '9.0'\n"],
    ['any bun.lock (not read: it may lock something)', 'bun.lock', '{}'],
  ])('keeps the gap for a declares-nothing package.json beside %s', (_label, lockName, lockBody) => {
    const project = makeTempDir('trivy-manifest-');
    writeFileSync(join(project, 'package.json'), EMPTY_MANIFEST, 'utf8');
    writeFileSync(join(project, lockName), lockBody, 'utf8');

    const { gaps } = assessManifestCoverage(project, NO_RESULTS_OUTPUT);
    expect(gaps).toEqual([{ ecosystem: 'npm', files: ['package.json'] }]);
  });

  it.each([
    [
      'a package-lock.json that locks only the root',
      'package-lock.json',
      JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'x', version: '1.0.0' } } }),
    ],
    ['a yarn.lock holding only its header', 'yarn.lock', '# THIS IS AN AUTOGENERATED FILE.\n# yarn lockfile v1\n\n\n'],
  ])('still excludes a declares-nothing package.json beside %s', (_label, lockName, lockBody) => {
    const project = makeTempDir('trivy-manifest-');
    writeFileSync(join(project, 'package.json'), EMPTY_MANIFEST, 'utf8');
    writeFileSync(join(project, lockName), lockBody, 'utf8');

    expect(assessManifestCoverage(project, NO_RESULTS_OUTPUT).gaps).toEqual([]);
  });

  it.each([
    ['devDependencies only', '{"name":"x","devDependencies":{"vitest":"^1.0.0"}}'],
    ['optionalDependencies only', '{"name":"x","optionalDependencies":{"fsevents":"^2.0.0"}}'],
    ['peerDependencies only', '{"name":"x","peerDependencies":{"react":"^18.0.0"}}'],
    ['bundleDependencies: true (bundle every dependency)', '{"name":"x","bundleDependencies":true}'],
    ['bundledDependencies: false (a boolean is never read as empty)', '{"name":"x","bundledDependencies":false}'],
    ['dependencies: null', '{"name":"x","dependencies":null}'],
    ['workspaces (the members declare the dependencies)', '{"name":"x","private":true,"workspaces":["packages/*"]}'],
    ['a manifest that does not parse', '{"name": "x", '],
    ['a manifest that is not an object', '["x"]'],
  ])('still flags a package.json that declares, or may declare, dependencies (%s)', (_label, body) => {
    const project = makeTempDir('trivy-manifest-');
    writeFileSync(join(project, 'package.json'), body, 'utf8');

    const { gaps } = assessManifestCoverage(project, NO_RESULTS_OUTPUT);
    expect(gaps).toEqual([{ ecosystem: 'npm', files: ['package.json'] }]);
  });

  it('keeps flagging a bare .csproj with no PackageReference: its dependencies can live outside the file', () => {
    // Directory.Packages.props, Directory.Build.props and the SDK's own
    // framework reference all add packages a .csproj does not list.
    const project = makeTempDir('trivy-manifest-');
    writeFileSync(join(project, 'Api.csproj'), '<Project Sdk="Microsoft.NET.Sdk"></Project>', 'utf8');

    const { gaps } = assessManifestCoverage(project, NO_RESULTS_OUTPUT);
    expect(gaps).toEqual([{ ecosystem: 'dotnet', files: ['Api.csproj'] }]);
  });

  // Trivy reads go.mod itself, no lock file needed — measured on 0.69.3: a
  // go.mod with or without `require` lines gets a `gomod` Result. One that
  // does not parse gets none, logs `Number of language-specific files
  // num=0` and exits 0: that is the gap (review I1).
  it('covers a go.mod Trivy read (a gomod Result in its directory)', () => {
    const project = makeTempDir('trivy-manifest-');
    writeFileSync(join(project, 'go.mod'), 'module x\n\ngo 1.21\n', 'utf8');
    const output = JSON.stringify({ Results: [{ Target: 'go.mod', Type: 'gomod', Vulnerabilities: [] }] });
    expect(assessManifestCoverage(project, output)).toEqual({ gaps: [], sawAnyResults: true });
  });

  it('flags a go.mod Trivy said nothing about (it did not parse) as a go gap', () => {
    const project = makeTempDir('trivy-manifest-');
    writeFileSync(join(project, 'go.mod'), 'module x\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.0 (\n', 'utf8');
    expect(assessManifestCoverage(project, NO_RESULTS_OUTPUT)).toEqual({
      gaps: [{ ecosystem: 'go', files: ['go.mod'] }],
      sawAnyResults: false,
    });
  });

  // Measured against Trivy 0.69.3 (test/e2e/trivyManifestCoverage.test.ts
  // pins it on the Trivy on PATH): `Results: []` for a build.gradle or
  // build.gradle.kts without gradle.lockfile, a PEP 621 pyproject.toml, a
  // Pipfile without Pipfile.lock, a requirements-dev.txt, and an unpinned
  // requirements.txt. Each read `ok`, coverage `full`, 0 findings.
  it.each([
    ['build.gradle', 'dependencies { implementation "org.apache.logging.log4j:log4j-core:2.14.1" }\n', 'gradle'],
    ['build.gradle.kts', 'dependencies { implementation("org.apache.logging.log4j:log4j-core:2.14.1") }\n', 'gradle'],
    ['pyproject.toml', '[project]\nname = "x"\ndependencies = ["django==3.2.0"]\n', 'python'],
    ['Pipfile', '[packages]\ndjango = "==3.2.0"\n', 'python'],
    ['requirements-dev.txt', 'django==3.2.0\n', 'python'],
    ['requirements.txt', 'django\n', 'python'],
  ])('flags a bare %s Trivy said nothing about (%#) as a gap', (file, body, ecosystem) => {
    const project = makeTempDir('trivy-manifest-');
    writeFileSync(join(project, file), body, 'utf8');

    const { gaps, sawAnyResults } = assessManifestCoverage(project, NO_RESULTS_OUTPUT);
    expect(sawAnyResults).toBe(false);
    expect(gaps).toEqual([{ ecosystem, files: [file] }]);
  });

  it.each([
    ['build.gradle', 'gradle', 'gradle.lockfile'],
    ['pyproject.toml', 'poetry', 'poetry.lock'],
    ['pyproject.toml', 'uv', 'uv.lock'],
    ['Pipfile', 'pipenv', 'Pipfile.lock'],
    ['requirements.txt', 'pip', 'requirements.txt'],
  ])('a %s is covered by a Trivy %s Result (%s)', (file, type, target) => {
    const project = makeTempDir('trivy-manifest-');
    writeFileSync(join(project, file), file.endsWith('.txt') ? 'django==3.2.0\n' : '[project]\ndependencies = ["x"]\n', 'utf8');

    const output = JSON.stringify({ Results: [{ Target: target, Type: type, Vulnerabilities: [] }] });
    expect(assessManifestCoverage(project, output)).toEqual({ gaps: [], sawAnyResults: true });
  });

  it('names the Gradle gap beside a covered npm (partial)', () => {
    const project = makeTempDir('trivy-manifest-');
    writeFileSync(join(project, 'package.json'), '{"name":"x"}', 'utf8');
    writeFileSync(join(project, 'package-lock.json'), '{}', 'utf8');
    writeFileSync(join(project, 'build.gradle'), 'plugins { id "java" }\n', 'utf8');

    const output = JSON.stringify({ Results: [{ Target: 'package-lock.json', Type: 'npm', Vulnerabilities: [] }] });
    expect(assessManifestCoverage(project, output)).toEqual({
      gaps: [{ ecosystem: 'gradle', files: ['build.gradle'] }],
      sawAnyResults: true,
    });
  });

  // The npm precedent: a manifest that declares nothing is no gap — no lock
  // file a user could add would make Trivy say anything else, and flagging
  // it made every tool-config-only pyproject.toml a permanently incomplete scan.
  it.each([
    ['pyproject.toml', '[tool.ruff]\nline-length = 100\n\n[build-system]\nrequires = ["setuptools"]\n'],
    ['pyproject.toml', '[project]\nname = "x"\nversion = "1.0"\n'],
    ['pyproject.toml', '[project]\nname = "x"\ndependencies = []\n'],
    ['pyproject.toml', '[tool.poetry]\nname = "x"\n\n[tool.poetry.dependencies]\npython = "^3.10"\n'],
    ['requirements.txt', '# nothing pinned yet\n\n'],
    ['Pipfile', '[[source]]\nurl = "https://pypi.org/simple"\n\n[packages]\n\n[dev-packages]\n'],
  ])('does not flag a %s that declares nothing to audit', (file, body) => {
    const project = makeTempDir('trivy-manifest-');
    writeFileSync(join(project, file), body, 'utf8');
    expect(assessManifestCoverage(project, NO_RESULTS_OUTPUT)).toEqual({ gaps: [], sawAnyResults: false });
  });

  it.each([
    ['[project]\ndependencies = [\n  "django==3.2.0",\n]\n'],
    ['[project.optional-dependencies]\ndev = ["pytest"]\n'],
    ['[tool.poetry.dependencies]\npython = "^3.10"\ndjango = "3.2.0"\n'],
    ['[tool.poetry.group.dev.dependencies]\npytest = "^8"\n'],
    ['[dependency-groups]\ndev = ["pytest"]\n'],
    ['[project\n'],
  ])('keeps flagging a pyproject.toml that may declare something (%#)', (body) => {
    const project = makeTempDir('trivy-manifest-');
    writeFileSync(join(project, 'pyproject.toml'), body, 'utf8');
    expect(assessManifestCoverage(project, NO_RESULTS_OUTPUT).gaps).toEqual([
      { ecosystem: 'python', files: ['pyproject.toml'] },
    ]);
  });

  // Follow-up 2, item 2: a setuptools project. Trivy reads neither setup.py
  // nor setup.cfg (measured on 0.69.3: a setup.py with
  // install_requires=["django==3.2.0"] beside a build-system-only
  // pyproject.toml read full, 0 findings).
  it.each([
    ['setup.py', 'from setuptools import setup\nsetup(name="x", install_requires=["django==3.2.0"])\n'],
    ['setup.cfg', '[metadata]\nname = x\n\n[options]\ninstall_requires =\n    django==3.2.0\n'],
    ['setup.cfg', '[options.extras_require]\ndev = pytest\n'],
  ])('flags a %s that declares dependencies as a python gap (%#)', (file, body) => {
    const project = makeTempDir('trivy-manifest-');
    writeFileSync(join(project, file), body, 'utf8');
    writeFileSync(join(project, 'pyproject.toml'), '[build-system]\nrequires = ["setuptools"]\n', 'utf8');
    expect(assessManifestCoverage(project, NO_RESULTS_OUTPUT).gaps).toEqual([{ ecosystem: 'python', files: [file] }]);
  });

  it.each([
    ['setup.py', 'from setuptools import setup\nsetup(name="x", version="1.0")\n'],
    ['setup.cfg', '[metadata]\nname = x\nversion = 1.0\n'],
  ])('does not flag a %s that declares no dependency', (file, body) => {
    const project = makeTempDir('trivy-manifest-');
    writeFileSync(join(project, file), body, 'utf8');
    expect(assessManifestCoverage(project, NO_RESULTS_OUTPUT).gaps).toEqual([]);
  });

  it('maps each new lock file Target to its ecosystem, at any depth', () => {
    expect(manifestEcosystemOfTarget('gradle.lockfile')).toBe('gradle');
    expect(manifestEcosystemOfTarget('app/gradle.lockfile')).toBe('gradle');
    expect(manifestEcosystemOfTarget('requirements.txt')).toBe('python');
    expect(manifestEcosystemOfTarget('svc\\poetry.lock')).toBe('python');
    expect(manifestEcosystemOfTarget('uv.lock')).toBe('python');
    expect(manifestEcosystemOfTarget('Pipfile.lock')).toBe('python');
    expect(manifestEcosystemOfTarget('go.mod')).toBe('go');
    expect(manifestEcosystemOfTarget('svc/go.mod')).toBe('go');
    expect(manifestEcosystemOfTarget('pom.xml')).toBeNull();
  });

  it('does not flag an ecosystem Trivy DID produce Results for', () => {
    const project = makeTempDir('trivy-manifest-');
    writeFileSync(join(project, 'package.json'), '{"name":"x"}', 'utf8');
    writeFileSync(join(project, 'package-lock.json'), '{}', 'utf8');

    const output = JSON.stringify({
      Results: [{ Target: 'package-lock.json', Type: 'npm', Vulnerabilities: [] }],
    });
    const { gaps, sawAnyResults } = assessManifestCoverage(project, output);
    expect(sawAnyResults).toBe(true);
    expect(gaps).toEqual([]);
  });

  it('reports a partial gap when one ecosystem is covered and another is not', () => {
    const project = makeTempDir('trivy-manifest-');
    writeFileSync(join(project, 'package.json'), '{"name":"x"}', 'utf8');
    writeFileSync(join(project, 'package-lock.json'), '{}', 'utf8');
    writeFileSync(join(project, 'Api.csproj'), '<Project></Project>', 'utf8');

    const output = JSON.stringify({
      Results: [{ Target: 'package-lock.json', Type: 'npm', Vulnerabilities: [] }],
    });
    const { gaps, sawAnyResults } = assessManifestCoverage(project, output);
    expect(sawAnyResults).toBe(true);
    expect(gaps).toEqual([{ ecosystem: 'dotnet', files: ['Api.csproj'] }]);
  });

  it('reports nothing when no manifest is present at all (genuinely nothing to scan)', () => {
    const project = makeTempDir('trivy-manifest-');
    const { gaps, sawAnyResults } = assessManifestCoverage(project, NO_RESULTS_OUTPUT);
    expect(gaps).toEqual([]);
    expect(sawAnyResults).toBe(false);
  });
});

/**
 * Review I1: the check read the project ROOT only, calling a buried manifest
 * "Trivy's own concern" — and Trivy skips one without a lock file in
 * silence. Reproduced on 0.69.3 with scan_deps: web/package.json (lodash
 * 4.17.4, no lock) and api/pyproject.toml + api/requirements-dev.txt read
 * trivy ok, coverage full, 0 findings, no Results key. The tree is walked
 * now, and each manifest's DIRECTORY is compared with the directories of
 * the Results of its ecosystem — never the Type alone, which a root lock
 * file already satisfies.
 */
describe('assessManifestCoverage — the whole tree', () => {
  const NO_RESULTS_OUTPUT = JSON.stringify({ SchemaVersion: 2, ArtifactType: 'filesystem' });

  function tree(files: Record<string, string>): string {
    const project = makeTempDir('trivy-manifest-tree-');
    for (const [rel, body] of Object.entries(files)) {
      mkdirSync(dirname(join(project, rel)), { recursive: true });
      writeFileSync(join(project, rel), body, 'utf8');
    }
    return project;
  }
  const results = (...rs: Array<[string, string]>): string =>
    JSON.stringify({ Results: rs.map(([Target, Type]) => ({ Target, Type, Vulnerabilities: [] })) });

  const LODASH_PKG = '{"name":"web","dependencies":{"lodash":"4.17.4","minimist":"0.0.8"}}';
  const DJANGO_PEP621 = '[project]\nname = "api"\ndependencies = ["django==2.2.0"]\n';

  it('names manifests buried below the root that Trivy said nothing about (the reproduction)', () => {
    const project = tree({
      'web/package.json': LODASH_PKG,
      'api/pyproject.toml': DJANGO_PEP621,
      'api/requirements-dev.txt': 'pytest==7.0.0\n',
    });
    expect(assessManifestCoverage(project, NO_RESULTS_OUTPUT)).toEqual({
      gaps: [
        { ecosystem: 'npm', files: ['web/package.json'] },
        { ecosystem: 'python', files: ['api/pyproject.toml', 'api/requirements-dev.txt'] },
      ],
      sawAnyResults: false,
    });
  });

  it('a root lock file does not cover a nested manifest of the same ecosystem (Type alone is not coverage)', () => {
    const project = tree({
      'package.json': '{"name":"root","dependencies":{"express":"4.0.0"}}',
      'package-lock.json': '{}',
      'web/package.json': LODASH_PKG,
    });
    expect(assessManifestCoverage(project, results(['package-lock.json', 'npm']))).toEqual({
      gaps: [{ ecosystem: 'npm', files: ['web/package.json'] }],
      sawAnyResults: true,
    });
  });

  it('a nested manifest is covered by a Result in its own directory', () => {
    const project = tree({ 'web/package.json': LODASH_PKG, 'web/package-lock.json': '{}', 'svc/go.mod': 'module x\n' });
    expect(assessManifestCoverage(project, results(['web/package-lock.json', 'npm'], ['svc/go.mod', 'gomod']))).toEqual({
      gaps: [],
      sawAnyResults: true,
    });
  });

  it('Results in the other separator style still count (a Windows Target)', () => {
    const project = tree({ 'web/package.json': LODASH_PKG });
    expect(assessManifestCoverage(project, results(['web\\package-lock.json', 'npm'])).gaps).toEqual([]);
  });

  it('a different ecosystem in the same directory does not cover it', () => {
    const project = tree({ 'api/pyproject.toml': DJANGO_PEP621, 'api/package.json': LODASH_PKG });
    expect(assessManifestCoverage(project, results(['api/package-lock.json', 'npm'])).gaps).toEqual([
      { ecosystem: 'python', files: ['api/pyproject.toml'] },
    ]);
  });

  it('an npm workspace member is covered by the root lock file that locks it', () => {
    const project = tree({
      'package.json': '{"name":"root","private":true,"workspaces":["packages/*","!packages/legacy"]}',
      'packages/a/package.json': LODASH_PKG,
      'packages/legacy/package.json': LODASH_PKG,
      'tools/x/package.json': LODASH_PKG,
    });
    expect(assessManifestCoverage(project, results(['package-lock.json', 'npm'])).gaps).toEqual([
      // Excluded by the root's own negation, and not a member at all.
      { ecosystem: 'npm', files: ['packages/legacy/package.json', 'tools/x/package.json'] },
    ]);
  });

  it('pnpm, yarn ({packages}), Cargo and uv workspaces cover their members', () => {
    const project = tree({
      'pnpm-workspace.yaml': "packages:\n  - 'apps/**'\n",
      'package.json': '{"name":"root","private":true}',
      'apps/web/site/package.json': LODASH_PKG,
      'y/package.json': '{"name":"y","private":true,"workspaces":{"packages":["libs/*"]}}',
      'y/libs/one/package.json': LODASH_PKG,
      'Cargo.toml': '[workspace]\nmembers = [\n  "crates/*",\n]\nexclude = ["crates/old"]\n',
      'crates/core/Cargo.toml': '[package]\nname = "core"\n[dependencies]\nserde = "1"\n',
      'crates/old/Cargo.toml': '[package]\nname = "old"\n[dependencies]\nserde = "1"\n',
      'py/pyproject.toml': '[tool.uv.workspace]\nmembers = ["pkgs/*"]\n',
      'py/pkgs/lib/pyproject.toml': DJANGO_PEP621,
    });
    const output = results(
      ['pnpm-lock.yaml', 'pnpm'],
      ['y/yarn.lock', 'yarn'],
      ['Cargo.lock', 'cargo'],
      ['py/uv.lock', 'uv'],
    );
    expect(assessManifestCoverage(project, output).gaps).toEqual([{ ecosystem: 'cargo', files: ['crates/old/Cargo.toml'] }]);
  });

  it('never walks into dependency, build, version-control, cache or .guardianignore directories', () => {
    const project = tree({
      'node_modules/lodash/package.json': LODASH_PKG,
      'vendor/x/composer.json': '{"require":{"a/b":"1.0"}}',
      // Round 4, item 5: bower's and jspm's dependency directories.
      'bower_components/x/package.json': LODASH_PKG,
      'jspm_packages/npm/x@1.0.0/package.json': LODASH_PKG,
      'dist/package.json': LODASH_PKG,
      '.cache/package.json': LODASH_PKG,
      '.hg/store/package.json': LODASH_PKG,
      '.svn/pristine/package.json': LODASH_PKG,
      '.yarn/cache/package.json': LODASH_PKG,
      '.pnpm-store/v3/package.json': LODASH_PKG,
      '.npm/_cacache/package.json': LODASH_PKG,
      'fixtures/vuln/package.json': LODASH_PKG,
      'app/package.json': LODASH_PKG,
    });
    const ignores = (rel: string): boolean => rel === 'fixtures' || rel.startsWith('fixtures/');
    expect(assessManifestCoverage(project, NO_RESULTS_OUTPUT, { ignores }).gaps).toEqual([
      { ecosystem: 'npm', files: ['app/package.json'] },
    ]);
  });

  /**
   * Round 4, item 4: the walk skipped every hidden directory, but Trivy reads
   * them — a GitHub composite action's `.github/actions/notify/package.json`
   * with no lock read full. Hidden directories are walked now, all but
   * version control and tool caches.
   */
  it('walks hidden directories Trivy reads: a composite action\'s manifest is named', () => {
    const project = tree({
      'package.json': '{"name":"root","dependencies":{"express":"4.0.0"}}',
      'package-lock.json': '{}',
      '.github/actions/notify/package.json': LODASH_PKG,
    });
    expect(assessManifestCoverage(project, results(['package-lock.json', 'npm'])).gaps).toEqual([
      { ecosystem: 'npm', files: ['.github/actions/notify/package.json'] },
    ]);
  });

  it('a nested manifest that declares nothing is no gap, as at the root', () => {
    const project = tree({ 'tools/package.json': '{"name":"tools","private":true,"scripts":{"x":"y"}}' });
    expect(assessManifestCoverage(project, NO_RESULTS_OUTPUT).gaps).toEqual([]);
  });

  it('a walk that reaches its directory ceiling says so', () => {
    const project = tree({ 'a/b/c/package.json': LODASH_PKG, 'package.json': LODASH_PKG });
    const r = assessManifestCoverage(project, NO_RESULTS_OUTPUT, { maxDirs: 2 });
    expect(r.walkIncomplete).toMatch(/2 directories/);
    // What it did see is still reported.
    expect(r.gaps[0]?.files).toContain('package.json');
  });
});

describe('trivyParser (Dockerfile config scan)', () => {
  it('emits one Finding per Misconfiguration with category=security', () => {
    const { findings, cves } = trivyParser.parse(read(DOCKERFILE_FIXTURE));
    expect(findings).toHaveLength(1);
    expect(cves).toEqual([]);
    const [f] = findings;
    expect(f?.category).toBe('security');
    expect(f?.rule_id).toBe('DS002');
    expect(f?.severity).toBe('high');
    expect(f?.line_start).toBe(1);
  });
});
