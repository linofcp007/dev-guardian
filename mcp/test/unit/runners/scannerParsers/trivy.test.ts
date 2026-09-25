import { readFileSync, writeFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { assessManifestCoverage, trivyParser } from '../../../../src/runners/scannerParsers/trivy.js';
import { makeTempDir, cleanupTempDirs } from '../../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const here = dirname(fileURLToPath(import.meta.url));
const FS_FIXTURE = resolve(here, '../../../fixtures/scanners/trivy-fs.json');
const DOCKERFILE_FIXTURE = resolve(here, '../../../fixtures/scanners/trivy-dockerfile.json');

function read(path: string): string {
  return readFileSync(path, 'utf8');
}

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

  it.each([
    ['devDependencies only', '{"name":"x","devDependencies":{"vitest":"^1.0.0"}}'],
    ['optionalDependencies only', '{"name":"x","optionalDependencies":{"fsevents":"^2.0.0"}}'],
    ['peerDependencies only', '{"name":"x","peerDependencies":{"react":"^18.0.0"}}'],
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

  it('does not flag requirements.txt or go.mod — Trivy scans both without a lockfile', () => {
    const project = makeTempDir('trivy-manifest-');
    writeFileSync(join(project, 'requirements.txt'), 'django==2.0.1\n', 'utf8');
    writeFileSync(join(project, 'go.mod'), 'module x\n\ngo 1.21\n', 'utf8');

    const { gaps } = assessManifestCoverage(project, NO_RESULTS_OUTPUT);
    expect(gaps).toEqual([]);
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
