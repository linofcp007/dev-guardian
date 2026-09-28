/**
 * `export_vex` — one VEX statement per CVE of the latest usable dependency
 * scan, written under `.guardian/reports/vex-*`, with what it could not know
 * said in the result rather than left for the reader to infer.
 */
import { afterAll, afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import type { PluginContext } from '../../src/context.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { externalImports } from '../../src/surface/moduleEdges.js';
import { TOOLS } from '../../src/tools/index.js';
import type { Finding } from '../../src/types.js';
import '../../src/tools/exportVex.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { okResult } from '../helpers/toolResult.js';

afterAll(cleanupTempDirs);

let ctx: PluginContext;
let projectPath = '';

beforeEach(() => {
  const db = new Database(':memory:');
  runMigrations(db);
  ctx = {
    storage: new Storage(db),
    shell: null,
    scriptsDir: join(process.cwd(), '..', 'scripts'),
    progressNotifier: { notify: async () => {} } as unknown as PluginContext['progressNotifier'],
  };
  projectPath = resolveProjectPath(makeTempDir('guardian-export-vex-')).path;
});

afterEach(() => ctx.storage.close());

interface ExportResult {
  format: string;
  file_path: string | null;
  statements: { total: number; not_affected: number; affected: number; under_investigation: number };
  deps_scan: { scan_id: string } | null;
  sbom: { scan_id: string; file_path: string } | null;
  surface_snapshot: { id: number } | null;
  product: { id: string; source: string };
  unknowns: string[];
  note?: string;
}

async function exportVex(input: Record<string, unknown> = {}) {
  const tool = TOOLS.find((t) => t.name === 'export_vex');
  if (tool === undefined) throw new Error('export_vex is not registered');
  return okResult<ExportResult>(await tool.handler({ project_path: projectPath, ...input }, ctx));
}

function trivyCve(fingerprint: string, cve: string, pkg: string, version: string): Finding {
  return {
    fingerprint, identity: `id-${fingerprint}`, tool: 'trivy', rule_id: cve, severity: 'high',
    category: 'security', subcategory: 'cve', title: `${cve} in ${pkg}`, file_path: 'package-lock.json',
    snippet: `${pkg}@${version}->9.9.9`, fix_available: true,
  };
}

/** A completed deps scan holding the lodash and minimist CVEs, findings and scan_cves alike. */
function seedDepsScan(treeHash = 'tree-1'): void {
  ctx.storage.scans.insert({ scan_id: 'deps-1', scan_type: 'deps', project_path: projectPath, tree_hash: treeHash });
  ctx.storage.findings.bulkInsert([
    { ...trivyCve('fp-lodash', 'CVE-2021-23337', 'lodash', '4.17.20'), scan_id: 'deps-1' },
    { ...trivyCve('fp-minimist', 'CVE-2021-44906', 'minimist', '1.2.5'), scan_id: 'deps-1' },
  ]);
  ctx.storage.cves.bulkUpsert([
    { scan_id: 'deps-1', cve_id: 'CVE-2021-23337', package_name: 'lodash', installed_version: '4.17.20', fixed_version: '4.17.21', severity: 'high' },
    { scan_id: 'deps-1', cve_id: 'CVE-2021-44906', package_name: 'minimist', installed_version: '1.2.5', fixed_version: '1.2.6', severity: 'critical' },
  ]);
  ctx.storage.scans.finalize({
    scan_id: 'deps-1', status: 'completed', tools_run: [{ name: 'trivy', status: 'ok' }], missing_tools: [],
  });
}

/** A snapshot whose route file imports lodash (and nothing imports minimist). */
function seedSurface(treeHash = 'tree-1'): number {
  // The project's code loads the vulnerable lodash 4.17.20 (and minimist 1.2.5).
  writeFileSync(join(projectPath, 'package-lock.json'), JSON.stringify({
    lockfileVersion: 3,
    packages: { 'node_modules/lodash': { version: '4.17.20' }, 'node_modules/minimist': { version: '1.2.5' } },
  }));
  return ctx.storage.surface.insert({
    project_path: projectPath,
    tree_hash: treeHash,
    snapshot: {
      routes: [{
        method: 'GET', provenance: 'code', path_raw: '/', path_resolved: '/', path_partial: false,
        file: join(projectPath, 'src', 'app.ts'), line: 1, framework: 'express', language: 'typescript',
        auth_hint: 'unknown', params: [], confidence: 'high',
      }],
      env_vars: [], ports: [], webhooks: [], coverage: [], tools_run: [], missing_tools: [],
      spec_files: [], spec_diff: null, imports: [],
      external_imports: externalImports([{ file: 'src/app.ts', specifier: 'lodash', language: 'typescript' }]),
    },
  }).id;
}

function seedSbom(treeHash = '', startedAt?: string): string {
  const file = join(projectPath, 'sbom.cdx.json');
  writeFileSync(file, JSON.stringify({
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    metadata: { component: { type: 'application', name: 'shop', purl: 'pkg:npm/shop@1.0.0' } },
    components: [
      { type: 'library', name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20' },
      { type: 'library', name: 'minimist', version: '1.2.5', purl: 'pkg:npm/minimist@1.2.5' },
    ],
  }));
  ctx.storage.scans.insert({ scan_id: 'sbom-1', scan_type: 'sbom', project_path: projectPath, tree_hash: treeHash });
  if (startedAt !== undefined) {
    ctx.storage.rawHandle().prepare('UPDATE scans SET started_at = ? WHERE id = ?').run(startedAt, 'sbom-1');
  }
  ctx.storage.scans.finalize({
    scan_id: 'sbom-1', status: 'completed', tools_run: [{ name: 'syft', status: 'ok' }], missing_tools: [],
    meta: { format: 'cyclonedx-json', file_path: file },
  });
  return file;
}

function suppressMinimistAsNotAffected(): void {
  ctx.storage.suppressions.insert({
    finding_fingerprint: 'fp-minimist',
    finding_identity: 'id-fp-minimist',
    reason: 'dev-only',
    project_path: projectPath,
    vex_status: 'not_affected',
    vex_justification: 'component_not_present',
  });
}

describe('export_vex', () => {
  it('writes an OpenVEX document with one statement per CVE, statuses from VEX suppressions and reachability', async () => {
    seedDepsScan();
    seedSurface();
    seedSbom();
    suppressMinimistAsNotAffected();

    const r = await exportVex();

    expect(r.format).toBe('openvex');
    expect(r.statements).toEqual({ total: 2, not_affected: 1, affected: 1, under_investigation: 0 });
    expect(r.unknowns).toEqual([]);
    expect(r.product).toEqual({ id: 'pkg:npm/shop@1.0.0', source: 'sbom' });
    if (r.file_path === null) throw new Error('no document written');
    expect(r.file_path).toMatch(/[\\/]\.guardian[\\/]reports[\\/]vex-[^\\/]+[\\/]vex\.openvex\.json$/);

    const doc = JSON.parse(readFileSync(r.file_path, 'utf8')) as {
      '@context': string;
      statements: Array<{ vulnerability: { name: string }; status: string; justification?: string; products: unknown[] }>;
    };
    expect(doc['@context']).toBe('https://openvex.dev/ns/v0.2.0');
    const byCve = new Map(doc.statements.map((s) => [s.vulnerability.name, s]));
    expect(byCve.get('CVE-2021-23337')?.status).toBe('affected');
    expect(byCve.get('CVE-2021-44906')).toMatchObject({ status: 'not_affected', justification: 'component_not_present' });
    expect(byCve.get('CVE-2021-44906')?.products).toEqual([{
      '@id': 'pkg:npm/shop@1.0.0',
      identifiers: { purl: 'pkg:npm/shop@1.0.0' },
      subcomponents: [{ '@id': 'pkg:npm/minimist@1.2.5', identifiers: { purl: 'pkg:npm/minimist@1.2.5' } }],
    }]);
  });

  it('writes CycloneDX when asked', async () => {
    seedDepsScan();
    seedSurface();
    seedSbom();

    const r = await exportVex({ format: 'cyclonedx' });

    if (r.file_path === null) throw new Error('no document written');
    expect(r.file_path).toMatch(/vex\.cdx\.json$/);
    const doc = JSON.parse(readFileSync(r.file_path, 'utf8')) as { bomFormat: string; specVersion: string; vulnerabilities: unknown[] };
    expect(doc).toMatchObject({ bomFormat: 'CycloneDX', specVersion: '1.6' });
    expect(doc.vulnerabilities).toHaveLength(2);
  });

  it('says what it did not know: no SBOM, no surface snapshot — and marks nothing affected without one', async () => {
    seedDepsScan();

    const r = await exportVex();

    expect(r.statements).toEqual({ total: 2, not_affected: 0, affected: 0, under_investigation: 2 });
    const unknowns = r.unknowns.join(' | ');
    expect(unknowns).toMatch(/no SBOM/);
    // Packages are still named: purls are built from ecosystem, name and version.
    expect(unknowns).not.toMatch(/carry no purl/);
    expect(unknowns).toMatch(/map_attack_surface/);
    expect(r.sbom).toBeNull();
    expect(r.surface_snapshot).toBeNull();
    // The product can only be named by the directory, and it says so.
    expect(r.product).toEqual({ id: `pkg:generic/${encodeURIComponent(basename(projectPath))}`, source: 'directory' });
    expect(r.file_path).not.toBeNull();
  });

  it('writes nothing, and says it measured nothing, when the project has no usable dependency scan', async () => {
    const r = await exportVex();

    expect(r.file_path).toBeNull();
    expect(r.deps_scan).toBeNull();
    expect(r.statements.total).toBe(0);
    expect(r.unknowns.join(' | ')).toMatch(/no usable dependency scan/);
    expect(r.note).toMatch(/not a statement that the project has no vulnerabilities/);
    expect(existsSync(join(projectPath, '.guardian', 'reports'))).toBe(false);
  });

  it('writes nothing when the dependency scan measured no CVE — an empty VEX document is not valid OpenVEX', async () => {
    ctx.storage.scans.insert({ scan_id: 'deps-0', scan_type: 'deps', project_path: projectPath, tree_hash: 't' });
    ctx.storage.scans.finalize({
      scan_id: 'deps-0', status: 'completed', tools_run: [{ name: 'trivy', status: 'ok' }], missing_tools: [],
    });

    const r = await exportVex();

    expect(r.file_path).toBeNull();
    expect(r.deps_scan?.scan_id).toBe('deps-0');
    expect(r.note).toMatch(/0 vulnerabilities/);
  });

  it('states a PYSEC-only advisory a scan recorded no CVE row for (review M3)', async () => {
    // pip-audit writes a scan_cves row only for a vulnerability with a CVE
    // alias; a PYSEC-only one exists only as a finding.
    ctx.storage.scans.insert({ scan_id: 'deps-py', scan_type: 'deps_audit', project_path: projectPath, tree_hash: 't' });
    ctx.storage.findings.bulkInsert([{
      scan_id: 'deps-py', fingerprint: 'fp-pysec', identity: 'id-pysec', tool: 'pip-audit', rule_id: 'PYSEC-2024-60',
      severity: 'medium', category: 'security', subcategory: 'dependency', title: 'PYSEC-2024-60 in jinja2 3.1.3',
      file_path: 'requirements.txt', snippet: 'jinja2@3.1.3', fix_available: true,
    }]);
    ctx.storage.scans.finalize({
      scan_id: 'deps-py', status: 'completed', tools_run: [{ name: 'pip-audit', status: 'ok' }], missing_tools: [],
    });

    const r = await exportVex();

    expect(r.statements.total).toBe(1);
    if (r.file_path === null) throw new Error('no document written');
    const doc = JSON.parse(readFileSync(r.file_path, 'utf8')) as {
      statements: Array<{ vulnerability: { name: string; '@id'?: string }; products: Array<{ subcomponents?: unknown[] }> }>;
    };
    expect(doc.statements[0]?.vulnerability).toEqual({ '@id': 'https://osv.dev/vulnerability/PYSEC-2024-60', name: 'PYSEC-2024-60' });
    expect(doc.statements[0]?.products[0]?.subcomponents).toEqual([
      { '@id': 'pkg:pypi/jinja2@3.1.3', identifiers: { purl: 'pkg:pypi/jinja2@3.1.3' } },
    ]);
  });

  it('never writes the absolute project path into the document, even when the SBOM names the product by it', async () => {
    // Syft (and Trivy fs) name a directory source's product by the path they
    // were given — absolute here, as generate_sbom passes it. A VEX document
    // is made to be shared; the local directory layout is not the product.
    seedDepsScan();
    const file = join(projectPath, 'sbom.cdx.json');
    writeFileSync(file, JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      metadata: { component: { type: 'file', name: projectPath } },
      components: [{ type: 'library', name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20' }],
    }));
    ctx.storage.scans.insert({ scan_id: 'sbom-abs', scan_type: 'sbom', project_path: projectPath, tree_hash: '' });
    ctx.storage.scans.finalize({
      scan_id: 'sbom-abs', status: 'completed', tools_run: [{ name: 'syft', status: 'ok' }], missing_tools: [],
      meta: { format: 'cyclonedx-json', file_path: file },
    });

    for (const format of ['openvex', 'cyclonedx']) {
      const r = await exportVex({ format });
      if (r.file_path === null) throw new Error('no document written');
      const text = readFileSync(r.file_path, 'utf8');
      expect(text).not.toContain(JSON.stringify(projectPath).slice(1, -1));
      expect(text).not.toContain(projectPath);
    }
    const cdx = await exportVex({ format: 'cyclonedx' });
    if (cdx.file_path === null) throw new Error('no document written');
    const doc = JSON.parse(readFileSync(cdx.file_path, 'utf8')) as { metadata: { component: { name: string } } };
    expect(doc.metadata.component.name).toBe(basename(projectPath));
  });

  it('does not trust the product purl of an SBOM older than the dependency scan, and says so', async () => {
    seedDepsScan();
    seedSurface();
    seedSbom('', '2000-01-01T00:00:00.000Z');

    const r = await exportVex();

    expect(r.unknowns.join(' | ')).toMatch(/SBOM .*older than the dependency scan/);
    expect(r.product.source).toBe('directory');
    // The packages are still named: a purl is name + version, whatever its age.
    if (r.file_path === null) throw new Error('no document written');
    expect(readFileSync(r.file_path, 'utf8')).toContain('pkg:npm/lodash@4.17.20');
  });

  it('does not trust the product purl of an SBOM of another tree, and says so', async () => {
    seedDepsScan('tree-1');
    seedSurface('tree-1');
    seedSbom('tree-older');

    const r = await exportVex();

    expect(r.unknowns.join(' | ')).toMatch(/SBOM .*another tree/);
    expect(r.product.source).toBe('directory');
  });

  it('trusts an SBOM of the same tree as the dependency scan', async () => {
    seedDepsScan('tree-1');
    seedSurface('tree-1');
    seedSbom('tree-1', '2000-01-01T00:00:00.000Z');

    const r = await exportVex();

    expect(r.product).toEqual({ id: 'pkg:npm/shop@1.0.0', source: 'sbom' });
    expect(r.unknowns).toEqual([]);
  });

  it('names a surface snapshot of a different tree than the dependency scan', async () => {
    seedDepsScan('tree-deps');
    seedSurface('tree-surface');
    seedSbom();

    const r = await exportVex();

    expect(r.unknowns.join(' | ')).toMatch(/different tree/);
  });
});
