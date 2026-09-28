/**
 * `export_vex` — a VEX document (OpenVEX, or CycloneDX VEX) for one project:
 * one statement per vulnerability (and package version) of its latest usable
 * dependency scan.
 *
 * This module is wiring: it reads storage, the SBOM file and the surface
 * snapshot, and writes the document. Every status rule is in
 * `../vex/statements.ts`; every field name in `../vex/render.ts`, with the
 * specifications they follow.
 *
 *   - Vulnerabilities: `scan_cves` of the newest usable scan of a CVE-source
 *     type (`CVE_SOURCE_SCAN_TYPES`, judged on its `deps` slot — the
 *     dashboard's and `risk_score`'s read) and that scan's vulnerability
 *     findings, tied by their own ids (`../vex/statements.ts`).
 *   - Purls: the newest completed `generate_sbom` scan of the project, read
 *     from its file on disk, else built from ecosystem, name and version; the
 *     SBOM's PRODUCT purl only when it describes the dependency scan's tree
 *     (`sbomTrust`).
 *   - Reachability: the dependency provider over the project's latest
 *     `map_attack_surface` snapshot, computed here rather than read from
 *     stored `validate_finding` verdicts, which may be of an older snapshot.
 *
 * What it could not know is returned in `unknowns`, one sentence each — no
 * SBOM, no snapshot, a snapshot of another tree, a partial dependency scan —
 * because a VEX document that is quietly thinner than it looks is exactly
 * the "clean because nothing looked" this project refuses to report.
 *
 * Nothing is written when there is nothing to state: no usable dependency
 * scan, or one that measured no vulnerability. OpenVEX requires at least one
 * statement, and an empty document would read as "not affected by anything".
 *
 * No network, no subprocess; one file under `.guardian/reports/vex-*`.
 */

import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, join, posix, win32 } from 'node:path';
import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { findLatestUsable } from '../history/openSet.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { resolveVersion } from '../platform/version.js';
import { ProjectPath } from '../schemas.js';
import { CVE_SOURCE_SCAN_TYPES, type ScanRecord, type ToolResult } from '../types.js';
import { prepareDependencyIndex, type DependencyIndex } from '../validate/dependencyProvider.js';
import { buildImportGraph } from '../validate/importGraph.js';
import { makeNpmResolver } from '../validate/npmResolve.js';
import { renderCycloneDxVex, renderOpenVex } from '../vex/render.js';
import { parseSbomInventory, type SbomInventory } from '../vex/sbom.js';
import { buildVexStatements, type VexStatement } from '../vex/statements.js';
import { registerToolModule, type ToolModule } from './index.js';
import { ensureReportDir } from './scanHelpers.js';

const SAMPLE_SIZE = 20;
const DEFAULT_AUTHOR = 'Unknown Author';

const inputSchema = {
  project_path: ProjectPath,
  format: z
    .enum(['openvex', 'cyclonedx'])
    .optional()
    .describe('openvex (OpenVEX 0.2.0 JSON, the default) or cyclonedx (a CycloneDX 1.6 BOM with vulnerabilities[].analysis).'),
  author: z
    .string()
    .min(1)
    .max(200)
    .optional()
    .describe(`OpenVEX author — the person or organisation making the statements. Default "${DEFAULT_AUTHOR}".`),
};

const tool: ToolModule = {
  name: 'export_vex',
  title: 'Export VEX (OpenVEX / CycloneDX)',
  description:
    'Write a VEX document for project_path: one statement per vulnerability (and package version) ' +
    'of its latest usable dependency scan (scan_deps, deps_audit or security_scan_full), named by ' +
    'its CVE or its own GHSA/PYSEC id with the aliases its scanner gave — tied to findings by those ' +
    'ids only, never by ids a description mentions. Status: not_affected ONLY from a ' +
    'suppress_finding with vex_status and its OpenVEX justification; affected when validate_finding\'s ' +
    'dependency provider finds that version imported by a file an HTTP route reaches (latest ' +
    'map_attack_surface); otherwise under_investigation, with the reason in status_notes. fixed is ' +
    'never guessed. Packages are named by purl (the newest generate_sbom\'s, else built from ' +
    'ecosystem, name and version); the product by the SBOM\'s purl only when that SBOM describes ' +
    'the same tree. Writes .guardian/reports/vex-*/vex.openvex.json (openvex, default) or ' +
    'vex.cdx.json (cyclonedx, CycloneDX 1.6). `unknowns` lists what it could not know — no SBOM, ' +
    'no surface snapshot, a partial scan — and nothing is written when no vulnerability was ' +
    'measured. No network.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

interface StatementCounts {
  total: number;
  not_affected: number;
  affected: number;
  under_investigation: number;
}

const NO_STATEMENTS: StatementCounts = { total: 0, not_affected: 0, affected: 0, under_investigation: 0 };

/** Enough to ask "is there any statement to make at all", reading nothing else. */
const EMPTY_CONTEXT = { suppressions: [], now: 0, dependency: null, sbom: null } as const;

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as { project_path?: string; format?: 'openvex' | 'cyclonedx'; author?: string };
  const format = inp.format ?? 'openvex';

  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    return { ok: false, error: { code: 'not_a_git_repo', message: (e as Error).message } };
  }

  const found = findLatestUsable(ctx.storage, projectPath, CVE_SOURCE_SCAN_TYPES, { slot: 'deps' });
  const depsScan = found.scan;
  if (depsScan === null) {
    return nothingWritten(format, null, {
      unknowns: [
        'no usable dependency scan (scan_deps, deps_audit or security_scan_full) of this project: ' +
          'no CVE was measured' +
          (found.skipped.count > 0 ? `, and ${found.skipped.count} run(s) that scanned nothing were passed over` : ''),
      ],
      note:
        'Nothing was written: there is no measured CVE to make a statement about. This is not a ' +
        'statement that the project has no vulnerabilities — run scan_deps (or deps_audit), then ' +
        'export_vex again.',
    });
  }

  const unknowns: string[] = [];
  if (found.coverage === 'partial') {
    unknowns.push(
      `the dependency scan ${depsScan.scan_id} has partial coverage (missing: ` +
        `${depsScan.missing_tools.join(', ') || 'see its tools_run'}): CVEs in what it did not scan are absent here`,
    );
  }
  if (found.skipped.count > 0) {
    unknowns.push(
      `${found.skipped.count} newer dependency scan(s) scanned nothing and were passed over; the CVEs ` +
        `are those of ${depsScan.scan_id} (${depsScan.started_at})`,
    );
  }

  // The scan's CVE rows AND its vulnerability findings: a PYSEC- or GHSA-only
  // advisory (pip-audit records a row only for one with a CVE alias) exists
  // only as a finding.
  const cves = ctx.storage.cves.listActive(depsScan.scan_id);
  const findings = ctx.storage.findings.listByScan(depsScan.scan_id);
  if (buildVexStatements({ ...EMPTY_CONTEXT, cves, findings, projectPath }).length === 0) {
    return nothingWritten(format, depsScan, {
      unknowns,
      note:
        `Nothing was written: the dependency scan ${depsScan.scan_id} measured 0 vulnerabilities, and a ` +
        'VEX document needs at least one statement.',
    });
  }

  const sbom = readSbom(ctx, projectPath, unknowns);
  const surface = readSurface(ctx, projectPath, depsScan, unknowns);

  const statements = buildVexStatements({
    cves,
    findings,
    suppressions: ctx.storage.suppressions.listAll(),
    projectPath,
    now: Date.now(),
    dependency: surface?.index ?? null,
    sbom: sbom?.inventory ?? null,
  });

  const unnamed = statements.filter((s) => s.subcomponent_purls.length === 0).length;
  if (unnamed > 0) {
    unknowns.push(
      `${unnamed} statement(s) carry no subcomponent purl: neither a finding nor the SBOM said which ` +
        'ecosystem (or which version) the package is from',
    );
  }

  // The SBOM's own product purl is trusted only for the tree the CVEs came
  // from — an older SBOM (or one of another tree) may name another release.
  const trust = sbom === null ? null : sbomTrust(sbom.scan, depsScan);
  if (trust !== null && trust.note !== null) unknowns.push(trust.note);
  const product = productOf(projectPath, sbom !== null && trust?.trusted === true ? sbom.inventory : null);
  if (product.source === 'directory' && sbom !== null && trust?.trusted === true) {
    unknowns.push('the SBOM names no product purl, so the product is identified by its directory name only');
  }

  const documentId = randomUUID();
  const meta = {
    documentId,
    timestamp: new Date().toISOString(),
    author: inp.author ?? DEFAULT_AUTHOR,
    toolVersion: resolveVersion(),
    product: { id: product.id, name: product.name, purl: product.source === 'sbom' ? product.id : null },
  };
  const document = format === 'openvex' ? renderOpenVex(statements, meta) : renderCycloneDxVex(statements, meta);
  const dir = ensureReportDir(projectPath, documentId, 'vex');
  const filePath = join(dir, format === 'openvex' ? 'vex.openvex.json' : 'vex.cdx.json');
  writeFileSync(filePath, `${JSON.stringify(document, null, 2)}\n`, 'utf8');

  return {
    ok: true,
    format,
    file_path: filePath,
    statements: countStatements(statements),
    deps_scan: describeScan(depsScan, found.coverage),
    sbom: sbom === null ? null : { scan_id: sbom.scan.scan_id, file_path: sbom.filePath },
    surface_snapshot:
      surface === null
        ? null
        : { id: surface.id, captured_at: surface.capturedAt, tree_hash: surface.treeHash },
    product: { id: product.id, source: product.source },
    author: meta.author,
    unknowns,
    statements_sample: statements.slice(0, SAMPLE_SIZE).map((s) => ({
      vulnerability: s.vulnerability,
      ...(s.aliases.length > 0 ? { aliases: s.aliases } : {}),
      package: s.package_name,
      installed_version: s.installed_version,
      status: s.status,
      ...(s.justification !== undefined ? { justification: s.justification } : {}),
    })),
    instructions_for_model:
      'Read `unknowns` before sharing the file: each names something the statements could not ' +
      'account for. under_investigation is not a clean bill of health. To state not_affected, use ' +
      'suppress_finding with vex_status and a justification; for affected, upgrade the package.',
  };
}

function nothingWritten(
  format: string,
  depsScan: ScanRecord | null,
  extra: { unknowns: string[]; note: string },
): ToolResult<Record<string, unknown>> {
  return {
    ok: true,
    format,
    file_path: null,
    statements: NO_STATEMENTS,
    deps_scan: depsScan === null ? null : describeScan(depsScan, null),
    sbom: null,
    surface_snapshot: null,
    product: null,
    unknowns: extra.unknowns,
    note: extra.note,
  };
}

function describeScan(scan: ScanRecord, coverage: string | null): Record<string, unknown> {
  return {
    scan_id: scan.scan_id,
    scan_type: scan.scan_type,
    started_at: scan.started_at,
    tree_hash: scan.tree_hash,
    ...(coverage !== null ? { coverage } : {}),
  };
}

function countStatements(statements: readonly VexStatement[]): StatementCounts {
  const counts = { ...NO_STATEMENTS, total: statements.length };
  for (const s of statements) counts[s.status] += 1;
  return counts;
}

interface SbomRead {
  scan: ScanRecord;
  filePath: string;
  inventory: SbomInventory;
}

/** The newest completed SBOM of THIS project, read from its file; null, with the reason noted, otherwise. */
function readSbom(ctx: PluginContext, projectPath: string, unknowns: string[]): SbomRead | null {
  const scan = ctx.storage.scans.listCompletedOfTypes(projectPath, ['sbom'], { limit: 1 })[0];
  if (scan === undefined) {
    unknowns.push(
      'no SBOM for this project (run generate_sbom): the product is identified by its directory name ' +
        'only, and each package purl is built from its ecosystem, name and version',
    );
    return null;
  }
  const filePath = scan.meta?.['file_path'];
  if (typeof filePath !== 'string' || !existsSync(filePath)) {
    unknowns.push(
      `the newest SBOM (${scan.scan_id}) has no file on disk any more (run generate_sbom again): no ` +
        'purls could be read',
    );
    return null;
  }
  let inventory: SbomInventory | null = null;
  try {
    inventory = parseSbomInventory(readFileSync(filePath, 'utf8'));
  } catch {
    inventory = null;
  }
  if (inventory === null) {
    unknowns.push(`the newest SBOM (${filePath}) could not be read as CycloneDX or SPDX JSON: no purls`);
    return null;
  }
  return { scan, filePath, inventory };
}

interface SurfaceRead {
  id: number;
  capturedAt: string;
  treeHash: string;
  index: DependencyIndex;
}

function readSurface(
  ctx: PluginContext,
  projectPath: string,
  depsScan: ScanRecord,
  unknowns: string[],
): SurfaceRead | null {
  const persisted = ctx.storage.surface.getLatestForProject(projectPath);
  if (persisted === null) {
    unknowns.push(
      'no attack-surface snapshot for this project (run map_attack_surface): whether each package is ' +
        'imported was not checked, so no statement is affected — they are under_investigation',
    );
    return null;
  }
  if (persisted.snapshot.external_imports === undefined) {
    unknowns.push(
      'the attack-surface snapshot was mapped before third-party imports were recorded — re-run ' +
        'map_attack_surface with force: true; until then no package reads as imported',
    );
  } else if (persisted.tree_hash !== depsScan.tree_hash) {
    unknowns.push(
      `the attack-surface snapshot (tree ${persisted.tree_hash}) describes a different tree than the ` +
        `dependency scan (tree ${depsScan.tree_hash}): the imports may have changed since`,
    );
  }
  return {
    id: persisted.id,
    capturedAt: persisted.captured_at,
    treeHash: persisted.tree_hash,
    index: prepareDependencyIndex({
      snapshot: persisted.snapshot,
      graph: buildImportGraph(persisted.snapshot.imports),
      projectPath,
      npmResolver: makeNpmResolver(projectPath),
    }),
  };
}

/**
 * The product the statements are about: the SBOM's own product purl, else a
 * generic purl built from the project directory's name — an IRI OpenVEX
 * accepts, and one that says no more than is known.
 *
 * The name is never a path. Syft and Trivy name a directory source's product
 * by the path they were given, which `generate_sbom` passes absolute: copied
 * into a document made to be shared, it published the local directory
 * layout (`C:\Users\<name>\…`). An absolute name is cut to its last segment.
 */
function productOf(
  projectPath: string,
  sbom: SbomInventory | null,
): { id: string; name: string; source: 'sbom' | 'directory' } {
  const directory = basename(projectPath);
  const sbomName = sbom?.product_name ?? null;
  const name =
    sbomName === null ? directory : isAbsolutePath(sbomName) ? win32.basename(sbomName) || directory : sbomName;
  const productPurl = sbom?.product_purl ?? null;
  if (productPurl !== null) return { id: productPurl, name, source: 'sbom' };
  return { id: `pkg:generic/${encodeURIComponent(directory)}`, name, source: 'directory' };
}

/**
 * Whether the SBOM describes the tree the CVEs were measured on (review of
 * part C, M9). `generate_sbom` records its tree; an SBOM stored before it did
 * (an empty tree hash) is judged by its age instead. Trusted: same tree, or
 * no tree recorded and not older than the dependency scan. A package purl is
 * name and version, true of any SBOM that lists that version; the PRODUCT
 * purl names a release, and is what an untrusted SBOM is not believed on.
 */
function sbomTrust(sbom: ScanRecord, deps: ScanRecord): { trusted: boolean; note: string | null } {
  const label = `the newest SBOM (${sbom.scan_id}, ${sbom.started_at})`;
  if (sbom.tree_hash !== '' && deps.tree_hash !== '') {
    if (sbom.tree_hash === deps.tree_hash) return { trusted: true, note: null };
    return {
      trusted: false,
      note:
        `${label} describes another tree (${sbom.tree_hash}) than the dependency scan (${deps.tree_hash}): ` +
        'its product purl is not used, and it may list other package versions — run generate_sbom again',
    };
  }
  if (Date.parse(sbom.started_at) < Date.parse(deps.started_at)) {
    return {
      trusted: false,
      note:
        `${label} is older than the dependency scan (${deps.started_at}) and records no tree: its ` +
        'product purl is not used, and it may list other package versions — run generate_sbom again',
    };
  }
  return { trusted: true, note: null };
}

/** Absolute on either platform — the SBOM may have been written on the other one. */
function isAbsolutePath(name: string): boolean {
  return posix.isAbsolute(name) || win32.isAbsolute(name);
}
