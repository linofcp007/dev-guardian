/**
 * `prioritize_findings` — KEV/EPSS weighting (Task 19). Exercises the tool
 * through the real `cve_intel` cache rather than mocking `fetch`: a FRESH
 * cached row (`fetched_at` = now) is served by `intel/enrich.ts` with no
 * network call at all, so seeding `storage.cveIntel` directly is enough —
 * see that module's own tests for the cache/network split itself. The whole
 * suite also defaults `GUARDIAN_OFFLINE=1` (`vitest.config.ts`), so any
 * finding correlated to a CVE this test does NOT seed degrades to
 * `unavailable` rather than reaching the real network.
 */
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { resolveProjectPath } from '../../../src/platform/projectPath.js';
import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { Storage } from '../../../src/storage/index.js';
import { externalImports } from '../../../src/surface/moduleEdges.js';
import { TOOLS } from '../../../src/tools/index.js';
import '../../../src/tools/prioritizeFindings.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';
import { okResult } from '../../helpers/toolResult.js';

afterAll(cleanupTempDirs);

const P = resolveProjectPath(makeTempDir('prioritize-')).path;
const NOW_ISO = new Date().toISOString();

interface RankedRow {
  finding: { fingerprint: string; rule_id?: string };
  priority_score: number;
  factors: string[];
}

function seed() {
  const db = new Database(':memory:');
  runMigrations(db);
  const storage = new Storage(db);
  const scanId = 'pf-scan-1';
  storage.scans.insert({ scan_id: scanId, scan_type: 'security_full', project_path: P, tree_hash: 'h' });
  storage.scans.finalize({ scan_id: scanId, status: 'completed', tools_run: [], missing_tools: [] });
  return { storage, db, scanId };
}

function trivyFinding(over: { rule_id: string }) {
  return {
    tool: 'trivy', rule_id: over.rule_id, severity: 'high' as const, category: 'security' as const,
    title: 't', message: 'm', file_path: 'x', line_start: 1, line_end: 1,
    fix_available: false, raw: {},
  };
}

/** Calls a registered tool by name, for tests naming a different result
 *  shape than `runPrioritize`'s own `RankedRow[]`. */
async function runToolRaw(name: string, storage: Storage): ReturnType<(typeof TOOLS)[number]['handler']> {
  const mod = TOOLS.find((t) => t.name === name);
  if (mod === undefined) throw new Error(`${name} not registered`);
  return mod.handler({ project_path: P }, { storage } as never);
}

async function runPrioritize(storage: Storage) {
  return okResult<{ ranked: RankedRow[] }>(await runToolRaw('prioritize_findings', storage));
}

describe('prioritize_findings — KEV/EPSS weighting', () => {
  it('ranks a KEV-listed finding above an equal-severity/category non-KEV finding', async () => {
    // Fingerprints deliberately chosen so the PRE-EXISTING fingerprint
    // tie-break alone would rank 'aa-plain' first — only the KEV weighting
    // this task adds can flip the order to KEV-first.
    const { storage, scanId, db } = seed();
    storage.findings.bulkInsert([
      { scan_id: scanId, fingerprint: 'aa-plain', ...trivyFinding({ rule_id: 'CVE-2024-1111' }) },
      { scan_id: scanId, fingerprint: 'zz-kev', ...trivyFinding({ rule_id: 'CVE-2024-2222' }) },
    ]);
    storage.cveIntel.upsertMany([
      { cve_id: 'CVE-2024-1111', kev: false, fetched_at: NOW_ISO },
      { cve_id: 'CVE-2024-2222', kev: true, kev_date_added: '2026-01-01', fetched_at: NOW_ISO },
    ]);

    const res = await runPrioritize(storage);
    expect(res.ranked.map((r) => r.finding.fingerprint)).toEqual(['zz-kev', 'aa-plain']);
    const kevRow = res.ranked.find((r) => r.finding.fingerprint === 'zz-kev');
    expect(kevRow?.factors.some((f) => /kev/i.test(f))).toBe(true);
    db.close();
  });

  it('among equal severity/category/KEV findings, ranks higher EPSS first', async () => {
    // Same trick: 'aa-low-epss' sorts first by fingerprint alone; only EPSS
    // weighting can flip it behind 'zz-high-epss'.
    const { storage, scanId, db } = seed();
    storage.findings.bulkInsert([
      { scan_id: scanId, fingerprint: 'aa-low-epss', ...trivyFinding({ rule_id: 'CVE-2024-3333' }) },
      { scan_id: scanId, fingerprint: 'zz-high-epss', ...trivyFinding({ rule_id: 'CVE-2024-4444' }) },
    ]);
    storage.cveIntel.upsertMany([
      { cve_id: 'CVE-2024-3333', kev: false, epss_score: 0.05, epss_percentile: 0.1, fetched_at: NOW_ISO },
      { cve_id: 'CVE-2024-4444', kev: false, epss_score: 0.9, epss_percentile: 0.95, fetched_at: NOW_ISO },
    ]);

    const res = await runPrioritize(storage);
    expect(res.ranked.map((r) => r.finding.fingerprint)).toEqual(['zz-high-epss', 'aa-low-epss']);
    db.close();
  });

  it('a CVE-linked finding with no cached intel (and no network, offline by default) ranks as before, unenriched', async () => {
    const { storage, scanId, db } = seed();
    storage.findings.bulkInsert([
      { scan_id: scanId, fingerprint: 'unmeasured', ...trivyFinding({ rule_id: 'CVE-2024-5555' }) },
    ]);
    const res = await runPrioritize(storage);
    const row = res.ranked.find((r) => r.finding.fingerprint === 'unmeasured');
    expect(row).toBeDefined();
    expect(row?.factors.some((f) => /kev/i.test(f))).toBe(false);
    db.close();
  });

  it('a CVE the description merely mentions boosts nothing and feeds no SSVC point (review C1)', async () => {
    // Reproduced on real Trivy output: CVE-2026-4800's lodash description
    // mentions CVE-2021-23337, and the finding used to inherit that CVE's
    // KEV/EPSS signal. Deliberate change: the boost below was 0 → +220.
    const { storage, scanId, db } = seed();
    storage.findings.bulkInsert([
      { scan_id: scanId, fingerprint: 'mentions', ...trivyFinding({ rule_id: 'CVE-2026-4800' }),
        message: 'This is due to an incomplete fix for CVE-2021-23337.' },
    ]);
    storage.cveIntel.upsertMany([
      { cve_id: 'CVE-2026-4800', kev: false, fetched_at: NOW_ISO },
      { cve_id: 'CVE-2021-23337', kev: true, kev_date_added: '2026-01-01', epss_score: 0.213, fetched_at: NOW_ISO },
    ]);
    const res = await okResult<{ ranked: Array<RankedRow & { ssvc: { exploitation: { value: string; assumed: boolean; basis: string } } | null }> }>(
      await runToolRaw('prioritize_findings', storage),
    );
    const row = res.ranked[0];
    // high 250 + security 200 + observed 30, and nothing from CVE-2021-23337.
    expect(row?.priority_score).toBe(480);
    expect(row?.factors.some((f) => /kev|epss/i.test(f))).toBe(false);
    expect(row?.ssvc?.exploitation.basis).not.toMatch(/CVE-2021-23337/);
    expect(row?.ssvc?.exploitation).toMatchObject({ value: 'poc', assumed: true });
    db.close();
  });

  it('a plain Semgrep finding with no CVE association is entirely unaffected', async () => {
    const { storage, scanId, db } = seed();
    storage.findings.bulkInsert([
      { scan_id: scanId, fingerprint: 'semgrep-1', tool: 'semgrep', rule_id: 'no-eval', severity: 'high',
        category: 'security', title: 't', message: 'm', file_path: 'x', line_start: 1, line_end: 1,
        fix_available: false, raw: {} },
    ]);
    const res = await runPrioritize(storage);
    expect(res.ranked).toHaveLength(1);
    expect(res.ranked[0]?.factors.some((f) => /kev|epss/i.test(f))).toBe(false);
    db.close();
  });
});

describe('prioritize_findings — uncorrelated CVE-capable findings (review round 1, Important #2)', () => {
  it('counts an npm-audit v2 finding (advisory id, no CVE) as uncorrelated', async () => {
    const { storage, scanId, db } = seed();
    storage.findings.bulkInsert([
      { scan_id: scanId, fingerprint: 'npm-1', tool: 'npm-audit', rule_id: 'GHSA-xxxx-yyyy-zzzz',
        severity: 'high', category: 'security', title: 'Prototype pollution in lodash', message: 'm',
        file_path: 'package.json', line_start: 1, line_end: 1, fix_available: true, raw: {} },
    ]);
    const res = await okResult<{ cve_intel: { uncorrelated: number; note?: string } }>(
      await runToolRaw('prioritize_findings', storage),
    );
    expect(res.cve_intel).toEqual({
      uncorrelated: 1,
      note: '1 finding(s) come from a CVE-capable scanner but carry no extractable CVE id, so they cannot be weighted by KEV/EPSS yet.',
    });
    db.close();
  });

  it('a Trivy finding with a real CVE is not counted as uncorrelated', async () => {
    const { storage, scanId, db } = seed();
    storage.findings.bulkInsert([
      { scan_id: scanId, fingerprint: 'trivy-1', ...trivyFinding({ rule_id: 'CVE-2024-7777' }) },
    ]);
    const res = await okResult<{ cve_intel: { uncorrelated: number } }>(
      await runToolRaw('prioritize_findings', storage),
    );
    expect(res.cve_intel.uncorrelated).toBe(0);
    db.close();
  });

  it('a plain Semgrep finding (never CVE-capable) does not count as uncorrelated, and no note is added at zero', async () => {
    const { storage, scanId, db } = seed();
    storage.findings.bulkInsert([
      { scan_id: scanId, fingerprint: 'semgrep-2', tool: 'semgrep', rule_id: 'no-eval', severity: 'high',
        category: 'security', title: 't', message: 'm', file_path: 'x', line_start: 1, line_end: 1,
        fix_available: false, raw: {} },
    ]);
    const res = await okResult<{ cve_intel: { uncorrelated: number; note?: string } }>(
      await runToolRaw('prioritize_findings', storage),
    );
    expect(res.cve_intel).toEqual({ uncorrelated: 0 });
    db.close();
  });
});

/* ------------------------------------------------------------------ */
/* CISA SSVC (deployer tree) for CVE findings                           */
/* ------------------------------------------------------------------ */

interface SsvcPointOut { value: string; assumed: boolean; basis: string }
interface SsvcOut {
  decision: string;
  exploitation: SsvcPointOut;
  automatable: SsvcPointOut;
  technical_impact: SsvcPointOut;
  mission_wellbeing: SsvcPointOut;
  assumed: string[];
  cve_ids: string[];
}
interface SsvcRow extends RankedRow { ssvc: SsvcOut | null }
interface SsvcSummary {
  decisions: Record<string, number>;
  not_applicable: number;
  assumed_inputs: Record<string, number>;
  mission_wellbeing: { value: string; source: string };
  surface_snapshot_id: number | null;
}

/** A Trivy CVE on an npm package, the shape its parser stores. */
function npmCve(fingerprint: string, cve: string, pkg: string, severity: 'critical' | 'high' | 'medium' = 'critical') {
  return {
    fingerprint, tool: 'trivy', rule_id: cve, severity, category: 'security' as const,
    subcategory: 'cve', title: `${cve} in ${pkg}`, file_path: 'package-lock.json',
    snippet: `${pkg}@1.0.0->1.0.1`, fix_available: true, raw: {},
  };
}

/** A snapshot whose one route file imports `pkg`. */
function seedSurface(storage: Storage, pkg: string): number {
  // The lockfile says the project's code loads exactly the vulnerable
  // version (npmCve's 1.0.0) — what lets the dependency provider say reachable.
  writeFileSync(join(P, 'package-lock.json'), JSON.stringify({
    lockfileVersion: 3, packages: { [`node_modules/${pkg}`]: { version: '1.0.0' } },
  }));
  return storage.surface.insert({
    project_path: P,
    tree_hash: 't',
    snapshot: {
      routes: [{
        method: 'GET', provenance: 'code', path_raw: '/', path_resolved: '/', path_partial: false,
        file: `${P}/src/app.ts`, line: 1, framework: 'express', language: 'typescript',
        auth_hint: 'unknown', params: [], confidence: 'high',
      }],
      env_vars: [], ports: [], webhooks: [], coverage: [], tools_run: [], missing_tools: [],
      spec_files: [], spec_diff: null, imports: [],
      external_imports: externalImports([{ file: 'src/app.ts', specifier: pkg, language: 'typescript' }]),
    },
  }).id;
}

async function runSsvc(storage: Storage, extra: Record<string, unknown> = {}) {
  const mod = TOOLS.find((t) => t.name === 'prioritize_findings');
  if (mod === undefined) throw new Error('prioritize_findings not registered');
  return okResult<{ ranked: SsvcRow[]; summary: { ssvc: SsvcSummary } }>(
    await mod.handler({ project_path: P, ...extra }, { storage } as never),
  );
}

describe('prioritize_findings — CISA SSVC decision per CVE finding', () => {
  it('decides Act for a KEV-listed critical CVE whose package a route file imports, with its inputs', async () => {
    const { storage, scanId, db } = seed();
    storage.findings.bulkInsert([{ scan_id: scanId, ...npmCve('kev-lodash', 'CVE-2024-2222', 'lodash') }]);
    storage.cveIntel.upsertMany([{ cve_id: 'CVE-2024-2222', kev: true, fetched_at: NOW_ISO }]);
    const snapshotId = seedSurface(storage, 'lodash');

    const res = await runSsvc(storage);
    const ssvc = res.ranked[0]?.ssvc;

    expect(ssvc?.decision).toBe('Act');
    expect(ssvc?.exploitation).toMatchObject({ value: 'active', assumed: false });
    expect(ssvc?.automatable).toMatchObject({ value: 'yes', assumed: false });
    expect(ssvc?.technical_impact).toMatchObject({ value: 'total', assumed: false });
    // Not passed: the default, and said to be one.
    expect(ssvc?.mission_wellbeing).toMatchObject({ value: 'medium', assumed: true });
    expect(ssvc?.assumed).toEqual(['mission_wellbeing']);
    expect(ssvc?.cve_ids).toEqual(['CVE-2024-2222']);
    expect(res.summary.ssvc.decisions).toEqual({ Act: 1, Attend: 0, 'Track*': 0, Track: 0 });
    expect(res.summary.ssvc.surface_snapshot_id).toBe(snapshotId);
    db.close();
  });

  it('takes mission_wellbeing from the caller, and the decision moves with it', async () => {
    const { storage, scanId, db } = seed();
    storage.findings.bulkInsert([{ scan_id: scanId, ...npmCve('kev-lodash', 'CVE-2024-2222', 'lodash') }]);
    storage.cveIntel.upsertMany([{ cve_id: 'CVE-2024-2222', kev: true, fetched_at: NOW_ISO }]);
    seedSurface(storage, 'lodash');

    const res = await runSsvc(storage, { mission_wellbeing: 'low' });

    // active / yes / total / low is Attend in CISA's table, not Act.
    expect(res.ranked[0]?.ssvc?.decision).toBe('Attend');
    expect(res.ranked[0]?.ssvc?.mission_wellbeing).toMatchObject({ value: 'low', assumed: false });
    expect(res.summary.ssvc.mission_wellbeing).toEqual({ value: 'low', source: 'parameter' });
    db.close();
  });

  it('assumes the worst for a CVE with no intel and no surface snapshot, and says which inputs were assumed', async () => {
    const { storage, scanId, db } = seed();
    storage.findings.bulkInsert([{ scan_id: scanId, ...npmCve('unmeasured', 'CVE-2024-5555', 'left-pad', 'medium') }]);

    const res = await runSsvc(storage);
    const ssvc = res.ranked[0]?.ssvc;

    expect(ssvc?.exploitation).toMatchObject({ value: 'active', assumed: true });
    expect(ssvc?.automatable).toMatchObject({ value: 'yes', assumed: true });
    expect(ssvc?.automatable.basis).toMatch(/map_attack_surface/);
    // active / yes / partial (medium severity) / medium
    expect(ssvc?.decision).toBe('Attend');
    expect(ssvc?.assumed).toEqual(['exploitation', 'automatable', 'mission_wellbeing']);
    expect(res.summary.ssvc.assumed_inputs).toEqual({ exploitation: 1, automatable: 1, mission_wellbeing: 1 });
    expect(res.summary.ssvc.surface_snapshot_id).toBeNull();
    db.close();
  });

  it('gives a finding with no CVE no SSVC decision, and keeps its score as it was', async () => {
    const { storage, scanId, db } = seed();
    storage.findings.bulkInsert([
      { scan_id: scanId, fingerprint: 'semgrep-3', tool: 'semgrep', rule_id: 'no-eval', severity: 'high',
        category: 'security', title: 't', message: 'm', file_path: 'x', line_start: 1, line_end: 1,
        fix_available: false, raw: {} },
    ]);

    const res = await runSsvc(storage);

    expect(res.ranked[0]?.ssvc).toBeNull();
    // severity high 250 + security 200 + observed in latest scan 30.
    expect(res.ranked[0]?.priority_score).toBe(480);
    expect(res.summary.ssvc.not_applicable).toBe(1);
    expect(res.summary.ssvc.decisions).toEqual({ Act: 0, Attend: 0, 'Track*': 0, Track: 0 });
    db.close();
  });

  it('never changes a CVE finding’s score: an assumed-active SSVC input is not a boost', async () => {
    // The score keeps its own contract — no boost from intel that was never
    // measured — while SSVC applies CISA's "assume the worse value". Both are
    // reported; neither is folded into the other.
    const { storage, scanId, db } = seed();
    storage.findings.bulkInsert([{ scan_id: scanId, ...npmCve('unmeasured', 'CVE-2024-5555', 'left-pad', 'medium') }]);

    const res = await runSsvc(storage);

    // medium 120 + security 200 + fix_available 60 + observed 30.
    expect(res.ranked[0]?.priority_score).toBe(410);
    db.close();
  });
});
