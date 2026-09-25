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
import { afterAll, describe, expect, it } from 'vitest';
import { resolveProjectPath } from '../../../src/platform/projectPath.js';
import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { Storage } from '../../../src/storage/index.js';
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

async function runPrioritize(storage: Storage) {
  const mod = TOOLS.find((t) => t.name === 'prioritize_findings');
  if (mod === undefined) throw new Error('prioritize_findings not registered');
  return okResult<{ ranked: RankedRow[] }>(await mod.handler({ project_path: P }, { storage } as never));
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
