/**
 * `risk_score` — KEV/EPSS weighting (Task 19). Same cache-seeding approach
 * as `test/unit/tools/prioritizeFindings.test.ts`: a FRESH `cve_intel` row
 * is served with no network call, and the whole suite defaults
 * `GUARDIAN_OFFLINE=1` (`vitest.config.ts`) so anything NOT seeded degrades
 * to `unavailable` instead of reaching the real network.
 */
import { afterAll, describe, expect, it } from 'vitest';
import { resolveProjectPath } from '../../../src/platform/projectPath.js';
import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { Storage } from '../../../src/storage/index.js';
import { TOOLS } from '../../../src/tools/index.js';
import '../../../src/tools/riskScore.js';
import { okResult } from '../../helpers/toolResult.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const P = resolveProjectPath(makeTempDir('risk-intel-')).path;
const NOW_ISO = new Date().toISOString();

interface RiskResponse {
  components: { cves: { score: number; active_cves: number } };
  coverage: {
    cve_intel?: {
      active_cves: number; kev_count: number; epss_measured: number; unavailable: number;
      uncorrelated: number; note?: string;
    };
  };
}

function seedWithCve(cveId: string) {
  const db = new Database(':memory:');
  runMigrations(db);
  const storage = new Storage(db);
  const scanId = 'ri-scan-1';
  storage.scans.insert({ scan_id: scanId, scan_type: 'deps', project_path: P, tree_hash: 'h' });
  storage.cves.upsert({ cve_id: cveId, package_name: 'lodash', installed_version: '4.0.0', severity: 'medium', scan_id: scanId });
  storage.scans.finalize({ scan_id: scanId, status: 'completed', tools_run: [], missing_tools: [] });
  return { storage, db };
}

async function runRiskScore(storage: Storage) {
  const mod = TOOLS.find((t) => t.name === 'risk_score');
  if (mod === undefined) throw new Error('risk_score not registered');
  return okResult<RiskResponse>(await mod.handler({ project_path: P }, { storage } as never));
}

describe('risk_score — KEV/EPSS weighting', () => {
  it('scores a KEV-listed CVE higher than the same CVE with no intel', async () => {
    const { storage: plainStorage, db: db1 } = seedWithCve('CVE-2024-9001');
    const plain = await runRiskScore(plainStorage);

    const { storage: kevStorage, db: db2 } = seedWithCve('CVE-2024-9002');
    kevStorage.cveIntel.upsertMany([{ cve_id: 'CVE-2024-9002', kev: true, kev_date_added: '2026-01-01', fetched_at: NOW_ISO }]);
    const kev = await runRiskScore(kevStorage);

    expect(kev.components.cves.score).toBeGreaterThan(plain.components.cves.score);
    db1.close();
    db2.close();
  });

  it('reports cve_intel coverage: measured KEV/EPSS vs unavailable', async () => {
    const { storage, db } = seedWithCve('CVE-2024-9003');
    storage.cveIntel.upsertMany([{ cve_id: 'CVE-2024-9003', kev: true, kev_date_added: '2026-01-01', fetched_at: NOW_ISO }]);
    const res = await runRiskScore(storage);
    expect(res.coverage.cve_intel).toEqual({ active_cves: 1, kev_count: 1, epss_measured: 0, unavailable: 0, uncorrelated: 0 });
    db.close();
  });

  it('an uncached CVE (offline by default) is reported as unavailable, not silently clean', async () => {
    const { storage, db } = seedWithCve('CVE-2024-9004');
    const res = await runRiskScore(storage);
    expect(res.coverage.cve_intel).toEqual({ active_cves: 1, kev_count: 0, epss_measured: 0, unavailable: 1, uncorrelated: 0 });
    db.close();
  });

  it('a project with no CVEs at all reports zeroed cve_intel coverage, not an absent key', async () => {
    const db = new Database(':memory:');
    runMigrations(db);
    const storage = new Storage(db);
    const res = await runRiskScore(storage);
    expect(res.coverage.cve_intel).toEqual({ active_cves: 0, kev_count: 0, epss_measured: 0, unavailable: 0, uncorrelated: 0 });
    db.close();
  });
});

describe('risk_score — uncorrelated CVE-capable findings (review round 1, Important #2)', () => {
  it('counts an npm-audit v2 finding (advisory id, no CVE) among open findings as uncorrelated', async () => {
    const db = new Database(':memory:');
    runMigrations(db);
    const storage = new Storage(db);
    const scanId = 'ri-scan-uncorr';
    storage.scans.insert({ scan_id: scanId, scan_type: 'deps', project_path: P, tree_hash: 'h' });
    storage.findings.bulkInsert([{
      scan_id: scanId, fingerprint: 'npm-uncorr-1', tool: 'npm-audit', rule_id: 'GHSA-xxxx-yyyy-zzzz',
      severity: 'high', category: 'security', title: 'Prototype pollution in lodash', message: 'm',
      file_path: 'package.json', line_start: 1, line_end: 1, fix_available: true, raw: {},
    }]);
    storage.scans.finalize({ scan_id: scanId, status: 'completed', tools_run: [], missing_tools: [] });

    const res = await runRiskScore(storage);
    expect(res.coverage.cve_intel).toMatchObject({
      uncorrelated: 1,
      note: '1 finding(s) come from a CVE-capable scanner but carry no extractable CVE id, so they cannot be weighted by KEV/EPSS yet.',
    });
    db.close();
  });
});
