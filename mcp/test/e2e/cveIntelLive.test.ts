/**
 * Real, unmocked calls to the FIRST EPSS API and the CISA KEV feed
 * (Task 19). Every other test in this repo mocks `fetch` (or runs with
 * `GUARDIAN_OFFLINE=1`, the suite's default — `vitest.config.ts`); this file
 * is the one place that is deliberately allowed to reach the real network,
 * and only when explicitly asked: gated on `GUARDIAN_TEST_LIVE_CVE_INTEL=1`,
 * a skip reports as a skip (`it.skipIf`), same discipline as
 * `depsUpdatePlanPnpm.test.ts`'s `PNPM_INSTALLED` gate next to it.
 *
 * CVE-2021-44228 (Log4Shell) is used as the live fixture: both CISA
 * KEV-listed and EPSS-scored at effectively 1.0 for as long as either feed
 * has existed, so a result that is NOT both is itself evidence the feed's
 * shape moved, not just that a snapshot was stale.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { fetchKevCatalog } from '../../src/intel/kev.js';
import { queryEpss } from '../../src/intel/epss.js';
import { enrichCveIntel } from '../../src/intel/enrich.js';
import { CveIntelRepo } from '../../src/storage/cveIntelRepo.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';

const LIVE = process.env['GUARDIAN_TEST_LIVE_CVE_INTEL'] === '1';
const LOG4SHELL = 'CVE-2021-44228';

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('CVE intel — live network (gated)', () => {
  it.skipIf(!LIVE)('FIRST EPSS scores Log4Shell close to 1.0', async () => {
    const res = await queryEpss([LOG4SHELL]);
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    const entry = res.scores.get(LOG4SHELL);
    expect(entry).toBeDefined();
    expect(entry?.score).toBeGreaterThan(0.9);
  }, 20_000);

  it.skipIf(!LIVE)('the CISA KEV feed lists Log4Shell', async () => {
    const res = await fetchKevCatalog();
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.entries.has(LOG4SHELL)).toBe(true);
  }, 20_000);

  it.skipIf(!LIVE)('enrichCveIntel end to end: cache miss -> live fetch -> cached row', async () => {
    vi.stubEnv('GUARDIAN_OFFLINE', '0');
    const db = new Database(':memory:');
    runMigrations(db);
    const storage = { cveIntel: new CveIntelRepo(db) };

    const first = await enrichCveIntel(storage, [LOG4SHELL]);
    const entry = first.get(LOG4SHELL);
    expect(entry?.status).toBe('ok');
    expect(entry?.kev).toBe(true);
    expect(entry?.epss_score).toBeGreaterThan(0.9);

    // Second call within the TTL is served from the cache alone.
    const cached = storage.cveIntel.getMany([LOG4SHELL]).get(LOG4SHELL);
    expect(cached).toBeDefined();
    expect(cached?.kev).toBe(true);

    db.close();
  }, 20_000);

  it.skipIf(LIVE)('skip notice: GUARDIAN_TEST_LIVE_CVE_INTEL is not set — this e2e did not run', () => {
    expect(LIVE).toBe(false);
  });
});
