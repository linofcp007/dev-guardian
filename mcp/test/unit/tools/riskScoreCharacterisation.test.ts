/**
 * Characterisation test for `risk_score`, run first against the UNMODIFIED
 * tool to pin its current public behaviour before `dashboard/risk.ts`
 * extracts the arithmetic out of it (see task-1-brief.md, Step 5/6). Asserts
 * the whole response object — the extraction must not change any field,
 * including key order and rounding.
 *
 * DB setup mirrors the established convention elsewhere in this suite (e.g.
 * `test/unit/storage/scansRepo.test.ts`, `test/integration/phase14Tools.test.ts`):
 * `new GuardianDatabase(':memory:')` + `runMigrations`, not `openDatabase`
 * (which returns `{ db, path }`, not a bare `DB`, and requires `projectPath`
 * even when `inMemory: true`).
 */

import { describe, expect, it } from 'vitest';
import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { Storage } from '../../../src/storage/index.js';
import { TOOLS } from '../../../src/tools/index.js';
import '../../../src/tools/riskScore.js';

function seed() {
  const db = new Database(':memory:');
  runMigrations(db);
  const storage = new Storage(db);
  const scanId = 'char-scan-1';
  storage.scans.insert({
    scan_id: scanId, scan_type: 'security_full', project_path: '/p', tree_hash: 'h',
  });
  storage.scans.finalize({
    scan_id: scanId, status: 'completed', tools_run: [], missing_tools: [],
  });
  storage.findings.bulkInsert([
    { scan_id: scanId, fingerprint: 'a', tool: 'semgrep', rule_id: 'r',
      severity: 'critical', category: 'security', subcategory: null,
      title: 't', message: 'm', file_path: 'a.ts', line_start: 1, line_end: 1,
      snippet: null, fix_available: false, raw: {} },
    { scan_id: scanId, fingerprint: 'b', tool: 'semgrep', rule_id: 'r',
      severity: 'high', category: 'security', subcategory: null,
      title: 't', message: 'm', file_path: 'b.ts', line_start: 1, line_end: 1,
      snippet: null, fix_available: false, raw: {} },
  ]);
  return { storage, db };
}

describe('risk_score — public behaviour is unchanged by the extraction', () => {
  it('returns the same object shape and values it always has', async () => {
    const { storage, db } = seed();
    const mod = TOOLS.find((t) => t.name === 'risk_score');
    expect(mod).toBeTruthy();
    const res = await mod?.handler({}, { storage } as never);
    expect(res).toEqual({
      ok: true,
      score: 23,                      // 15 findings + 0 cves + 0 compliance + 8 no-baseline
      band: 'medium',
      components: {
        findings: { score: 15, open_findings: 2 },
        cves: { score: 0, active_cves: 0 },
        compliance: { score: 0, policies_missing: 0 },
        baseline: { score: 8, has_active_baseline: false },
      },
      recommended_next_action:
        'Set a baseline with set_baseline so diff_scans can track regressions.',
    });
    db.close();
  });
});

/**
 * fix-round-3, Minor 5 (coordinator review): `dependencyBotConfigured =
 * Boolean(bot.renovate || bot.dependabot)` (riskScore.ts:66) had no test
 * that distinguishes `||` from `??`. Mutating it leaves the whole suite
 * green, because every existing bot_configured fixture anywhere in the repo
 * uses {false, false} (both falsy — the two operators agree) or omits the
 * field entirely. `??` only falls through on null/undefined, never on
 * `false`, so {renovate: false, dependabot: true} is the one input shape
 * where `false || true` (true, correctly configured) and `false ?? true`
 * (false, WRONGLY unconfigured, since `false` is not nullish) diverge. The
 * code is already correct — this closes the coverage gap, not a live defect.
 */
function seedDepsOnly(botConfigured: { renovate: boolean; dependabot: boolean }) {
  const db = new Database(':memory:');
  runMigrations(db);
  const storage = new Storage(db);
  const scanId = 'char-scan-bot-1';
  storage.scans.insert({
    scan_id: scanId, scan_type: 'deps', project_path: '/p', tree_hash: 'h',
  });
  storage.scans.finalize({
    scan_id: scanId, status: 'completed', tools_run: [], missing_tools: [],
    meta: { bot_configured: botConfigured },
  });
  return { storage, db };
}

describe('risk_score — dependency-bot `||` regression coverage', () => {
  it('treats ANY one bot configured as configured — {renovate:false, dependabot:true} must not be penalised', async () => {
    const { storage, db } = seedDepsOnly({ renovate: false, dependabot: true });
    const mod = TOOLS.find((t) => t.name === 'risk_score');
    expect(mod).toBeTruthy();
    const res = await mod?.handler({}, { storage } as never);
    expect(res).toEqual({
      ok: true,
      score: 8,                       // 0 findings + 0 cves + 0 compliance + 8 no-baseline
      band: 'low',
      components: {
        findings: { score: 0, open_findings: 0 },
        cves: { score: 0, active_cves: 0 },
        compliance: { score: 0, policies_missing: 0 },
        baseline: { score: 8, has_active_baseline: false },
      },
      recommended_next_action:
        'Set a baseline with set_baseline so diff_scans can track regressions.',
    });
    db.close();
  });
});
