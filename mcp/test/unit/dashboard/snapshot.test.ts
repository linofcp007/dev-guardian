/**
 * `buildSnapshot` — the single project-scoped query pass (task-3-brief.md).
 *
 * DB setup mirrors the established convention elsewhere in this suite (e.g.
 * `test/unit/storage/scansRepo.test.ts`,
 * `test/unit/tools/riskScoreCharacterisation.test.ts`): `new GuardianDatabase(
 * ':memory:')` + `runMigrations`, not `openDatabase` (which returns
 * `{ db, path }`, not a bare `DB`, and requires `projectPath` even when
 * `inMemory: true`).
 */

import { describe, expect, it } from 'vitest';
import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { Storage } from '../../../src/storage/index.js';
import { buildSnapshot } from '../../../src/dashboard/snapshot.js';
import type { ScanType, Severity, ToolRun } from '../../../src/types.js';

const NOW = Date.parse('2026-08-15T12:00:00.000Z');

function fresh() {
  const db = new Database(':memory:');
  runMigrations(db);
  return { db, storage: new Storage(db) };
}

let scanSeq = 0;

function completedScan(
  storage: Storage,
  projectPath: string,
  opts: {
    tools_run?: ToolRun[]; missing_tools?: string[]; scan_type?: ScanType;
    meta?: Record<string, unknown>;
  } = {},
) {
  // `scans.insert` does NOT generate an id — the caller supplies one, and the
  // record's field is `scan_id`, not `id`.
  const scanId = `scan-${++scanSeq}`;
  storage.scans.insert({
    scan_id: scanId,
    scan_type: opts.scan_type ?? 'security_full',
    project_path: projectPath, tree_hash: 'h',
  });
  storage.scans.finalize({
    scan_id: scanId, status: 'completed',
    // ToolRun is { name, status: 'ok' | 'skipped' | 'failed' } — there is no
    // `ok` boolean. `report_dir` and `error` are OPTIONAL: omit them; `null`
    // is not assignable to `string | undefined`.
    tools_run: opts.tools_run ?? [{ name: 'semgrep', status: 'ok' }],
    missing_tools: opts.missing_tools ?? [],
    ...(opts.meta !== undefined ? { meta: opts.meta } : {}),
  });
  return scanId;
}

function insertFinding(storage: Storage, scanId: string, fingerprint: string,
  severity: Severity, file_path: string) {
  // `subcategory`/`snippet` are optional-string, not nullable — the same
  // "optional, not nullable" trap the brief calls out for FinalizeScanInput
  // and InsertSuppressionInput applies here too, so they are omitted rather
  // than passed as `null`.
  storage.findings.bulkInsert([{
    scan_id: scanId, fingerprint, tool: 'semgrep', rule_id: 'r', severity,
    category: 'security', title: 't', message: 'm',
    file_path, line_start: 1, line_end: 1,
    fix_available: false, raw: {},
  }]);
}

describe('buildSnapshot', () => {
  it('returns ONLY the requested project, even when another scanned later', () => {
    // This is the listOpen() hazard, tested rather than trusted. The wrong
    // implementation reaches for findings.listOpen() / scans.getLatest(),
    // which return the newest scan in the WHOLE database. It never looks
    // wrong, because the result is never empty.
    const { storage, db } = fresh();
    const mine = completedScan(storage, '/mine');
    insertFinding(storage, mine, 'mine-1', 'high', 'mine.ts');
    const theirs = completedScan(storage, '/theirs');       // completes LATER
    insertFinding(storage, theirs, 'theirs-1', 'critical', 'theirs.ts');

    const snap = buildSnapshot(storage, '/mine', NOW);
    expect(snap.project_path).toBe('/mine');
    expect(snap.scan?.scan_id).toBe(mine);
    expect(snap.findings.total).toBe(1);
    expect(snap.findings.items[0]?.fingerprint).toBe('mine-1');
    expect(snap.findings.by_severity.critical).toBe(0);
    db.close();
  });

  it('marks coverage partial and names what the numbers therefore omit', () => {
    const { storage, db } = fresh();
    completedScan(storage, '/p', {
      tools_run: [{ name: 'semgrep', status: 'ok' }],
      missing_tools: ['gitleaks', 'trivy'],
    });
    const snap = buildSnapshot(storage, '/p', NOW);
    expect(snap.coverage.level).toBe('partial');
    expect(snap.coverage.missing_tools).toEqual(['gitleaks', 'trivy']);
    expect(snap.coverage.omitted_categories).toEqual(
      expect.arrayContaining(['secrets', 'container and dependency']),
    );
    expect(snap.risk.coverage_caveat).toBe(true);
    db.close();
  });

  it('names an unknown missing tool rather than dropping it', () => {
    const { storage, db } = fresh();
    completedScan(storage, '/p', { missing_tools: ['some-new-scanner'] });
    const snap = buildSnapshot(storage, '/p', NOW);
    expect(snap.coverage.omitted_categories).toContain('some-new-scanner');
    db.close();
  });

  it('compares against the previous scan OF THE SAME TYPE', () => {
    // Comparing security_full against a secrets-only run would report every
    // SAST finding as "new".
    const { storage, db } = fresh();
    const older = completedScan(storage, '/p', { scan_type: 'security_full' });
    insertFinding(storage, older, 'keep', 'high', 'a.ts');
    completedScan(storage, '/p', { scan_type: 'secrets' });   // different type
    const newest = completedScan(storage, '/p', { scan_type: 'security_full' });
    insertFinding(storage, newest, 'keep', 'high', 'a.ts');

    const snap = buildSnapshot(storage, '/p', NOW);
    expect(snap.deltas.since_previous?.from_scan_id).toBe(older);
    expect(snap.deltas.since_previous?.unchanged_count).toBe(1);
    expect(snap.deltas.since_previous?.new_count).toBe(0);
    db.close();
  });

  it('leaves a delta null — not zeroed — when its reference does not exist', () => {
    // Zeros read as "nothing changed". Null reads as "there is nothing to
    // compare against", which is the truth.
    const { storage, db } = fresh();
    completedScan(storage, '/p');
    const snap = buildSnapshot(storage, '/p', NOW);
    expect(snap.deltas.since_previous).toBeNull();
    expect(snap.deltas.since_baseline).toBeNull();
    expect(snap.baseline.active).toBeNull();
    db.close();
  });

  it('returns a usable snapshot when the project has never been scanned', () => {
    const { storage, db } = fresh();
    const snap = buildSnapshot(storage, '/never', NOW);
    expect(snap.scan).toBeNull();
    expect(snap.coverage.level).toBe('none');
    expect(snap.findings.total).toBe(0);
    expect(snap.risk.score).toBe(0);
    expect(snap.risk.coverage_caveat).toBe(true);   // unknown is not safe
    expect(Number.isNaN(snap.risk.score)).toBe(false);
    db.close();
  });

  it('excludes suppressed findings from the counts and from both deltas', () => {
    const { storage, db } = fresh();
    const scan = completedScan(storage, '/p');
    insertFinding(storage, scan, 'visible', 'high', 'a.ts');
    insertFinding(storage, scan, 'hidden', 'critical', 'b.ts');
    storage.suppressions.insert({
      finding_fingerprint: 'hidden', reason: 'false positive',
      created_by: 'test',   // expires_at is optional — omit, never pass null
    });
    const snap = buildSnapshot(storage, '/p', NOW);
    expect(snap.findings.total).toBe(1);
    expect(snap.findings.by_severity.critical).toBe(0);
    expect(snap.suppressions.active_count).toBe(1);
    db.close();
  });

  it('excludes a suppressed finding from a since_previous delta too, on both sides', () => {
    // The brief's own suppression test only has one scan, so it cannot
    // exercise "suppressed on both sides of a delta" — this closes that gap.
    // The wrong implementation suppression-filters the CURRENT side (it
    // reuses listOpenForProject, which already excludes suppressions) but
    // forgets to filter the OLDER side (fetched via listByScan, which does
    // not), so a finding suppressed after the older scan ran would appear as
    // "resolved" instead of vanishing from both counts.
    const { storage, db } = fresh();
    const older = completedScan(storage, '/p', { scan_type: 'security_full' });
    insertFinding(storage, older, 'noisy', 'critical', 'a.ts');
    insertFinding(storage, older, 'keep', 'high', 'a.ts');
    storage.suppressions.insert({ finding_fingerprint: 'noisy', reason: 'fp', created_by: 'test' });
    const newest = completedScan(storage, '/p', { scan_type: 'security_full' });
    insertFinding(storage, newest, 'keep', 'high', 'a.ts');

    const snap = buildSnapshot(storage, '/p', NOW);
    // If 'noisy' leaked into the older side unsuppressed, it would show up
    // as resolved_count: 1. It must not appear on either side at all.
    expect(snap.deltas.since_previous?.resolved_count).toBe(0);
    expect(snap.deltas.since_previous?.unchanged_count).toBe(1);
    expect(snap.deltas.since_previous?.new_count).toBe(0);
    db.close();
  });

  it('treats a baseline pointing at ANOTHER project\'s scan as absent, not borrowed', () => {
    // Baselines have no project_path column (schema fact, not an oversight of
    // this task) — baselines.getActive() is genuinely global. BaselineState's
    // own doc comment says "null ⇒ no baseline has ever been set for THIS
    // PROJECT", so a baseline whose scan belongs to a different project must
    // read as absent here, the same failure shape as the listOpen() hazard
    // this whole module exists to close off, just for a field the schema
    // cannot filter by project at the SQL layer. The wrong implementation
    // trusts baselines.getActive() unconditionally and would silently diff
    // '/mine' against '/theirs' baselined scan.
    const { storage, db } = fresh();
    const theirs = completedScan(storage, '/theirs');
    storage.baselines.set({ scan_id: theirs });
    completedScan(storage, '/mine');

    const snap = buildSnapshot(storage, '/mine', NOW);
    expect(snap.baseline.active).toBeNull();
    expect(snap.baseline.age_days).toBeNull();
    expect(snap.deltas.since_baseline).toBeNull();
    db.close();
  });

  it('de-duplicates omitted_categories when two missing tools share one category', () => {
    // Step 4 requires "de-duplicated" explicitly. The wrong implementation
    // maps each tool through TOOL_CATEGORIES without deduping, producing
    // ['secrets', 'secrets'] instead of ['secrets'] — a reader would see the
    // consequence stated twice for no reason.
    const { storage, db } = fresh();
    completedScan(storage, '/p', { missing_tools: ['gitleaks', 'gitleaks'] });
    const snap = buildSnapshot(storage, '/p', NOW);
    expect(snap.coverage.omitted_categories).toEqual(['secrets']);
    db.close();
  });

  it('caps findings.items at 2000 and discloses the cut with a TruncationNotice', () => {
    // Design §8 / the plan's global constraints: findings cap at 2000. The
    // wrong implementation either does not cap at all (a huge inlined
    // payload later) or caps silently (no TruncationNotice) — either way,
    // `total` must stay the TRUE count while `items` is the capped list.
    const { storage, db } = fresh();
    const scan = completedScan(storage, '/p');
    const rows = Array.from({ length: 2005 }, (_, i) => ({
      scan_id: scan, fingerprint: `fp-${i}`, tool: 'semgrep', rule_id: 'r',
      severity: 'low' as const, category: 'security' as const, title: 't',
      file_path: 'a.ts', line_start: 1, line_end: 1, fix_available: false, raw: {},
    }));
    storage.findings.bulkInsert(rows);

    const snap = buildSnapshot(storage, '/p', NOW);
    expect(snap.findings.total).toBe(2005);          // true count, never capped
    expect(snap.findings.items).toHaveLength(2000);  // display list, capped
    expect(snap.findings.by_severity.low).toBe(2005); // grouping over the FULL set
    const notice = snap.truncation.find((t) => t.what === 'findings.items');
    expect(notice).toEqual({ what: 'findings.items', shown: 2000, total: 2005,
      reason: expect.stringContaining('2000') });
    db.close();
  });

  it('caps a delta\'s new_findings at 500 and discloses the cut, keeping new_count true', () => {
    const { storage, db } = fresh();
    const older = completedScan(storage, '/p', { scan_type: 'security_full' });
    const newest = completedScan(storage, '/p', { scan_type: 'security_full' });
    const rows = Array.from({ length: 505 }, (_, i) => ({
      scan_id: newest, fingerprint: `new-${i}`, tool: 'semgrep', rule_id: 'r',
      severity: 'low' as const, category: 'security' as const, title: 't',
      file_path: 'a.ts', line_start: 1, line_end: 1, fix_available: false, raw: {},
    }));
    storage.findings.bulkInsert(rows);
    void older; // establishes "previous scan of the same type"; carries no findings of its own

    const snap = buildSnapshot(storage, '/p', NOW);
    expect(snap.deltas.since_previous?.new_count).toBe(505);          // true count
    expect(snap.deltas.since_previous?.new_findings).toHaveLength(500); // capped list
    const notice = snap.truncation.find((t) => t.what === 'deltas.since_previous.new_findings');
    expect(notice).toEqual({ what: 'deltas.since_previous.new_findings', shown: 500, total: 505,
      reason: expect.stringContaining('500') });
    db.close();
  });

  it('computes since_baseline against the scan a VALID, same-project baseline points at, and its age', () => {
    // The counterpart to the "another project's baseline" test: this is the
    // ordinary case where the baseline genuinely belongs to this project, and
    // none of the tests above exercise it — every other test either sets no
    // baseline, or one that gets rejected by the cross-project check.
    const { storage, db } = fresh();
    const baselineScan = completedScan(storage, '/p', { scan_type: 'security_full' });
    insertFinding(storage, baselineScan, 'keep', 'high', 'a.ts');
    insertFinding(storage, baselineScan, 'gone', 'high', 'old.ts');
    storage.baselines.set({ scan_id: baselineScan, note: 'pre-refactor' });
    // baselines.set() stamps the real wall clock; pin it to a known value so
    // age_days is deterministic regardless of when this test actually runs.
    const SET_AT = '2026-07-12T00:00:00.000Z'; // 34.5 days before NOW
    db.prepare('UPDATE baselines SET set_at = ? WHERE scan_id = ?').run(SET_AT, baselineScan);

    const currentScanId = completedScan(storage, '/p', { scan_type: 'security_full' });
    insertFinding(storage, currentScanId, 'keep', 'high', 'a.ts');
    insertFinding(storage, currentScanId, 'fresh', 'critical', 'b.ts');

    const snap = buildSnapshot(storage, '/p', NOW);
    expect(snap.baseline.active?.scan_id).toBe(baselineScan);
    expect(snap.baseline.active?.note).toBe('pre-refactor');
    expect(snap.baseline.age_days).toBe(34);
    expect(snap.deltas.since_baseline?.from_scan_id).toBe(baselineScan);
    expect(snap.deltas.since_baseline?.to_scan_id).toBe(currentScanId);
    expect(snap.deltas.since_baseline?.new_count).toBe(1); // 'fresh'
    expect(snap.deltas.since_baseline?.resolved_count).toBe(1); // 'gone'
    expect(snap.deltas.since_baseline?.unchanged_count).toBe(1); // 'keep'
    db.close();
  });

  it('lists an active suppression expiring within 7 days, soonest first, excluding one further out', () => {
    const { storage, db } = fresh();
    const scan = completedScan(storage, '/p');
    insertFinding(storage, scan, 'soonest', 'high', 'a.ts');
    insertFinding(storage, scan, 'soon', 'high', 'b.ts');
    insertFinding(storage, scan, 'later', 'high', 'c.ts');

    const idSoonest = storage.suppressions.insert({
      finding_fingerprint: 'soonest', reason: 'about to expire', created_by: 'test',
      expires_at: '2026-08-16T00:00:00.000Z', // ~1 day out
    });
    const idLater = storage.suppressions.insert({
      finding_fingerprint: 'later', reason: 'long-lived', created_by: 'test',
      expires_at: '2026-09-30T00:00:00.000Z', // well beyond 7 days
    });
    const idSoon = storage.suppressions.insert({
      finding_fingerprint: 'soon', reason: 'triage in progress', created_by: 'test',
      expires_at: '2026-08-18T00:00:00.000Z', // ~3 days out
    });
    // suppressions.listActive() orders by created_at DESC. Force created_at
    // so that RAW order is the exact reverse of expiry order — 'soon'
    // (created last) would come out first, 'soonest' (created first) would
    // come out last. Without listActive()'s own DESC order (or with equal
    // created_at values, an unspecified tie-break) it is possible for a
    // missing re-sort to pass this test by coincidence; pinning distinct,
    // deliberately-inverted timestamps closes that gap and makes the
    // `expires_at`-ascending sort in buildSuppressionState load-bearing.
    const setCreatedAt = (id: number, createdAt: string) =>
      db.prepare('UPDATE suppressions SET created_at = ? WHERE id = ?').run(createdAt, id);
    setCreatedAt(idSoonest, '2026-08-10T00:00:00.000Z');
    setCreatedAt(idLater, '2026-08-11T00:00:00.000Z');
    setCreatedAt(idSoon, '2026-08-12T00:00:00.000Z');

    const snap = buildSnapshot(storage, '/p', NOW);
    expect(snap.suppressions.active_count).toBe(3);
    expect(snap.suppressions.expiring_soon).toEqual([
      { fingerprint: 'soonest', reason: 'about to expire', expires_at: '2026-08-16T00:00:00.000Z' },
      { fingerprint: 'soon', reason: 'triage in progress', expires_at: '2026-08-18T00:00:00.000Z' },
    ]);
    db.close();
  });

  // --- Task 3 review, round 1: findings 1, 3 and 4 (task-3-review.md) ---

  it('sources compliance and dependency-bot signals from THIS project\'s own scans, matching risk_score\'s arithmetic', () => {
    // Review finding 1: policies_missing/dependency_bot_configured were
    // hardcoded to 0/true, so the same single-project DB scored differently
    // through dev-guardian status than through risk_score. Ported
    // tools/riskScore.ts's own compliance-signal gathering, scoped via
    // listHistoryForProject instead of the unscoped listHistory.
    const { storage, db } = fresh();
    completedScan(storage, '/p', {
      scan_type: 'compliance',
      meta: { policy_documents_found: {
        privacy_policy: false, terms_of_service: false, security_policy: true,
      } },
    });
    completedScan(storage, '/p', {
      scan_type: 'deps',
      meta: { bot_configured: { renovate: false, dependabot: false } },
    });
    completedScan(storage, '/p', { scan_type: 'security_full' });

    const snap = buildSnapshot(storage, '/p', NOW);
    // 2 policies missing * 3 = 6, + 6 (no bot configured) = 12 — the exact
    // arithmetic risk.ts's compliance component applies, ported unchanged.
    expect(snap.risk.components.compliance).toEqual({ score: 12, policies_missing: 2 });
    db.close();
  });

  // fix-round-3, Minor 5 (coordinator review): mutating `||` to `??` on this
  // exact line leaves the full suite green, because every existing
  // bot_configured fixture uses {false, false} (both falsy — `??` and `||`
  // agree) or omits the field entirely. `??` only falls through on
  // null/undefined, never on `false`, so {renovate: false, dependabot: true}
  // is the one shape where the two operators diverge: `false || true` is
  // `true` (correctly configured, no penalty); `false ?? true` is `false`
  // (WRONGLY unconfigured — `false` is not nullish — a false 6-point
  // penalty). The code is already correct; this closes the coverage gap.
  it('treats ANY one bot configured as configured — {renovate:false, dependabot:true} must not be penalised', () => {
    const { storage, db } = fresh();
    completedScan(storage, '/p', {
      scan_type: 'deps',
      meta: { bot_configured: { renovate: false, dependabot: true } },
    });
    const snap = buildSnapshot(storage, '/p', NOW);
    expect(snap.risk.components.compliance).toEqual({ score: 0, policies_missing: 0 });
    db.close();
  });

  it('leaves compliance signals at "no penalty" when this project has no compliance/deps scan at all', () => {
    // The other half of finding 1: an absent signal must stay "not
    // measured, no penalty" (risk_score's own accepted fallback), never a
    // fabricated missing-policy count.
    const { storage, db } = fresh();
    completedScan(storage, '/p', { scan_type: 'security_full' });
    const snap = buildSnapshot(storage, '/p', NOW);
    expect(snap.risk.components.compliance).toEqual({ score: 0, policies_missing: 0 });
    db.close();
  });

  it('sources CVEs from the latest deps-flavoured scan in history, not just whatever scan is current', () => {
    // Review finding 4, positive path: a deps scan recorded CVEs; a later
    // secrets-only scan becomes the project's current scan. CVEs must still
    // be found by searching back through history for the deps-flavoured
    // scan, mirroring risk_score's findLatestOfType(['deps','security_full']).
    const { storage, db } = fresh();
    const depsScan = completedScan(storage, '/p', { scan_type: 'deps' });
    storage.cves.upsert({
      cve_id: 'CVE-2026-1', package_name: 'left-pad', severity: 'critical', scan_id: depsScan,
    });
    completedScan(storage, '/p', {
      scan_type: 'secrets', tools_run: [{ name: 'gitleaks', status: 'ok' }],
    });

    const snap = buildSnapshot(storage, '/p', NOW);
    expect(snap.cves.total).toBe(1);
    expect(snap.cves.items[0]?.cve_id).toBe('CVE-2026-1');
    // The current (secrets) scan itself is fully covered on its own terms —
    // this is the sourcing fix, not the gap-disclosure case below.
    expect(snap.coverage.level).toBe('full');
    db.close();
  });

  it('flags CVE data as unmeasured, not zero, when no deps-flavoured scan has ever run for this project', () => {
    // Review finding 4, the gap-disclosure requirement: a secrets-only scan
    // with empty missing_tools used to read coverage.level: 'full' and
    // cves.total: 0 — indistinguishable from "checked, found nothing" even
    // though no CVE scanner has ever run for this project. The gap must
    // reach `coverage` (design §6: the MISSING line is absent entirely once
    // coverage is 'full', so a gap that does not flip the level never
    // reaches the reader at all).
    const { storage, db } = fresh();
    completedScan(storage, '/p', {
      scan_type: 'secrets', tools_run: [{ name: 'gitleaks', status: 'ok' }],
    });

    const snap = buildSnapshot(storage, '/p', NOW);
    expect(snap.cves.total).toBe(0);
    expect(snap.coverage.level).toBe('partial');
    expect(snap.coverage.missing_tools).toEqual([]); // nothing genuinely missing from THIS scan
    expect(snap.coverage.omitted_categories).toContain('container and dependency');
    expect(snap.risk.coverage_caveat).toBe(true);
    db.close();
  });

  it('does not double up the CVE gap when trivy is already listed as a missing tool', () => {
    // omitted_categories de-dupes on the OUTPUT category — a scan that is
    // both missing trivy AND has no deps-flavoured scan in history must
    // still contribute 'container and dependency' exactly once.
    const { storage, db } = fresh();
    completedScan(storage, '/p', {
      scan_type: 'security_full',
      tools_run: [{ name: 'semgrep', status: 'ok' }],
      missing_tools: ['trivy'],
    });
    const snap = buildSnapshot(storage, '/p', NOW);
    expect(snap.coverage.omitted_categories.filter((c) => c === 'container and dependency')).toHaveLength(1);
    db.close();
  });

  it('finds this project\'s own baseline even when another project set one more recently', () => {
    // Review finding 3: getActive() alone only ever sees the single
    // globally-newest baseline row. The cross-project check correctly
    // rejects it when it belongs to another project, but never looks past
    // it — so this project's own (older) baseline was invisible whenever
    // another project's baseline was set later. resolveBaseline now walks
    // baselines.listAll() for the newest one whose scan matches.
    const { storage, db } = fresh();
    const mineBaselineScan = completedScan(storage, '/mine');
    storage.baselines.set({ scan_id: mineBaselineScan, note: 'my real baseline' });
    const theirsScan = completedScan(storage, '/theirs');
    storage.baselines.set({ scan_id: theirsScan }); // set LATER — the global "active" row
    completedScan(storage, '/mine'); // '/mine' scans again, after both baselines exist

    const snap = buildSnapshot(storage, '/mine', NOW);
    expect(snap.baseline.active?.scan_id).toBe(mineBaselineScan);
    expect(snap.baseline.active?.note).toBe('my real baseline');
    expect(snap.baseline.age_days).not.toBeNull();
    expect(snap.risk.components.baseline.has_active_baseline).toBe(true);
    db.close();
  });

  it('determines suppression activity from the injected now, never the ambient clock', () => {
    // Review finding 2: buildSnapshot mixed clocks — the injected `now` for
    // generated_at/age_seconds/age_days/the expiring-soon cutoff, but the
    // real wall clock (via suppressions.listActive()'s own nowIso()) for
    // "which suppressions are active at all". A fixed `now` far from real
    // time proves the two are no longer coupled: real wall-clock time,
    // whenever this test actually executes, is certainly past 2020-01-05 —
    // code that still consulted it anywhere in this path would see this
    // suppression as already expired and report active_count: 0.
    const { storage, db } = fresh();
    completedScan(storage, '/p');
    storage.suppressions.insert({
      finding_fingerprint: 'a', reason: 'active relative to an old injected now',
      created_by: 'test', expires_at: '2020-01-05T00:00:00.000Z',
    });
    const OLD_NOW = Date.parse('2020-01-01T00:00:00.000Z');
    const snap = buildSnapshot(storage, '/p', OLD_NOW);
    expect(snap.suppressions.active_count).toBe(1);
    db.close();
  });
});
