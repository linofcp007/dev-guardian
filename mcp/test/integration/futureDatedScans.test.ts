/**
 * Scans dated in the future are ignored by every history reader, with a note.
 *
 * Round 6 of the 3.0 review: a dense series of future-dated scans with no
 * findings — every 9 minutes from now - 2 h to now + 2 days — made one of
 * them "latest" at any moment: risk 8/low, coverage full, its source
 * finished two days ahead, the victim's own scan shadowed (open 7 -> 0). A
 * clock that was wrong on the machine that wrote a shared database does the
 * same by accident. The rule lives in one place (`storage/scanClock.ts`),
 * applied in every reader's SQL; this file holds the readers to it, with the
 * reviewer's series itself.
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildSnapshot } from '../../src/dashboard/snapshot.js';
import { describeOpenSet, openSetForProject } from '../../src/history/openSet.js';
import { FUTURE_SKEW_MINUTES } from '../../src/storage/scanClock.js';
import { TOOLS } from '../../src/tools/index.js';
import { cleanupTempDirs } from '../helpers/tempDir.js';
import { freshPlugin, projectDir, type Seeded } from '../helpers/historySeed.js';
import { okResult } from '../helpers/toolResult.js';

afterAll(cleanupTempDirs);

beforeAll(async () => {
  await import('../../src/registerAll.js');
});

async function call(name: string, s: Seeded, input: Record<string, unknown>): Promise<Record<string, unknown>> {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`tool ${name} not registered`);
  return okResult(await t.handler(input, s.plugin));
}

const MINUTE = 60_000;

/** A completed sast scan with `findings` critical findings, dated at `at` (start) + 1 s (finish). */
function scanAt(s: Seeded, project: string, id: string, at: number, findings: number): void {
  s.storage.scans.insert({ scan_id: id, scan_type: 'sast', project_path: project, tree_hash: `h-${id}` });
  if (findings > 0) {
    s.storage.findings.bulkInsert(
      Array.from({ length: findings }, (_, i) => ({
        scan_id: id,
        fingerprint: `${id}-fp-${i}`,
        identity: `${id}-id-${i}`,
        tool: 'semgrep',
        rule_id: 'r',
        severity: 'critical' as const,
        category: 'security' as const,
        title: `finding ${i}`,
        file_path: `src/f${i}.ts`,
        line_start: i + 1,
        fix_available: false,
      })),
    );
  }
  s.storage.scans.finalize({ scan_id: id, status: 'completed', tools_run: [{ name: 'semgrep', status: 'ok' }], missing_tools: [] });
  s.db
    .prepare('UPDATE scans SET started_at = ?, finished_at = ? WHERE id = ?')
    .run(new Date(at).toISOString(), new Date(at + 1000).toISOString(), id);
}

/**
 * The reviewer's series, planted beside the victim's own scan (7 criticals,
 * finished just now). Returns how many of the planted scans lie beyond the
 * skew — the ones every reader must ignore.
 */
function reviewersSeries(s: Seeded, project: string): { future: number } {
  const now = Date.now();
  let future = 0;
  let i = 0;
  for (let t = now - 120 * MINUTE; t <= now + 2 * 24 * 60 * MINUTE; t += 9 * MINUTE, i++) {
    scanAt(s, project, `planted-${String(i).padStart(4, '0')}`, t, 0);
    if (t > now + FUTURE_SKEW_MINUTES * MINUTE) future += 1;
  }
  // The victim's own scan, the newest one that is not in the future (the
  // series has a scan at now - 3 min and the next at now + 6 min).
  scanAt(s, project, 'victim', now - 30_000, 7);
  return { future };
}

const beyondSkew = (iso: string | null | undefined): boolean =>
  iso !== null && iso !== undefined && Date.parse(iso) > Date.now() + FUTURE_SKEW_MINUTES * MINUTE;

describe('scans dated in the future', () => {
  it("the reviewer's series: no reader reads one, the victim's findings stay open, and each reader says how many it ignored", async () => {
    const s = freshPlugin();
    const p = projectDir('future-');
    const { future } = reviewersSeries(s, p);
    expect(future).toBeGreaterThan(300);

    const set = openSetForProject(s.storage, p);
    expect(set.findings).toHaveLength(7);
    expect(set.sources.map((x) => x.scan_id)).toEqual(['victim']);
    expect(set.scans.some((x) => beyondSkew(x.started_at) || beyondSkew(x.finished_at))).toBe(false);
    expect(set.future_dated_note).toMatch(new RegExp(`^${future} scan\\(s\\) dated in the future were ignored`));
    expect(describeOpenSet(set).future_dated_note).toBe(set.future_dated_note);

    expect(s.storage.scans.getLatestForProject(p)?.scan_id).toBe('victim');
    expect(s.storage.scans.listHistoryForProject(p, 5000).some((x) => beyondSkew(x.started_at))).toBe(false);
    expect(s.storage.findings.listOpenForProject(p)).toHaveLength(7);
    expect(s.storage.scans.countFutureDated(p)).toBe(future);

    const risk = await call('risk_score', s, { project_path: p });
    expect(risk['future_dated_note']).toBe(set.future_dated_note);
    expect(risk['band']).not.toBe('low');

    const health = await call('health_status', s, { project_path: p });
    expect((health['storage'] as Record<string, unknown>)['future_dated_scans_ignored']).toBe(future);
    expect(health['future_dated_note']).toBe(set.future_dated_note);
    expect((health['last_scan'] as { scan_id: string }).scan_id).toBe('victim');

    const snapshot = buildSnapshot(s.storage, p, Date.now());
    expect(JSON.stringify(snapshot)).not.toMatch(/planted-0(?:01[4-9]|0[2-9]\d|[1-9]\d\d)/);
  });

  it(`a scan within the ${FUTURE_SKEW_MINUTES} minutes of clock skew is read; a project with none gets no note`, () => {
    const s = freshPlugin();
    const p = projectDir('future-');
    scanAt(s, p, 'skewed', Date.now() + 2 * MINUTE, 3);
    const set = openSetForProject(s.storage, p);
    expect(set.sources.map((x) => x.scan_id)).toEqual(['skewed']);
    expect(set.findings).toHaveLength(3);
    expect(set.future_dated_note).toBeUndefined();
  });

  it('a future-dated scan is never served from the cache either', () => {
    const s = freshPlugin();
    const p = projectDir('future-');
    scanAt(s, p, 'ahead', Date.now() + 60 * MINUTE, 0);
    s.db.prepare(`UPDATE scans SET cache_key = 'k' WHERE id = 'ahead'`).run();
    expect(s.storage.scans.findCacheHit({ cache_key: 'k', freshThreshold: new Date(Date.now() - 5 * MINUTE).toISOString() })).toBeNull();
  });
});
