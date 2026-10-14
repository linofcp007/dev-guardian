/**
 * The bounded monotonic `started_at` (3.4.0, a deferred design item of review
 * 10). History orders by `started_at DESC, rowid DESC`; a wall clock that
 * stepped back between two scans of one slot made the earlier scan "latest".
 * A small step back is held (last stamp + 1 ms); a large one — a real
 * correction — is trusted, and said; the hold never drifts past its bound, so
 * a stamp never reaches the 5-minute future-dated filter.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import {
  FUTURE_SKEW_MINUTES,
  MONOTONIC_HOLD_MS,
  resetScanClock,
  scanStartedAt,
  setScanClockLog,
} from '../../../src/storage/scanClock.js';
import { ScansRepo } from '../../../src/storage/scansRepo.js';

const T0 = Date.UTC(2020, 0, 2, 12, 0, 0);
const ms = (iso: string): number => Date.parse(iso);

beforeEach(() => {
  resetScanClock();
  setScanClockLog(() => {});
});
afterEach(() => {
  vi.restoreAllMocks();
  resetScanClock();
});

describe('scanStartedAt', () => {
  it('the wall clock as it reads, when it moves forward or stands still', () => {
    expect(scanStartedAt(T0)).toBe(new Date(T0).toISOString());
    expect(scanStartedAt(T0 + 250)).toBe(new Date(T0 + 250).toISOString());
    expect(scanStartedAt(T0 + 250)).toBe(new Date(T0 + 250).toISOString());
  });

  it('a step back of 1 ms keeps the order the scans started in', () => {
    const first = scanStartedAt(T0);
    const second = scanStartedAt(T0 - 1);
    expect(ms(second)).toBeGreaterThan(ms(first));
    expect(ms(second)).toBe(T0 + 1);
  });

  it('a large step back is a correction: trusted, not clamped, and said', () => {
    const lines: string[] = [];
    setScanClockLog((line) => lines.push(line));
    scanStartedAt(T0);
    const corrected = T0 - 60 * 60_000;
    expect(scanStartedAt(corrected)).toBe(new Date(corrected).toISOString());
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/stepped back 3600000 ms/);
    // And from there on, the corrected clock is the reference.
    expect(scanStartedAt(corrected + 5)).toBe(new Date(corrected + 5).toISOString());
  });

  it('repeated small steps back never hold a stamp more than the bound ahead — never near the future filter', () => {
    let now = T0;
    let lead = 0;
    scanStartedAt(now);
    for (let i = 0; i < 20_000; i += 1) {
      now -= 1; // a clock creeping backwards, one ms per scan
      lead = Math.max(lead, ms(scanStartedAt(now)) - now);
    }
    expect(lead).toBeLessThanOrEqual(MONOTONIC_HOLD_MS);
    expect(lead).toBeLessThan(FUTURE_SKEW_MINUTES * 60_000);
  });
});

describe('ScansRepo.insert stamps through it', () => {
  it('two scans of one slot, the clock stepping back 1 ms between them: the later one is the latest', () => {
    const db = new Database(':memory:');
    runMigrations(db);
    const repo = new ScansRepo(db);
    const now = vi.spyOn(Date, 'now');
    // Dated in the past, so `started_at` is never read as future-dated whatever the real clock says.
    now.mockReturnValue(T0);
    repo.insert({ scan_id: 'first', scan_type: 'sast', project_path: '/p', tree_hash: 'h' });
    now.mockReturnValue(T0 - 1);
    repo.insert({ scan_id: 'second', scan_type: 'sast', project_path: '/p', tree_hash: 'h' });
    now.mockRestore();
    for (const id of ['first', 'second']) repo.finalize({ scan_id: id, status: 'completed', tools_run: [], missing_tools: [] });
    expect(repo.listHistoryForProject('/p').map((s) => s.scan_id)).toEqual(['second', 'first']);
    expect(repo.getLatestForProject('/p')?.scan_id).toBe('second');
  });
});
