/**
 * Scans dated in the future: the one rule every history reader applies.
 *
 * A scan's `started_at` / `finished_at` are what orders history — "the
 * latest scan" is the one that sorts first. A row dated in the future sorts
 * first until that date passes, whoever's clock was wrong: another machine's
 * on a shared database, or a database crafted so its rows outrank the
 * user's. Round 6 of the 3.0 review reproduced the second — a dense series
 * of future-dated scans with no findings became "latest" (risk 8/low,
 * coverage full, its source finished two days ahead) and shadowed the
 * victim's own scan (open 7 -> 0).
 *
 * So a row dated more than {@link FUTURE_SKEW_MINUTES} minutes past the
 * reader's clock — by its start or its finish — is ignored by every history
 * reader (`scansRepo.ts`, `findingsRepo.ts`, `cvesRepo.ts`), and a reader that
 * answers for a project says how many it passed over
 * ({@link futureDatedNote}). The rule is SQL, evaluated at query time
 * against SQLite's own clock, and a time that does not parse is not counted
 * as future (it never outranks anything a parseable one does).
 *
 * ---- A clock that steps back (3.4.0) --------------------------------------
 *
 * History orders by `started_at DESC, rowid DESC`. When the wall clock steps
 * back between two scans of one tool and slot — an NTP correction, a VM
 * resumed — the later scan sorted second, and "the latest scan" was the one
 * before it. {@link scanStartedAt} keeps this process's stamps in order
 * across a SMALL step back: a wall clock behind the last stamp it wrote, by
 * less than {@link MONOTONIC_HOLD_MS}, is that stamp + 1 ms. A larger gap is
 * a real correction (the clock was wrong before, not now): the wall clock is
 * trusted, and a debug line says so ({@link setScanClockLog}). A held stamp
 * is never more than the hold ahead of the wall clock, however many small
 * steps follow one another — far inside the {@link FUTURE_SKEW_MINUTES}
 * filter, so a held stamp is never read as future-dated. Other processes'
 * stamps are not ordered by this: two servers on one database keep the
 * rowid tie-break they had.
 */

/** How far past this machine's clock a scan may be dated and still be read. */
export const FUTURE_SKEW_MINUTES = 5;

/** The largest step back of the wall clock that scan stamps are held across, in ms. */
export const MONOTONIC_HOLD_MS = 5_000;

let lastStampMs: number | null = null;
let clockLog: (line: string) => void = () => {};

/** Where {@link scanStartedAt} says it trusted a clock that stepped back (the server's stderr log); silent by default. */
export function setScanClockLog(log: (line: string) => void): void {
  clockLog = log;
}

/** Forget the last stamp — a test's fresh process. */
export function resetScanClock(): void {
  lastStampMs = null;
}

/**
 * A scan's `started_at` (ISO 8601, ms): the wall clock, held at the last
 * stamp this process wrote + 1 ms while the clock is behind it by less than
 * {@link MONOTONIC_HOLD_MS} — see the module comment. `nowMs`: a test's clock.
 */
export function scanStartedAt(nowMs: number = Date.now()): string {
  let stamp = nowMs;
  if (lastStampMs !== null && nowMs < lastStampMs) {
    const behind = lastStampMs - nowMs;
    if (behind < MONOTONIC_HOLD_MS) {
      stamp = lastStampMs + 1;
    } else {
      clockLog(
        `the wall clock stepped back ${behind} ms since this process's last scan stamp — beyond the ` +
          `${MONOTONIC_HOLD_MS} ms it holds stamps across, so it is trusted as corrected: scans started before ` +
          'the step may sort after scans started since',
      );
    }
  }
  lastStampMs = stamp;
  return new Date(stamp).toISOString();
}

/**
 * SQL, true for a scan row (`alias.` prefix, or the bare table) dated more
 * than {@link FUTURE_SKEW_MINUTES} minutes in the future by its start or
 * its finish.
 */
export function datedInFutureSql(alias = ''): string {
  const col = (name: string): string => (alias === '' ? name : `${alias}.${name}`);
  const limit = `julianday('now', '+${FUTURE_SKEW_MINUTES} minutes')`;
  return (
    `(COALESCE(julianday(${col('started_at')}) > ${limit}, 0) ` +
    `OR COALESCE(julianday(${col('finished_at')}) > ${limit}, 0))`
  );
}

/** SQL, true for a scan row every history reader may read ({@link datedInFutureSql}, negated). */
export function notInFutureSql(alias = ''): string {
  return `NOT ${datedInFutureSql(alias)}`;
}

/** What a reader says when it passed over `count` future-dated scans; null when none. */
export function futureDatedNote(count: number): string | null {
  if (count <= 0) return null;
  return (
    `${count} scan(s) dated in the future were ignored (more than ${FUTURE_SKEW_MINUTES} minutes past this ` +
    "machine's clock): a clock that was wrong where they ran, or rows written to outrank the real history."
  );
}
