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
 */

/** How far past this machine's clock a scan may be dated and still be read. */
export const FUTURE_SKEW_MINUTES = 5;

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
