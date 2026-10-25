/**
 * The timeout a scanner run gets — its own module, apart from
 * `processRunner.ts`, so a caller that splits one budget across several
 * runs (`semgrepRun.ts#runSemgrep`) reads the same default the runner
 * applies, and the tests that replace the runner keep it.
 */

const DEFAULT_TIMEOUT_MS = 10 * 60 * 1000;

/** The timeout a run with `timeoutMs` gets: that, or `GUARDIAN_SCAN_TIMEOUT_MS`, or ten minutes. */
export function effectiveTimeoutMs(timeoutMs: number | undefined): number {
  return timeoutMs ?? (Number(process.env['GUARDIAN_SCAN_TIMEOUT_MS']) || DEFAULT_TIMEOUT_MS);
}
