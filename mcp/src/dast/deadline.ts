/**
 * The scan's global wall-clock ceiling (design §5).
 *
 * The per-request timeout bounds one probe; the request ceiling bounds how
 * many are planned. Neither bounds the total. A 750-request plan against a
 * target that answers every request slowly can run for a quarter of an hour
 * with no single bound exceeded, which is not a shape an active scanner
 * pointed at someone's live application should be able to take.
 *
 * The mechanism is deliberately the one `probe.ts` already implements rather
 * than a second, parallel one: an `AbortSignal` handed to every probe. That
 * buys the distinction that matters — a probe cut by this deadline records
 * `outcome: 'cancelled'`, NOT `'timeout'`. The target did not fail to answer;
 * we stopped asking. Collapsing the two would report "the target timed out on
 * 300 requests" about a run this tool itself cut short, which is the exact
 * class of fabricated claim this feature exists to avoid (and the reason
 * Task 3 separated the two outcomes in the first place).
 *
 * `hit()` is true only for the deadline, never for a host cancellation, even
 * though both abort the same signal — "the operator stopped this scan" and
 * "the scan ran out of its own time budget" are different facts and lead to
 * different results (`cancelled` versus a truncated-but-reported run).
 */

/**
 * Ten minutes. Generous for a healthy target — the default 750-request plan
 * at concurrency 4 against an app answering in tens of milliseconds finishes
 * in seconds — and short enough that a pathological run is cut rather than
 * left going. Overridable per call, and always reported when it cuts.
 */
export const DEFAULT_WALL_CLOCK_MS = 600_000;

export interface ScanDeadline {
  /** Pass to `ProbeOptions.signal`. Aborts on the deadline OR a host cancel. */
  signal: AbortSignal;
  /** True exactly when the ceiling fired. False for a host cancellation. */
  hit: () => boolean;
  /** Clears the timer and unsubscribes. Must run on every exit path. */
  dispose: () => void;
}

export function armDeadline(ms: number, hostSignal?: AbortSignal): ScanDeadline {
  const controller = new AbortController();
  let deadlineFired = false;

  const timer = setTimeout(() => {
    deadlineFired = true;
    controller.abort();
  }, ms);
  // A stray timer must never be the reason this process stays alive. `dispose`
  // clears it on every path; `unref` is the belt to that braces.
  timer.unref();

  const onHostAbort = (): void => controller.abort();
  if (hostSignal?.aborted === true) {
    // The same trap `probe.ts` documents: adding an 'abort' listener to a
    // signal that has already aborted never fires it, so an already-cancelled
    // call would otherwise run its full plan against the live target.
    controller.abort();
  } else {
    hostSignal?.addEventListener('abort', onHostAbort);
  }

  return {
    signal: controller.signal,
    hit: () => deadlineFired,
    dispose: () => {
      clearTimeout(timer);
      hostSignal?.removeEventListener('abort', onHostAbort);
    },
  };
}
