/**
 * Tiny in-process semaphore.
 *
 * Used by the scan-tool factory to cap how many concurrent scans we run.
 * Without this, a host that fires 50 parallel scan calls would spawn 50
 * scanner processes — easy way to take the box down. The limit is
 * configurable via env (`GUARDIAN_MAX_CONCURRENT_SCANS`); default 2.
 */

const DEFAULT_LIMIT = 2;

/**
 * A release HANDS its slot to the first waiter — `active` unchanged — as
 * `scannerPasses.ts` does (review 3.6.1, finding 7): giving it back first and
 * letting the woken waiter take it again left a gap, a microtask long, in
 * which a new `acquire()` got in too, one over the limit. A waiter whose
 * `signal` aborts leaves the queue, takes no slot, and is rejected.
 */
class Semaphore {
  private active = 0;
  private waiting: Array<() => void> = [];

  constructor(private readonly limit: number) {}

  async acquire(signal?: AbortSignal): Promise<void> {
    if (signal?.aborted === true) throw cancelledWaiting();
    if (this.active < this.limit) {
      this.active += 1;
      return;
    }
    await new Promise<void>((resolve, reject) => {
      const take = (): void => {
        signal?.removeEventListener('abort', leave);
        resolve();
      };
      const leave = (): void => {
        const at = this.waiting.indexOf(take);
        if (at >= 0) this.waiting.splice(at, 1);
        reject(cancelledWaiting());
      };
      this.waiting.push(take);
      signal?.addEventListener('abort', leave, { once: true });
    });
  }

  release(): void {
    const next = this.waiting.shift();
    if (next !== undefined) next();
    else this.active -= 1;
  }

  get inFlight(): number {
    return this.active;
  }
  get queued(): number {
    return this.waiting.length;
  }
}

function cancelledWaiting(): Error {
  const e = new Error('cancelled while waiting for a scanner slot');
  e.name = 'AbortError';
  return e;
}

let limiter: Semaphore | null = null;

export function getScanLimiter(): Semaphore {
  if (!limiter) {
    const fromEnv = Number(process.env['GUARDIAN_MAX_CONCURRENT_SCANS']);
    const limit = Number.isFinite(fromEnv) && fromEnv > 0 ? fromEnv : DEFAULT_LIMIT;
    limiter = new Semaphore(limit);
  }
  return limiter;
}

/** Test-only. */
export function resetLimiter(): void {
  limiter = null;
}
