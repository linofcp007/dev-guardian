/**
 * Tiny in-process semaphore.
 *
 * Used by the scan-tool factory to cap how many concurrent scans we run.
 * Without this, a host that fires 50 parallel scan calls would spawn 50
 * scanner processes — easy way to take the box down. The limit is
 * configurable via env (`GUARDIAN_MAX_CONCURRENT_SCANS`); default 2.
 */

const DEFAULT_LIMIT = 2;

class Semaphore {
  private active = 0;
  private waiting: Array<() => void> = [];

  constructor(private readonly limit: number) {}

  async acquire(): Promise<void> {
    if (this.active < this.limit) {
      this.active += 1;
      return;
    }
    await new Promise<void>((resolve) => this.waiting.push(resolve));
    this.active += 1;
  }

  release(): void {
    this.active -= 1;
    const next = this.waiting.shift();
    if (next) next();
  }

  get inFlight(): number {
    return this.active;
  }
  get queued(): number {
    return this.waiting.length;
  }
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
