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
    limit;
    active = 0;
    waiting = [];
    constructor(limit) {
        this.limit = limit;
    }
    async acquire() {
        if (this.active < this.limit) {
            this.active += 1;
            return;
        }
        await new Promise((resolve) => this.waiting.push(resolve));
        this.active += 1;
    }
    release() {
        this.active -= 1;
        const next = this.waiting.shift();
        if (next)
            next();
    }
    get inFlight() {
        return this.active;
    }
    get queued() {
        return this.waiting.length;
    }
}
let limiter = null;
export function getScanLimiter() {
    if (!limiter) {
        const fromEnv = Number(process.env['GUARDIAN_MAX_CONCURRENT_SCANS']);
        const limit = Number.isFinite(fromEnv) && fromEnv > 0 ? fromEnv : DEFAULT_LIMIT;
        limiter = new Semaphore(limit);
    }
    return limiter;
}
/** Test-only. */
export function resetLimiter() {
    limiter = null;
}
//# sourceMappingURL=concurrencyLimiter.js.map