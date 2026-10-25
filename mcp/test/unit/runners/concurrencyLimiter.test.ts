import { afterEach, describe, expect, it } from 'vitest';
import { getScanLimiter, resetLimiter } from '../../../src/runners/concurrencyLimiter.js';

afterEach(() => {
  resetLimiter();
  delete process.env['GUARDIAN_MAX_CONCURRENT_SCANS'];
});

describe('concurrency limiter', () => {
  it('serialises beyond the configured cap', async () => {
    process.env['GUARDIAN_MAX_CONCURRENT_SCANS'] = '2';
    resetLimiter();
    const limiter = getScanLimiter();

    let peak = 0;
    let active = 0;

    const work = async (): Promise<void> => {
      await limiter.acquire();
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((r) => setTimeout(r, 30));
      active -= 1;
      limiter.release();
    };

    await Promise.all([work(), work(), work(), work(), work()]);
    expect(peak).toBe(2);
  });

  it('exposes inFlight and queued counts', async () => {
    process.env['GUARDIAN_MAX_CONCURRENT_SCANS'] = '1';
    resetLimiter();
    const limiter = getScanLimiter();

    let releaseFirst: (() => void) | null = null;
    const firstDone = new Promise<void>((r) => {
      releaseFirst = r;
    });

    const slow = (async () => {
      await limiter.acquire();
      await firstDone;
      limiter.release();
    })();

    // Give slow() a tick to acquire.
    await new Promise((r) => setImmediate(r));
    expect(limiter.inFlight).toBe(1);

    // Queue one more — it should report queued=1.
    const queued = (async () => {
      await limiter.acquire();
      limiter.release();
    })();
    await new Promise((r) => setImmediate(r));
    expect(limiter.queued).toBe(1);

    if (releaseFirst) (releaseFirst as () => void)();
    await Promise.all([slow, queued]);
  });

  // Review 3.6.1, finding 7: release() gave the slot back before the woken
  // waiter took it, so an acquire() in between got in too — one over the limit.
  it('a release hands its slot to the first waiter: an acquire in between waits its turn', async () => {
    process.env['GUARDIAN_MAX_CONCURRENT_SCANS'] = '1';
    resetLimiter();
    const limiter = getScanLimiter();
    await limiter.acquire();
    let b = false;
    let c = false;
    const waiter = limiter.acquire().then(() => {
      b = true;
    });
    limiter.release();
    const late = limiter.acquire().then(() => {
      c = true;
    });
    await new Promise((r) => setImmediate(r));
    expect([b, c, limiter.inFlight, limiter.queued]).toEqual([true, false, 1, 1]);
    limiter.release();
    await Promise.all([waiter, late]);
    expect(c).toBe(true);
    limiter.release();
    expect(limiter.inFlight).toBe(0);
  });

  it('a waiter whose call is cancelled leaves the queue and takes no slot', async () => {
    process.env['GUARDIAN_MAX_CONCURRENT_SCANS'] = '1';
    resetLimiter();
    const limiter = getScanLimiter();
    await limiter.acquire();
    const stop = new AbortController();
    const cancelled = limiter.acquire(stop.signal);
    expect(limiter.queued).toBe(1);
    stop.abort();
    await expect(cancelled).rejects.toThrow(/cancelled while waiting for a scanner slot/);
    expect(limiter.queued).toBe(0);
    // Already cancelled: refused at once, no slot taken.
    await expect(limiter.acquire(stop.signal)).rejects.toThrow(/cancelled/);
    limiter.release();
    expect(limiter.inFlight).toBe(0);
  });
});
