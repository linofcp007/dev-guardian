/**
 * Execute probe requests. All I/O, no decisions.
 *
 * Never throws: a timeout, a refused connection and a DNS failure are all
 * *recorded outcomes*, because a DAST run that aborts on the first dead route
 * tells you nothing about the other three hundred.
 *
 * `redirect: 'manual'` is load-bearing, not a preference. Following a redirect
 * could carry the scanner off the authorised target — an open redirect on the
 * target would turn this tool into a request forwarder aimed wherever the
 * server says. Redirects are observed and reported; `analyze.ts` turns an
 * off-origin Location into an open-redirect finding.
 */
import { createHash } from 'node:crypto';
export const BODY_PREFIX_BYTES = 8192;
export const BODY_READ_CAP_BYTES = 256 * 1024;
export const DEFAULT_PROBE_TIMEOUT_MS = 5000;
export const DEFAULT_CONCURRENCY = 4;
export async function executeProbe(req, opts) {
    const started = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), opts.timeoutMs);
    const onOuterAbort = () => controller.abort();
    if (opts.signal?.aborted === true) {
        // Already aborted before this call started — e.g. a later request
        // claimed by `executeProbes`' worker pool after the caller cancelled the
        // scan. Adding an 'abort' listener to an AbortSignal that is already
        // aborted never fires it (the event already happened, per the DOM
        // event model), so react to the stale signal directly here instead of
        // silently wiring up a listener that would never trigger — the
        // alternative is this request running to completion, or its own
        // `timeoutMs`, against the live target after the scan was supposedly
        // stopped.
        controller.abort();
    }
    else {
        opts.signal?.addEventListener('abort', onOuterAbort);
    }
    try {
        const init = {
            method: req.method,
            headers: req.headers,
            redirect: 'manual',
            signal: controller.signal,
        };
        if (req.body !== undefined && req.method !== 'GET' && req.method !== 'HEAD') {
            init.body = req.body;
        }
        const res = await fetch(req.url, init);
        const text = await readCapped(res);
        const headers = {};
        res.headers.forEach((value, key) => {
            headers[key.toLowerCase()] = value;
        });
        return {
            request: req,
            outcome: 'completed',
            status: res.status,
            headers,
            body_prefix: text.slice(0, BODY_PREFIX_BYTES),
            body_hash: createHash('sha256').update(text).digest('hex'),
            elapsed_ms: Date.now() - started,
            error: null,
        };
    }
    catch (e) {
        const elapsed = Date.now() - started;
        // The timer's abort and the outer signal's abort both land on this same
        // `controller`, so `controller.signal.aborted` alone cannot tell "the
        // host stopped this scan" from "the target didn't answer" — the two
        // routes are indistinguishable at that point. Check the outer signal
        // first: it is the more specific fact, and a host cancellation is true
        // regardless of whether the internal timer had also fired by the time
        // the fetch actually unwound.
        let outcome;
        if (opts.signal?.aborted === true) {
            outcome = 'cancelled';
        }
        else if (controller.signal.aborted) {
            outcome = 'timeout';
        }
        else {
            outcome = 'network_error';
        }
        return {
            request: req,
            outcome,
            status: null,
            headers: {},
            body_prefix: '',
            body_hash: '',
            elapsed_ms: elapsed,
            // Never assert `e` is an Error: this catch is the module's whole "never
            // throws" guarantee. A cast (`e as Error`) would type-check and still
            // throw at runtime if anything ever rejects with a non-Error value,
            // which would escape as an unhandled rejection from this function.
            error: e instanceof Error ? e.message : String(e),
        };
    }
    finally {
        clearTimeout(timer);
        opts.signal?.removeEventListener('abort', onOuterAbort);
    }
}
/** Results are returned in input order regardless of completion order. */
export async function executeProbes(reqs, opts) {
    const results = new Array(reqs.length);
    let next = 0;
    const worker = async () => {
        for (;;) {
            const i = next;
            next += 1;
            const req = reqs[i];
            if (req === undefined)
                return;
            results[i] = await executeProbe(req, opts);
        }
    };
    const lanes = Math.max(1, Math.min(opts.concurrency, reqs.length));
    await Promise.all(Array.from({ length: lanes }, () => worker()));
    return results;
}
/**
 * Read at most `BODY_READ_CAP_BYTES`. A target that streams gigabytes (or
 * never closes) must not be able to exhaust this process's memory — the cap is
 * a scanner-safety property, not an optimisation.
 */
async function readCapped(res) {
    const body = res.body;
    if (body === null)
        return '';
    const reader = body.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
        const { done, value } = await reader.read();
        if (done)
            break;
        if (value === undefined)
            continue;
        chunks.push(value);
        total += value.byteLength;
        if (total >= BODY_READ_CAP_BYTES) {
            await reader.cancel();
            break;
        }
    }
    return Buffer.concat(chunks).toString('utf8');
}
//# sourceMappingURL=probe.js.map