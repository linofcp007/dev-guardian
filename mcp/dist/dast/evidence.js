/**
 * Evidence records — the redacted request/response exchanges a DAST finding
 * points at.
 *
 * Design §8 puts raw evidence under `.guardian/reports/dast-<short-scan-id>/`
 * rather than inline in the SQLite row, so the finding stays small and
 * diffable while the proof stays readable.
 *
 * Two decisions this module makes, both forced by shapes upstream:
 *
 *   - **Evidence is keyed by the finding's FINGERPRINT, never by
 *     `ProbeRequest.id`.** `rateLimit.ts#buildBurst` deliberately gives all
 *     thirty burst requests one identical id (the burst has to be
 *     byte-identical — it is a limiter probe, not a guessing attack), so an
 *     id-keyed writer would collapse thirty writes onto one file and let the
 *     last one win. A fingerprint is unique per stored finding by
 *     construction: it is the findings table's primary key alongside
 *     `scan_id`.
 *   - **The burst is written as ONE aggregate record.** Thirty copies of an
 *     identical request prove nothing individually; what a reader needs is
 *     the request template plus the status sequence that came back — exactly
 *     what `rateLimitVerdict` reasoned over.
 *
 * A record gathers every exchange at the finding's (method, path), not only
 * the one request the finding was built from: the anonymous and authenticated
 * twins side by side are what makes a `differential_authz` finding legible,
 * and having both there is also what the redaction guarantee is measured
 * against.
 */
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
/**
 * How much of a response body an evidence record carries. `probe.ts` already
 * caps what it reads at `BODY_PREFIX_BYTES` (8 KiB); this second, tighter cap
 * bounds what reaches disk across potentially hundreds of findings. It is
 * reported per record (`body_truncated`) rather than applied silently.
 */
export const EVIDENCE_BODY_CHARS = 2000;
/**
 * Ceiling on how many evidence files one scan writes. Findings are handed to
 * `writeEvidenceFiles` severity-first, so a cut lands on the least severe —
 * and the caller reports it rather than letting a finding quietly point at a
 * file that was never written.
 */
export const MAX_EVIDENCE_FILES = 200;
function toExchange(result) {
    return { ...requestPart(result.request), response: responsePart(result) };
}
function requestPart(request) {
    const part = {
        variant: request.variant,
        request: { method: request.method, url: request.url, headers: request.headers },
    };
    if (request.body !== undefined)
        part.request.body = request.body;
    return part;
}
function responsePart(result) {
    const body = result.body_prefix;
    return {
        outcome: result.outcome,
        status: result.status,
        headers: result.headers,
        body_excerpt: body.slice(0, EVIDENCE_BODY_CHARS),
        body_truncated: body.length > EVIDENCE_BODY_CHARS,
        elapsed_ms: result.elapsed_ms,
        error: result.error,
    };
}
/**
 * The exchange the finding names, followed by every other variant probed at
 * the same (method, path) — anonymous, authenticated and the CORS probe are
 * at most three, bounded by `plan.ts`'s (method, path) dedupe.
 */
export function buildEvidence(finding, origin, results) {
    const primary = results.find((r) => r.request.id === finding.evidence_id);
    const record = {
        fingerprint: finding.fingerprint,
        check: finding.check,
        evidence_id: finding.evidence_id,
        origin,
        exchanges: [],
    };
    if (finding.rule_id !== undefined)
        record.rule_id = finding.rule_id;
    if (primary === undefined) {
        // A nuclei hit has no `ProbeRequest` of ours behind it — inventing one
        // would be fabricating the very evidence this file exists to hold.
        record.note =
            'No probe exchange recorded for this finding; it was reported by an external engine. ' +
                'See nuclei.jsonl in this directory for the raw output.';
        return record;
    }
    record.exchanges.push(toExchange(primary));
    for (const other of results) {
        if (other === primary)
            continue;
        if (other.request.method !== primary.request.method)
            continue;
        if (other.request.path !== primary.request.path)
            continue;
        record.exchanges.push(toExchange(other));
    }
    return record;
}
/** The rate-limit burst's single aggregate record. */
export function buildBurstEvidence(finding, origin, burst, planned, observed) {
    const first = burst[0];
    const record = {
        fingerprint: finding.fingerprint,
        check: finding.check,
        evidence_id: finding.evidence_id,
        origin,
        exchanges: first === undefined ? [] : [toExchange(first)],
        burst: {
            planned,
            sent: burst.filter((r) => r.outcome === 'completed').length,
            statuses: burst.map((r) => r.status),
            observed,
        },
    };
    if (finding.rule_id !== undefined)
        record.rule_id = finding.rule_id;
    if (first === undefined)
        record.note = 'The burst produced no results at all.';
    return record;
}
/**
 * Write one `<fingerprint>.json` per record. Redaction is applied to the
 * serialised text, so it covers request headers, response headers and bodies
 * in one pass — including anything a future field adds.
 */
export function writeEvidenceFiles(dir, records, redact) {
    const outcome = { written: new Set(), capped: 0, failed: 0 };
    for (const [index, record] of records.entries()) {
        if (index >= MAX_EVIDENCE_FILES) {
            outcome.capped += 1;
            continue;
        }
        try {
            writeFileSync(join(dir, `${record.fingerprint}.json`), redact(JSON.stringify(record, null, 2)), 'utf8');
            outcome.written.add(record.fingerprint);
        }
        catch {
            outcome.failed += 1;
        }
    }
    return outcome;
}
//# sourceMappingURL=evidence.js.map