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
import type { DastFinding } from './analyze.js';
import type { Redactor } from './redact.js';
import type { ProbeRequest, ProbeResult, ProbeVariant } from './types.js';

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

export interface EvidenceResponse {
  outcome: ProbeResult['outcome'];
  status: number | null;
  headers: Record<string, string>;
  body_excerpt: string;
  body_truncated: boolean;
  elapsed_ms: number;
  error: string | null;
}

export interface EvidenceExchange {
  variant: ProbeVariant;
  request: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: string;
  };
  response: EvidenceResponse | null;
}

export interface EvidenceRecord {
  fingerprint: string;
  check: string;
  rule_id?: string;
  /** The `ProbeRequest.id` (or nuclei hit id) the finding was built from. */
  evidence_id: string;
  origin: string;
  exchanges: EvidenceExchange[];
  /** Present only on the rate-limit finding — see the module doc comment. */
  burst?: {
    planned: number;
    sent: number;
    statuses: (number | null)[];
    observed: boolean;
  };
  /** Set when there is no probe exchange to show, saying why. */
  note?: string;
}

function toExchange(result: ProbeResult): EvidenceExchange {
  return { ...requestPart(result.request), response: responsePart(result) };
}

function requestPart(request: ProbeRequest): Omit<EvidenceExchange, 'response'> {
  const part: Omit<EvidenceExchange, 'response'> = {
    variant: request.variant,
    request: { method: request.method, url: request.url, headers: request.headers },
  };
  if (request.body !== undefined) part.request.body = request.body;
  return part;
}

function responsePart(result: ProbeResult): EvidenceResponse {
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
export function buildEvidence(
  finding: DastFinding,
  origin: string,
  results: readonly ProbeResult[],
): EvidenceRecord {
  const primary = results.find((r) => r.request.id === finding.evidence_id);
  const record: EvidenceRecord = {
    fingerprint: finding.fingerprint,
    check: finding.check,
    evidence_id: finding.evidence_id,
    origin,
    exchanges: [],
  };
  if (finding.rule_id !== undefined) record.rule_id = finding.rule_id;

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
    if (other === primary) continue;
    if (other.request.method !== primary.request.method) continue;
    if (other.request.path !== primary.request.path) continue;
    record.exchanges.push(toExchange(other));
  }
  return record;
}

/** The rate-limit burst's single aggregate record. */
export function buildBurstEvidence(
  finding: DastFinding,
  origin: string,
  burst: readonly ProbeResult[],
  planned: number,
  observed: boolean,
): EvidenceRecord {
  const first = burst[0];
  const record: EvidenceRecord = {
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
  if (finding.rule_id !== undefined) record.rule_id = finding.rule_id;
  if (first === undefined) record.note = 'The burst produced no results at all.';
  return record;
}

export interface EvidenceWriteOutcome {
  /**
   * Fingerprints whose file is genuinely on disk — not a count, because the
   * caller stores an `evidence_file` pointer on each finding and a pointer to
   * a file that was capped or failed to write would be a fabricated value.
   */
  written: Set<string>;
  /** Records beyond `MAX_EVIDENCE_FILES`; reported, never silently dropped. */
  capped: number;
  /** Records whose file could not be written (permissions, full disk). */
  failed: number;
}

/**
 * Write one `<fingerprint>.json` per record. Redaction is applied to the
 * serialised text, so it covers request headers, response headers and bodies
 * in one pass — including anything a future field adds.
 */
export function writeEvidenceFiles(
  dir: string,
  records: readonly EvidenceRecord[],
  redact: Redactor,
): EvidenceWriteOutcome {
  const outcome: EvidenceWriteOutcome = { written: new Set<string>(), capped: 0, failed: 0 };
  for (const [index, record] of records.entries()) {
    if (index >= MAX_EVIDENCE_FILES) {
      outcome.capped += 1;
      continue;
    }
    try {
      writeFileSync(
        join(dir, `${record.fingerprint}.json`),
        redact(JSON.stringify(record, null, 2)),
        'utf8',
      );
      outcome.written.add(record.fingerprint);
    } catch {
      outcome.failed += 1;
    }
  }
  return outcome;
}
