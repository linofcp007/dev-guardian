/**
 * Review of the LLM pack, round 3 (N-2): a response carries the first
 * entries of a per-file gap list and its counts; the handler's own result
 * (and the row) keep every entry.
 */

import { describe, expect, it } from 'vitest';
import { boundResponsePayload, RESPONSE_PARTIAL_ENTRIES } from '../../../src/tools/responseBounds.js';

const entries = (n: number, type: string) => Array.from({ length: n }, (_, i) => ({ file: `f${i}`, type, message: 'm' }));

describe('boundResponsePayload', () => {
  it('cuts a long tools_run[].partially_parsed to the first entries, with the total and the count per type', () => {
    const list = [...entries(30, 'PartialParsing'), ...entries(10, 'Fixpoint timeout')];
    const payload = { ok: true, tools_run: [{ name: 'semgrep', status: 'ok', partially_parsed: list }, { name: 'bandit', status: 'ok' }] };
    const out = boundResponsePayload(payload);
    const run = (out['tools_run'] as Array<Record<string, unknown>>)[0];
    expect((run?.['partially_parsed'] as unknown[]).length).toBe(RESPONSE_PARTIAL_ENTRIES);
    expect(run?.['partially_parsed_total']).toBe(40);
    expect(run?.['partially_parsed_by_type']).toEqual({ PartialParsing: 30, 'Fixpoint timeout': 10 });
    // The input is not touched: the caller's own result keeps every entry.
    expect(payload.tools_run[0]?.partially_parsed).toHaveLength(40);
  });

  it('cuts a top-level partially_parsed (map_attack_surface) the same way', () => {
    const out = boundResponsePayload({ ok: true, partially_parsed: entries(25, 'PartialParsing') });
    expect((out['partially_parsed'] as unknown[]).length).toBe(RESPONSE_PARTIAL_ENTRIES);
    expect(out['partially_parsed_total']).toBe(25);
  });

  it('leaves a short list, and a payload with none, as it is — the same object', () => {
    const short = { ok: true, tools_run: [{ name: 'semgrep', status: 'ok', partially_parsed: entries(RESPONSE_PARTIAL_ENTRIES, 'PartialParsing') }] };
    expect(boundResponsePayload(short)).toBe(short);
    const none = { ok: true, findings_count: 3 };
    expect(boundResponsePayload(none)).toBe(none);
  });
});
