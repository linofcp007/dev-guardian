/**
 * A tool's content-only keys (`ToolModule.contentOnlyKeys`: `llm_scan_task`'s
 * `brief`, `generate_sbom`'s `inline`) must reach the model in every host.
 *
 * They used to travel only in the text block, with `structuredContent`
 * carrying the rest. Claude Code 2.1.293 hands the model `structuredContent`
 * when a result has one — measured in the llm-scan smoke test, 2026-10-08:
 * every `llm_scan_task` arrived with `task_id`, `lease_token` and
 * `response_schema` but no `brief`, and no task could be run. A result with
 * content-only keys now has ONE representation, the full text block, which
 * every host shows; the payload still travels once.
 */

import { describe, expect, it } from 'vitest';
import { toCallToolResult } from '../../../src/tools/index.js';

describe('content-only keys reach the model whichever representation the host shows', () => {
  const result = { ok: true as const, task_id: 't-0001', lease_token: 'tok', brief: 'Verify one finding ...' };

  it('a result with content-only keys carries no structuredContent, and the text holds every key', () => {
    const out = toCallToolResult(result, ['brief']);
    expect(out.structuredContent).toBeUndefined();
    expect(out.content).toHaveLength(1);
    const text = JSON.parse(out.content[0]?.text ?? '{}') as Record<string, unknown>;
    expect(text).toMatchObject({ ok: true, task_id: 't-0001', lease_token: 'tok', brief: 'Verify one finding ...' });
  });

  it('a result without them keeps both representations, as before', () => {
    const out = toCallToolResult(result, []);
    expect(out.structuredContent).toMatchObject({ task_id: 't-0001', brief: 'Verify one finding ...' });
    expect(out.content[0]?.text).toContain('"brief"');
  });

  it('an error is unchanged by content-only keys', () => {
    const out = toCallToolResult({ ok: false, error: { code: 'bad_lease', message: 'no' } }, ['brief']);
    expect(out.isError).toBe(true);
    expect(out.structuredContent).toMatchObject({ ok: false, error: { code: 'bad_lease' } });
  });
});
