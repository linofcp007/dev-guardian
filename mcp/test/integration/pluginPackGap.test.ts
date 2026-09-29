/**
 * The plugin's LLM pack's own taint timeouts are the PACK's gap, not the
 * scan's.
 *
 * `scan_sast` records them in the Semgrep run's shared `partially_parsed`
 * under their own type, `Fixpoint timeout (plugin pack)`
 * (`runners/semgrepReport.ts#withPluginPackFixpoint`), and leaves the run's
 * status and `missing_tools` alone. Only the CI gate filtered that type. Two
 * other readers still took it for the scan's gap — on essentially every
 * scan_sast of a TypeScript codebase (19 pack timeouts in 18 files on this
 * repo's own mcp/src):
 *
 *   - OWASP coverage: every category the registry reached dropped from
 *     `tested` to `partial` ("some files were only partly parsed") — in
 *     report_export, the dashboard's coverage.owasp and compliance_evidence;
 *   - history: a REGISTRY finding fixed in one of those files read "not
 *     re-measured" instead of resolved, and stayed open.
 *
 * The rule now: every reader ignores the type, except that history treats a
 * file under it as not re-measured for findings of the pack's own rules.
 */

import { readFileSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { owaspCoverage } from '../../src/frameworks/coverage.js';
import { openSetForProject } from '../../src/history/openSet.js';
import { FIXPOINT_TIMEOUT_PACK_TYPE } from '../../src/runners/semgrepReport.js';
import { TOOLS } from '../../src/tools/index.js';
import type { ToolRun } from '../../src/types.js';
import { freshPlugin, projectDir, seedScan } from '../helpers/historySeed.js';
import { cleanupTempDirs } from '../helpers/tempDir.js';
import { okResult } from '../helpers/toolResult.js';

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/registerAll.js');
});

function tool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`tool ${name} not registered`);
  return t;
}

/** A pack rule id, as a pack finding is stored (the rule's own id). */
const PACK_RULE = 'llm-output-to-interpreter-js';
const REGISTRY_RULE = 'javascript.express.security.audit.xss.direct-response-write';

/** scan_sast's Semgrep run with only the LLM pack's own fixpoint timeouts in `files`. */
function packGapRun(...files: string[]): ToolRun {
  return {
    name: 'semgrep',
    status: 'ok',
    reason: "ran; the plugin's LLM pack: taint analysis incomplete",
    partially_parsed: files.map((file) => ({ file, type: FIXPOINT_TIMEOUT_PACK_TYPE, message: 'x', functions: 1 })),
    plugin_packs: { llm: { status: 'partial', reason: 'taint analysis incomplete' } },
  };
}

const JS = { local_only: false, project_languages: { languages: ['javascript'], source: 'test' } };

describe("OWASP coverage ignores the pack's own gap", () => {
  it('control: a clean registry run tests A05 for javascript', () => {
    const cov = owaspCoverage(
      [{ scan_id: 'a', scan_type: 'sast', tools_run: [{ name: 'semgrep', status: 'ok' }], missing_tools: [], meta: JS }],
      [],
      { languages: ['javascript'], source: 'test' },
    );
    expect(cov.categories.find((c) => c.id === 'A05:2025')?.status).toBe('tested');
  });

  it("A05 stays tested when the only partial entries are the pack's fixpoint timeouts", () => {
    const cov = owaspCoverage(
      [{ scan_id: 'a', scan_type: 'sast', tools_run: [packGapRun('src/llm.ts')], missing_tools: [], meta: JS }],
      [],
      { languages: ['javascript'], source: 'test' },
    );
    const a05 = cov.categories.find((c) => c.id === 'A05:2025');
    expect(a05?.status).toBe('tested');
    expect(a05?.reasons.join(' ') ?? '').not.toMatch(/partly parsed/);
  });

  it('report_export (the reviewer\'s repro): A05 tested, not partial', async () => {
    const s = freshPlugin();
    const p = projectDir('packgap-report-');
    const id = seedScan(s, {
      id: '00000000-0000-4000-8000-0000000000a1',
      type: 'sast',
      project: p,
      tools_run: [packGapRun('src/llm.ts', 'src/agent.ts')],
      meta: JS,
    });
    const r = okResult<{ file_path: string }>(
      await tool('report_export').handler({ project_path: p, scan_id: id, format: 'json' }, s.plugin),
    );
    const report = JSON.parse(readFileSync(r.file_path, 'utf8')) as {
      owasp_2025: { categories: Array<{ id: string; status: string }> };
    };
    expect(report.owasp_2025.categories.find((c) => c.id === 'A05:2025')?.status).toBe('tested');
  });
});

describe("history reads the pack's gap for the pack's findings only", () => {
  function pair(ruleId: string): { s: ReturnType<typeof freshPlugin>; p: string } {
    const s = freshPlugin();
    const p = projectDir('packgap-history-');
    seedScan(s, { id: 'older', type: 'sast', project: p, findings: [{ fp: 'fp-1', tool: 'semgrep', rule_id: ruleId, file: 'src/llm.ts' }] });
    seedScan(s, { id: 'newer', type: 'sast', project: p, tools_run: [packGapRun('src/llm.ts')] });
    return { s, p };
  }

  it('a registry finding fixed in a pack-gap file is resolved, and leaves the open set', async () => {
    const { s, p } = pair(REGISTRY_RULE);
    const d = okResult<{ summary: Record<string, number>; not_measured?: string[] }>(
      await tool('diff_scans').handler({ project_path: p, scan_type: 'sast' }, s.plugin),
    );
    expect(d.summary).toMatchObject({ resolved: 1, not_remeasured: 0 });
    expect(openSetForProject(s.storage, p).findings).toEqual([]);
  });

  it("a pack finding there is not re-measured, and stays open (carried)", async () => {
    const { s, p } = pair(PACK_RULE);
    const d = okResult<{ summary: Record<string, number>; not_measured?: string[] }>(
      await tool('diff_scans').handler({ project_path: p, scan_type: 'sast' }, s.plugin),
    );
    expect(d.summary).toMatchObject({ resolved: 0, not_remeasured: 1 });
    expect(d.not_measured).toEqual(['semgrep (LLM pack partly measured: src/llm.ts)']);
    const open = openSetForProject(s.storage, p).findings;
    expect(open.map((f) => [f.fingerprint, f.not_remeasured])).toEqual([['fp-1', true]]);
  });

  it('control: a registry finding in a file Semgrep itself only partly parsed is still not re-measured', async () => {
    const s = freshPlugin();
    const p = projectDir('packgap-history-');
    seedScan(s, { id: 'older', type: 'sast', project: p, findings: [{ fp: 'fp-1', tool: 'semgrep', rule_id: REGISTRY_RULE, file: 'src/llm.ts' }] });
    seedScan(s, {
      id: 'newer',
      type: 'sast',
      project: p,
      tools_run: [{ ...packGapRun('src/llm.ts'), partially_parsed: [{ file: 'src/llm.ts', type: 'Fixpoint timeout', message: 'x', functions: 1 }] }],
    });
    const d = okResult<{ summary: Record<string, number> }>(
      await tool('diff_scans').handler({ project_path: p, scan_type: 'sast' }, s.plugin),
    );
    expect(d.summary).toMatchObject({ resolved: 0, not_remeasured: 1 });
  });
});
