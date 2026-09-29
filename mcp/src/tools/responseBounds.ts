/**
 * What a tool RESPONSE carries of a run's per-file gaps — never what is
 * stored.
 *
 * `ToolRun.partially_parsed` names every file a Semgrep run did not fully
 * analyse, and the scan row keeps every one: the history reads a finding in
 * any of them as not re-measured (`history/runCompare.ts`), and the CI gate
 * matches `--accept-partial-parse` against the whole list — both read the
 * handler's own result or the row, never this. But taint fixpoint timeouts
 * put hundreds of files there on a loaded run (`runners/semgrepReport.ts`):
 * LibreChat under `local_only` gave a 59.6 KB response, 43 KB of it one
 * `semgrep` entry with 232 files, and every MCP result travels twice (the
 * text block and `structuredContent`). So at the MCP boundary only
 * (`tools/index.ts#toCallToolResult`) a list longer than
 * {@link RESPONSE_PARTIAL_ENTRIES} is cut to its first entries, with the
 * whole count and the count per type beside it (review of the LLM pack,
 * round 3, N-2). A tool that calls another's handler (security_scan_full's
 * children, `ci/runScans.ts`) still gets the full list.
 */

import type { PartialParse, ToolRun } from '../types.js';

/** How many `partially_parsed` entries a response carries per list. */
export const RESPONSE_PARTIAL_ENTRIES = 20;

interface BoundedList {
  partially_parsed: PartialParse[];
  partially_parsed_total: number;
  partially_parsed_by_type: Record<string, number>;
}

function bound(list: readonly PartialParse[]): BoundedList | null {
  if (list.length <= RESPONSE_PARTIAL_ENTRIES) return null;
  const byType: Record<string, number> = {};
  for (const p of list) byType[p.type] = (byType[p.type] ?? 0) + 1;
  return {
    partially_parsed: list.slice(0, RESPONSE_PARTIAL_ENTRIES),
    partially_parsed_total: list.length,
    partially_parsed_by_type: byType,
  };
}

function isPartialList(value: unknown): value is PartialParse[] {
  return Array.isArray(value) && value.every((p) => p !== null && typeof p === 'object' && typeof (p as { file?: unknown }).file === 'string');
}

/**
 * `payload` as a response carries it: every `tools_run[].partially_parsed`
 * and a top-level `partially_parsed` (map_attack_surface) longer than
 * {@link RESPONSE_PARTIAL_ENTRIES} cut, with `partially_parsed_total` and
 * `partially_parsed_by_type` beside it. Anything else, and every list short
 * enough, is passed through as is (the same object when nothing is cut).
 */
export function boundResponsePayload(payload: Record<string, unknown>): Record<string, unknown> {
  let out = payload;
  const runs = payload['tools_run'];
  if (Array.isArray(runs)) {
    let changed = false;
    const bounded = runs.map((run: unknown) => {
      if (run === null || typeof run !== 'object') return run;
      const list = (run as ToolRun).partially_parsed;
      const cut = list === undefined ? null : bound(list);
      if (cut === null) return run;
      changed = true;
      return { ...(run as ToolRun), ...cut };
    });
    if (changed) out = { ...out, tools_run: bounded };
  }
  const top = payload['partially_parsed'];
  if (isPartialList(top)) {
    const cut = bound(top);
    if (cut !== null) out = { ...out, ...cut };
  }
  return out;
}
