/**
 * One scan's scanners, run side by side — `scan_sast`'s Semgrep, Bandit,
 * gosec, cppcheck, Psalm and the .NET analyzers ran one after another, so a
 * project in several languages waited for the sum of them; side by side it
 * waits for the slowest.
 *
 * Each pass gathers into its own `tools_run` / `missing_tools` /
 * `parser_inputs`, merged in the passes' order once all are done: the result
 * reads the same whichever finished first, and a pass that judges the entry
 * it just pushed (`tools_run.at(-1)`) still finds its own. A pass that throws
 * costs its own entry — `failed`, the error as its reason — never the
 * others' results. `after` names earlier passes it must wait for: one that
 * writes into the tree another walks (Semgrep's `--autofix`, a .NET build's
 * `obj/` and `bin/`). At most `limit` run at once
 * (`GUARDIAN_MAX_PARALLEL_SCANNERS`, {@link maxParallelScanners}): each
 * scanner may use several cores and a few GB of its own — Psalm reached ~2 GB
 * on WooCommerce.
 */

import type { ScannerParser } from './scannerParsers/index.js';
import type { ToolRun } from '../types.js';

/** What one pass gathers. */
export interface PassCollect {
  tools_run: ToolRun[];
  missing_tools: string[];
  parser_inputs: Array<{ parser: ScannerParser; input: unknown }>;
}

export interface ScannerPass {
  /** The pass's `tools_run` name, used when it throws, and how `after` names it. */
  name: string;
  /** Earlier passes (by name) that must finish before this one starts. */
  after?: readonly string[];
  run: (into: PassCollect) => Promise<void>;
}

/** How many of one scan's scanners run at once, unless `GUARDIAN_MAX_PARALLEL_SCANNERS` says otherwise. */
export const DEFAULT_MAX_PARALLEL_SCANNERS = 3;

/** `GUARDIAN_MAX_PARALLEL_SCANNERS` when it is a whole number of 1 or more (1: one after another); else the default. */
export function maxParallelScanners(env: NodeJS.ProcessEnv = process.env): number {
  const n = Number(env['GUARDIAN_MAX_PARALLEL_SCANNERS']);
  return Number.isInteger(n) && n > 0 ? n : DEFAULT_MAX_PARALLEL_SCANNERS;
}

/** Run `passes` side by side (see the module comment), at most `limit` at once; their results merged in order. */
export async function runScannerPasses(passes: readonly ScannerPass[], limit: number): Promise<PassCollect> {
  const parts = passes.map((): PassCollect => ({ tools_run: [], missing_tools: [], parser_inputs: [] }));
  let active = 0;
  const waiting: Array<() => void> = [];
  const acquire = async (): Promise<void> => {
    if (active < Math.max(1, limit)) {
      active += 1;
      return;
    }
    // The slot is handed over by `release`, `active` unchanged.
    await new Promise<void>((resolve) => waiting.push(resolve));
  };
  const release = (): void => {
    const next = waiting.shift();
    if (next !== undefined) next();
    else active -= 1;
  };
  const done = new Map<string, Promise<void>>();
  passes.forEach((pass, i) => {
    const into = parts[i];
    if (into === undefined) return;
    // Only an earlier pass can be waited for: a later one is not in `done` yet.
    const before = (pass.after ?? []).flatMap((name) => done.get(name) ?? []);
    done.set(
      pass.name,
      (async () => {
        await Promise.all(before);
        await acquire();
        try {
          await pass.run(into);
        } catch (e) {
          into.tools_run.push({
            name: pass.name,
            status: 'failed',
            reason: `${pass.name} could not run: ${e instanceof Error ? e.message : String(e)}`,
          });
        } finally {
          release();
        }
      })(),
    );
  });
  await Promise.all(done.values());
  const out: PassCollect = { tools_run: [], missing_tools: [], parser_inputs: [] };
  for (const part of parts) {
    out.tools_run.push(...part.tools_run);
    for (const name of part.missing_tools) if (!out.missing_tools.includes(name)) out.missing_tools.push(name);
    out.parser_inputs.push(...part.parser_inputs);
  }
  return out;
}
