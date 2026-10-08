/**
 * The `source_tool` argument of the tools that pick "the latest scan of a
 * type" (`set_baseline`, `diff_scans`, `regression_alert`, `report_export`):
 * for `sarif_import` the latest scan, and the baseline, are one source tool's.
 */

import { z } from 'zod';
import type { Storage } from '../storage/index.js';
import type { ScanType } from '../types.js';

export const SourceToolInput = z
  .string()
  .min(1)
  .max(100)
  .optional()
  .describe(
    "With scan_type 'sarif_import': the source tool whose imports are read (the driver name an import recorded). " +
      'Required when the project holds imports from more than one tool.',
  );

export type SourceToolChoice = { ok: true; sourceTool?: string } | { ok: false; message: string };

/**
 * The source tool to read for a call that names no explicit scan: the one
 * asked for, else the project's only one. A `source_tool` with any other
 * scan type is refused, and so is `sarif_import` with imports from several
 * tools and none named — the refusal lists them.
 */
export function chooseSourceTool(
  storage: Storage,
  projectPath: string,
  scanType: ScanType | undefined,
  sourceTool: string | undefined,
): SourceToolChoice {
  if (scanType !== 'sarif_import') {
    return sourceTool === undefined
      ? { ok: true }
      : { ok: false, message: "source_tool applies only to scan_type 'sarif_import'." };
  }
  if (sourceTool !== undefined) return { ok: true, sourceTool };
  const tools = storage.scans.sarifSourceTools(projectPath);
  if (tools.length > 1) {
    return {
      ok: false,
      message:
        `${projectPath} holds SARIF imports from ${String(tools.length)} tools (${tools.map((t) => `'${t}'`).join(', ')}); ` +
        'pass source_tool to say which one.',
    };
  }
  const only = tools[0];
  return only === undefined ? { ok: true } : { ok: true, sourceTool: only };
}

/** The refusal of a `source_tool` next to an explicit scan id, which already names its tool. */
export const SOURCE_TOOL_WITH_SCAN_ID =
  'source_tool picks the latest import of a tool; it cannot be combined with an explicit scan id.';
