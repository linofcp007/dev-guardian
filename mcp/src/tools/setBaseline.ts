/**
 * `set_baseline` — mark a scan as its project's regression baseline for its
 * scan type.
 *
 * Pure SQL: inserts a new row in `baselines` recording the scan, its project
 * and its scan type (migration 008). The scan is either the argument
 * (validated to exist and be completed) or `project_path`'s newest usable
 * state scan — of `scan_type` when given (default project: the server's
 * working directory). It used to default to the newest completed scan in the
 * WHOLE database: another project's, or an SBOM.
 *
 * The most recently inserted row of a project and type is that type's
 * active baseline; `diff_scans from='baseline'` and `regression_alert` read
 * it. Older rows are kept for audit/history.
 */

import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { latestStateScan } from '../history/openSet.js';
import { notMeasured as notMeasuredBy } from '../history/runCompare.js';
import { isScopedScan } from '../history/scanRoles.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import { chooseSourceTool, SOURCE_TOOL_WITH_SCAN_ID, SourceToolInput } from './sourceToolArg.js';
import { SCAN_TYPES, type DomainError, type ScanType, type ToolResult } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

const inputSchema = {
  project_path: ProjectPath,
  scan_id: z
    .string()
    .uuid()
    .optional()
    .describe("Scan to mark as the baseline. Defaults to project_path's newest usable scan."),
  scan_type: z
    .enum(SCAN_TYPES)
    .optional()
    .describe('Without scan_id: baseline the newest scan of this type. Default: any finding-producing type.'),
  source_tool: SourceToolInput,
  note: z.string().max(500).optional().describe('Free-form note attached to the baseline row.'),
};

const tool: ToolModule = {
  name: 'set_baseline',
  title: 'Set regression baseline',
  description:
    "Mark a scan as its project's regression baseline for its scan type. Without scan_id, uses " +
    "project_path's (default: the server's working directory) newest usable scan — of scan_type " +
    'when given — never an SBOM, stack detection, diff review, scoped scan (meta.scope; refused ' +
    'as scan_id too) or a scan whose scanners did not run. Future `diff_scans from=baseline` and ' +
    '`regression_alert` calls compare scans of that ' +
    'type against it. Older baselines are kept for history but inactive. For scan_type sarif_import (import_sarif), ' +
    "source_tool says which tool's newest import is baselined — each tool keeps its own baseline.",
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as { project_path?: string; scan_id?: string; scan_type?: ScanType; source_tool?: string; note?: string };

  if (inp.scan_id && inp.source_tool !== undefined) return failDomain('unsupported_target', SOURCE_TOOL_WITH_SCAN_ID);
  let targetScanId: string;
  if (inp.scan_id) {
    const scan = ctx.storage.scans.getById(inp.scan_id);
    if (!scan) {
      return failDomain('unknown_scan_id', `No scan with id '${inp.scan_id}'.`);
    }
    if (scan.status !== 'completed') {
      return failDomain(
        'unknown_scan_id',
        `Scan '${inp.scan_id}' is status='${scan.status}'. Baselines require completed scans.`,
      );
    }
    // A scoped scan (a diff, a file, the changes since a tag) saw part of the
    // project: as a baseline, everything outside its scope would come back
    // "new" on the next whole-project scan.
    if (isScopedScan(scan)) {
      return failDomain(
        'unsupported_target',
        `Scan '${inp.scan_id}' is a scoped scan (meta.scope) — it measured part of the project only, so it ` +
          'cannot be a baseline. Baseline a whole-project scan of the same type.',
      );
    }
    targetScanId = inp.scan_id;
  } else {
    let projectPath: string;
    try {
      projectPath = resolveProjectPath(inp.project_path).path;
    } catch (e) {
      return failDomain('not_a_git_repo', (e as Error).message);
    }
    const choice = chooseSourceTool(ctx.storage, projectPath, inp.scan_type, inp.source_tool);
    if (!choice.ok) return failDomain('unsupported_target', choice.message);
    const latest = latestStateScan(ctx.storage, projectPath, inp.scan_type, choice.sourceTool !== undefined ? { sourceTool: choice.sourceTool } : {});
    if (!latest.scan) {
      return failDomain(
        'unknown_scan_id',
        `No usable completed ${inp.scan_type ?? 'finding-producing'} scan exists for ${projectPath} ` +
          'yet; run a scan tool before setting a baseline.' +
          (latest.skipped.count > 0
            ? ` Skipped ${latest.skipped.count} scan(s) whose scanners did not run (coverage none).`
            : ''),
      );
    }
    targetScanId = latest.scan.scan_id;
  }

  const baseline = ctx.storage.baselines.set({
    scan_id: targetScanId,
    ...(inp.note !== undefined ? { note: inp.note } : {}),
  });

  // Set, but flagged: a baseline of a scan that did not fully measure
  // something — a failed child of security_scan_full, one scanner that failed
  // or was missing beside others that ran (Semgrep exit 7 next to Bandit), or
  // one failed pass of a scanner (guardian-dast:unanswered) — holds none, or
  // only some, of its findings. `notMeasured(…, 'gaps')` names exactly what
  // the comparing readers treat as unmeasured in a REFERENCE
  // (`history/runCompare.ts`), so the warning's promise is theirs: a later
  // finding from it that the baseline does not hold is "not previously
  // measured", never new, and never scored. A scanner the scan did not run at
  // all — not applicable, or not requested — is no gap: what it finds later is
  // new, so it is not flagged here. Not refused — a machine without Trivy
  // would then never get a baseline — and never presented as a complete
  // measurement either.
  const target = ctx.storage.scans.getById(targetScanId);
  const notMeasured = target === null ? [] : notMeasuredBy(ctx.storage, target, 'gaps');

  return {
    ok: true,
    baseline_id: baseline.id,
    scan_id: baseline.scan_id,
    project_path: baseline.project_path,
    scan_type: baseline.scan_type,
    set_at: baseline.set_at,
    ...(baseline.note !== undefined ? { note: baseline.note } : {}),
    ...(notMeasured.length > 0
      ? {
          not_measured: notMeasured,
          warning:
            `This baseline's scan did not fully measure ${notMeasured.join(', ')} (a scanner, or a pass ` +
            'of one, failed or was not installed), so it holds only some of their findings, or none. Later ' +
            'comparisons against this baseline report a finding from them that it does not hold as ' +
            '"not previously measured" — never as new, and never counted in regression_alert\'s ' +
            'score. Re-run the scan once the scanner works and set the baseline again.',
        }
      : {}),
  };
}

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
