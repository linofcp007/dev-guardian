/**
 * `diff_scans` — compute the new / resolved / unchanged finding sets
 * between two scans of ONE project.
 *
 * Inputs:
 *   - `to_scan_id` (explicit) or `to: 'latest'` (default): the project's
 *     newest usable state scan — of `scan_type` when given. An SBOM, a stack
 *     detection or a diff review is never "the latest scan" (see
 *     `history/scanRoles.ts`), nor is a scan whose coverage was none.
 *   - `from_scan_id` (explicit), `from: 'baseline'` (the project's active
 *     baseline of the `to` scan's type), or `from: 'previous'` (the
 *     project's usable scan of the same `scan_type` immediately before
 *     `to`).
 *
 * The project is `project_path` (default: the server's working directory),
 * or — when `to_scan_id` is given — that scan's own project. "Previous" used
 * to be searched in the 200 newest scans of the WHOLE database, so it could
 * be another project's scan of the same type.
 *
 * "Previous of same type" matters: comparing a `deps` scan with a `sast`
 * scan is meaningless because the fingerprints come from different rule
 * families.
 *
 * Findings are matched by their line-independent `identity`, with the
 * fingerprint as the fallback where either scan predates identities
 * (`fingerprint/findingIdentity.ts#indexFindings`).
 *
 * Response size: `summary` carries the true counts; each list carries at
 * most {@link ITEMS_PER_BUCKET} findings and `truncated` says which were cut.
 */

import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { indexFindings } from '../fingerprint/findingIdentity.js';
import { latestStateScan, type SkippedScan } from '../history/openSet.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import { SCAN_TYPES, type DomainError, type Finding, type ScanType, type ToolResult } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

/** Items returned per bucket; the counts in `summary` are never capped. */
export const ITEMS_PER_BUCKET = 50;

const FromEnum = z.enum(['baseline', 'previous']);
const ToEnum = z.enum(['latest']);

const inputSchema = {
  project_path: ProjectPath,
  scan_type: z
    .enum(SCAN_TYPES)
    .optional()
    .describe("With to='latest': diff the newest scan of this type. Default: the newest scan of any finding-producing type."),
  from_scan_id: z.string().uuid().optional(),
  from: FromEnum.optional(),
  to_scan_id: z.string().uuid().optional(),
  to: ToEnum.optional(),
};

const tool: ToolModule = {
  name: 'diff_scans',
  title: 'Diff scans (regression / resolution detection)',
  description:
    'Compare findings between two scans of one project (same scan_type). Returns new (in to but ' +
    'not in from), resolved (in from but not in to) and unchanged (in both): true counts in ' +
    '`summary`, at most 50 findings per list, `truncated` naming the lists that were cut. ' +
    'Findings are matched by their line-independent identity, so code moving above a finding ' +
    'does not make it new; scans from before identities existed match by fingerprint. Default: ' +
    "from=previous, to=latest — the newest usable scan of project_path (default: the server's " +
    'working directory), never an SBOM/stack/diff-review run or one whose scanners did not run; ' +
    'skipped scans are listed in `skipped`. from=baseline uses the project\'s baseline of the ' +
    'same scan type.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as {
    project_path?: string;
    scan_type?: ScanType;
    from_scan_id?: string;
    from?: 'baseline' | 'previous';
    to_scan_id?: string;
    to?: 'latest';
  };

  const skipped: SkippedScan[] = [];

  // Resolve `to` first because `from='previous'` depends on it.
  const toScan = resolveTo(inp, ctx, skipped);
  if (!toScan.ok) return toScan.err;
  const fromId = resolveFrom(inp, toScan.value, ctx, skipped);
  if (!fromId.ok) return fromId.err;

  if (fromId.value === toScan.value.scan_id) {
    return failDomain(
      'unknown_scan_id',
      `Cannot diff a scan against itself (${toScan.value.scan_id}).`,
    );
  }

  const fromFindings = ctx.storage.findings.listByScan(fromId.value);
  const toFindings = ctx.storage.findings.listByScan(toScan.value.scan_id);

  const fromIndex = indexFindings(fromFindings);
  const toIndex = indexFindings(toFindings);

  const new_findings: Finding[] = [];
  const resolved_findings: Finding[] = [];
  const unchanged_findings: Finding[] = [];

  for (const f of toFindings) {
    if (fromIndex.has(f)) unchanged_findings.push(f);
    else new_findings.push(f);
  }
  for (const f of fromFindings) {
    if (!toIndex.has(f)) resolved_findings.push(f);
  }

  return {
    ok: true,
    project_path: toScan.value.project_path,
    scan_type: toScan.value.scan_type,
    from_scan_id: fromId.value,
    to_scan_id: toScan.value.scan_id,
    summary: {
      new: new_findings.length,
      resolved: resolved_findings.length,
      unchanged: unchanged_findings.length,
    },
    new_findings: new_findings.slice(0, ITEMS_PER_BUCKET),
    resolved_findings: resolved_findings.slice(0, ITEMS_PER_BUCKET),
    unchanged_findings: unchanged_findings.slice(0, ITEMS_PER_BUCKET),
    truncated: {
      new: new_findings.length > ITEMS_PER_BUCKET,
      resolved: resolved_findings.length > ITEMS_PER_BUCKET,
      unchanged: unchanged_findings.length > ITEMS_PER_BUCKET,
    },
    ...(skipped.length > 0 ? { skipped } : {}),
  };
}

type Resolved<T> = { ok: true; value: T } | { ok: false; err: ToolResult<Record<string, unknown>> };
type ScanRow = NonNullable<ReturnType<PluginContext['storage']['scans']['getById']>>;

function resolveTo(
  inp: { project_path?: string; scan_type?: ScanType; to_scan_id?: string; to?: 'latest' },
  ctx: PluginContext,
  skipped: SkippedScan[],
): Resolved<ScanRow> {
  if (inp.to_scan_id) {
    const scan = ctx.storage.scans.getById(inp.to_scan_id);
    if (!scan)
      return { ok: false, err: failDomain('unknown_scan_id', `to scan '${inp.to_scan_id}' not found`) };
    return { ok: true, value: scan };
  }
  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    return { ok: false, err: failDomain('not_a_git_repo', (e as Error).message) };
  }
  // Default: this project's newest usable state scan.
  const latest = latestStateScan(ctx.storage, projectPath, inp.scan_type);
  skipped.push(...latest.skipped);
  if (!latest.scan) {
    return {
      ok: false,
      err: failDomain(
        'unknown_scan_id',
        `No usable completed ${inp.scan_type ?? 'finding-producing'} scan for ${projectPath} yet.` +
          describeSkipped(latest.skipped),
      ),
    };
  }
  return { ok: true, value: latest.scan };
}

function resolveFrom(
  inp: { from_scan_id?: string; from?: 'baseline' | 'previous' },
  toScan: ScanRow,
  ctx: PluginContext,
  skipped: SkippedScan[],
): Resolved<string> {
  if (inp.from_scan_id) {
    const scan = ctx.storage.scans.getById(inp.from_scan_id);
    if (!scan)
      return {
        ok: false,
        err: failDomain('unknown_scan_id', `from scan '${inp.from_scan_id}' not found`),
      };
    return { ok: true, value: inp.from_scan_id };
  }
  const mode = inp.from ?? 'previous';

  if (mode === 'baseline') {
    const baseline = ctx.storage.baselines.getActiveForProject(toScan.project_path, toScan.scan_type);
    if (!baseline)
      return {
        ok: false,
        err: failDomain(
          'unknown_scan_id',
          `No '${toScan.scan_type}' baseline is set for ${toScan.project_path}. ` +
            'Call `set_baseline` on a scan of that type first.',
        ),
      };
    return { ok: true, value: baseline.scan_id };
  }

  // mode === 'previous' — this project's previous usable scan of the same type.
  const previous = latestStateScan(ctx.storage, toScan.project_path, toScan.scan_type, {
    beforeScanId: toScan.scan_id,
  });
  skipped.push(...previous.skipped);
  if (!previous.scan)
    return {
      ok: false,
      err: failDomain(
        'unknown_scan_id',
        `No previous usable '${toScan.scan_type}' scan of ${toScan.project_path} exists before ` +
          `${toScan.scan_id}.${describeSkipped(previous.skipped)}`,
      ),
    };
  return { ok: true, value: previous.scan.scan_id };
}

function describeSkipped(skipped: readonly SkippedScan[]): string {
  if (skipped.length === 0) return '';
  return (
    ` Skipped ${skipped.length} scan(s) whose scanners did not run (coverage none): ` +
    `${skipped.map((s) => s.scan_id).join(', ')}.`
  );
}

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
