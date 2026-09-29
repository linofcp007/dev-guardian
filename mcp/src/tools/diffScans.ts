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
 * (`fingerprint/findingIdentity.ts#indexFindings`). The project's active
 * suppressions apply first, as in the open set: suppressed findings are
 * listed apart (`suppressed_findings`), never as new, resolved or unchanged.
 *
 * Explicit ids are held to one project and one type: a `to_scan_id` of
 * another project than `project_path` (when given), a `from_scan_id` of
 * another project or scan type than the `to` scan, or a scan that has not
 * completed (a running one has not stored all its findings) is refused, with
 * the reason. They were taken as given.
 *
 * Response size: `summary` carries the true counts; each list carries at
 * most {@link ITEMS_PER_BUCKET} findings and `truncated` says which were cut.
 */

import { z } from 'zod';
import type { PluginContext } from '../context.js';
import {
  latestStateScan,
  partitionSuppressed,
  type SkipHit,
  summarizeSkipped,
  type SkippedSummary,
  suppressedOfEither,
} from '../history/openSet.js';
import { classifyDiff, compareScansFor, describeMeasurementGaps, measurementGaps } from '../history/runCompare.js';
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
    'not in from), resolved (in from but not in to), unchanged (in both) and not_remeasured (in ' +
    'from, of a type to did not measure — e.g. a failed child of a security_scan_full run; never ' +
    'counted as resolved): true counts in `summary`, at most 50 findings per list, `truncated` ' +
    'naming the lists that were cut. Findings are matched by their line-independent identity, so ' +
    'code moving above a finding does not make it new; scans from before identities existed match ' +
    "by fingerprint. Default: from=previous, to=latest — the newest usable scan of project_path " +
    "(default: the server's working directory), never an SBOM/stack/diff-review run or one whose " +
    'scanners did not run; skipped scans are counted in `skipped`. from=baseline uses the ' +
    "project's baseline of the same scan type.",
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

  const skipHits: SkipHit[] = [];

  // Resolve `to` first because `from='previous'` depends on it.
  const toScan = resolveTo(inp, ctx, skipHits);
  if (!toScan.ok) return toScan.err;
  const fromId = resolveFrom(inp, toScan.value, ctx, skipHits);
  if (!fromId.ok) return fromId.err;

  if (fromId.value === toScan.value.scan_id) {
    return failDomain(
      'unknown_scan_id',
      `Cannot diff a scan against itself (${toScan.value.scan_id}).`,
    );
  }

  const fromScan = ctx.storage.scans.getById(fromId.value);
  if (!fromScan) return failDomain('unknown_scan_id', `from scan '${fromId.value}' not found`);
  // The project's active suppressions apply first, as in the open set: a
  // suppressed finding is listed apart, never new, resolved or unchanged.
  const fromSplit = partitionSuppressed(ctx.storage, toScan.value.project_path, ctx.storage.findings.listByScan(fromId.value));
  const toSplit = partitionSuppressed(
    ctx.storage,
    toScan.value.project_path,
    ctx.storage.findings.listByScan(toScan.value.scan_id),
  );
  const suppressed = suppressedOfEither(toSplit.suppressed, fromSplit.suppressed);

  // Per scanner (`history/runCompare.ts`): a `from` finding whose scanner `to`
  // did not measure is not resolved, and a `to` finding whose scanner `from`
  // named and did not run ok is not new. A scanner `from` did not run at all
  // (not applicable, or not requested, then) leaves its findings new.
  const check = compareScansFor(ctx.storage, fromScan, toScan.value);
  const d = classifyDiff(check, fromSplit.visible, toSplit.visible);
  const gaps = measurementGaps(check, d);
  const note = describeMeasurementGaps(fromScan, toScan.value, gaps);
  const cap = (list: readonly Finding[]): Finding[] => list.slice(0, ITEMS_PER_BUCKET);
  const cut = (list: readonly Finding[]): boolean => list.length > ITEMS_PER_BUCKET;

  return {
    ok: true,
    project_path: toScan.value.project_path,
    scan_type: toScan.value.scan_type,
    from_scan_id: fromId.value,
    to_scan_id: toScan.value.scan_id,
    summary: {
      new: d.new.length,
      resolved: d.resolved.length,
      unchanged: d.unchanged.length,
      not_remeasured: d.notRemeasured.length,
      not_previously_measured: d.notPreviouslyMeasured.length,
      suppressed: suppressed.length,
    },
    new_findings: cap(d.new),
    resolved_findings: cap(d.resolved),
    unchanged_findings: cap(d.unchanged),
    not_remeasured_findings: cap(d.notRemeasured),
    not_previously_measured_findings: cap(d.notPreviouslyMeasured),
    suppressed_findings: cap(suppressed),
    truncated: {
      new: cut(d.new),
      resolved: cut(d.resolved),
      unchanged: cut(d.unchanged),
      not_remeasured: cut(d.notRemeasured),
      not_previously_measured: cut(d.notPreviouslyMeasured),
      suppressed: cut(suppressed),
    },
    ...(gaps.byTo.length > 0 ? { not_measured: gaps.byTo } : {}),
    ...(gaps.byFrom.length > 0 ? { reference_not_measured: gaps.byFrom } : {}),
    ...(note !== null ? { note } : {}),
    ...(skipHits.length > 0 ? { skipped: summarizeSkipped(skipHits) } : {}),
  };
}

type Resolved<T> = { ok: true; value: T } | { ok: false; err: ToolResult<Record<string, unknown>> };
type ScanRow = NonNullable<ReturnType<PluginContext['storage']['scans']['getById']>>;

function resolveTo(
  inp: { project_path?: string; scan_type?: ScanType; to_scan_id?: string; to?: 'latest' },
  ctx: PluginContext,
  skipHits: SkipHit[],
): Resolved<ScanRow> {
  if (inp.to_scan_id) {
    const scan = ctx.storage.scans.getById(inp.to_scan_id);
    if (!scan)
      return { ok: false, err: failDomain('unknown_scan_id', `to scan '${inp.to_scan_id}' not found`) };
    // Without project_path the project is the scan's own (documented); with
    // it, the scan must belong to it — every history reader answers for one
    // project.
    if (inp.project_path !== undefined) {
      let projectPath: string;
      try {
        projectPath = resolveProjectPath(inp.project_path).path;
      } catch (e) {
        return { ok: false, err: failDomain('not_a_git_repo', (e as Error).message) };
      }
      if (scan.project_path !== projectPath) {
        return {
          ok: false,
          err: failDomain(
            'unknown_scan_id',
            `to scan '${scan.scan_id}' is a scan of ${scan.project_path}, not of ${projectPath}; ` +
              'a diff compares scans of one project.',
          ),
        };
      }
    }
    const incomplete = incompleteReason(scan, 'to');
    if (incomplete !== null) return { ok: false, err: failDomain('unknown_scan_id', incomplete) };
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
  skipHits.push(...latest.hits);
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
  skipHits: SkipHit[],
): Resolved<string> {
  if (inp.from_scan_id) {
    const scan = ctx.storage.scans.getById(inp.from_scan_id);
    if (!scan)
      return {
        ok: false,
        err: failDomain('unknown_scan_id', `from scan '${inp.from_scan_id}' not found`),
      };
    const refusal =
      scan.project_path !== toScan.project_path
        ? `from scan '${scan.scan_id}' belongs to another project (${scan.project_path}) than to scan ` +
          `'${toScan.scan_id}' (${toScan.project_path}); a diff compares scans of one project.`
        : scan.scan_type !== toScan.scan_type
          ? `from scan '${scan.scan_id}' is a '${scan.scan_type}' scan and to scan '${toScan.scan_id}' is ` +
            `'${toScan.scan_type}': findings of different scan types come from different rule families, ` +
            'so a diff compares scans of one type.'
          : incompleteReason(scan, 'from');
    if (refusal !== null) return { ok: false, err: failDomain('unknown_scan_id', refusal) };
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
  skipHits.push(...previous.hits);
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

/**
 * Why an explicitly named scan cannot be diffed, or null. A scan still
 * running has not stored all its findings (they are inserted in chunks while
 * the row is `running`); a failed or cancelled one measured only part of
 * what it names.
 */
function incompleteReason(scan: ScanRow, side: 'from' | 'to'): string | null {
  if (scan.status === 'completed') return null;
  if (scan.status === 'running') {
    return `${side} scan '${scan.scan_id}' is still running: its findings are not all stored yet.`;
  }
  return `${side} scan '${scan.scan_id}' did not complete (status ${scan.status}); a diff compares completed scans.`;
}

function describeSkipped(skipped: SkippedSummary): string {
  if (skipped.count === 0) return '';
  const named = skipped.newest.map((s) => s.scan_id).join(', ');
  const more = skipped.count > skipped.newest.length ? `, and ${skipped.count - skipped.newest.length} older` : '';
  return ` Skipped ${skipped.count} scan(s) whose scanners did not run (coverage none): ${named}${more}.`;
}

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
