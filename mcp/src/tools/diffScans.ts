/**
 * `diff_scans` — compute the new / resolved / unchanged finding sets
 * between two scans.
 *
 * Inputs:
 *   - `to_scan_id` (explicit) or `to: 'latest'` (default).
 *   - `from_scan_id` (explicit), `from: 'baseline'` (active baseline), or
 *     `from: 'previous'` (the scan of the same `scan_type` immediately
 *      before `to`).
 *
 * "Previous of same type" matters: comparing a `deps` scan with a `sast`
 * scan is meaningless because the fingerprints come from different rule
 * families. Restricting the previous lookup to the same scan_type avoids
 * spurious resolves/news.
 */

import { z } from 'zod';
import type { PluginContext } from '../context.js';
import type { DomainError, Finding, ToolResult } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

const FromEnum = z.enum(['baseline', 'previous']);
const ToEnum = z.enum(['latest']);

const inputSchema = {
  from_scan_id: z.string().uuid().optional(),
  from: FromEnum.optional(),
  to_scan_id: z.string().uuid().optional(),
  to: ToEnum.optional(),
};

const tool: ToolModule = {
  name: 'diff_scans',
  title: 'Diff scans (regression / resolution detection)',
  description:
    'Compare findings between two scans (same scan_type). Returns three lists by fingerprint: ' +
    'new (in to but not in from), resolved (in from but not in to), unchanged (in both). ' +
    'Default: from=previous, to=latest.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as {
    from_scan_id?: string;
    from?: 'baseline' | 'previous';
    to_scan_id?: string;
    to?: 'latest';
  };

  // Resolve `to` first because `from='previous'` depends on it.
  const toId = resolveTo(inp, ctx);
  if (!toId.ok) return toId.err;
  const fromId = resolveFrom(inp, toId.value, ctx);
  if (!fromId.ok) return fromId.err;

  if (fromId.value === toId.value) {
    return failDomain(
      'unknown_scan_id',
      `Cannot diff a scan against itself (${toId.value}).`,
    );
  }

  const fromFindings = ctx.storage.findings.listByScan(fromId.value);
  const toFindings = ctx.storage.findings.listByScan(toId.value);

  const fromMap = new Map(fromFindings.map((f) => [f.fingerprint, f]));
  const toMap = new Map(toFindings.map((f) => [f.fingerprint, f]));

  const new_findings: Finding[] = [];
  const resolved_findings: Finding[] = [];
  const unchanged_findings: Finding[] = [];

  for (const f of toFindings) {
    if (fromMap.has(f.fingerprint)) unchanged_findings.push(f);
    else new_findings.push(f);
  }
  for (const f of fromFindings) {
    if (!toMap.has(f.fingerprint)) resolved_findings.push(f);
  }

  return {
    ok: true,
    from_scan_id: fromId.value,
    to_scan_id: toId.value,
    new_findings,
    resolved_findings,
    unchanged_findings,
    summary: {
      new: new_findings.length,
      resolved: resolved_findings.length,
      unchanged: unchanged_findings.length,
    },
  };
}

type Resolved<T> = { ok: true; value: T } | { ok: false; err: ToolResult<Record<string, unknown>> };

function resolveTo(
  inp: { to_scan_id?: string; to?: 'latest' },
  ctx: PluginContext,
): Resolved<string> {
  if (inp.to_scan_id) {
    const scan = ctx.storage.scans.getById(inp.to_scan_id);
    if (!scan)
      return { ok: false, err: failDomain('unknown_scan_id', `to scan '${inp.to_scan_id}' not found`) };
    return { ok: true, value: inp.to_scan_id };
  }
  // Default: latest completed scan.
  const latest = ctx.storage.scans.getLatest();
  if (!latest) return { ok: false, err: failDomain('unknown_scan_id', 'No completed scans yet.') };
  return { ok: true, value: latest.scan_id };
}

function resolveFrom(
  inp: { from_scan_id?: string; from?: 'baseline' | 'previous' },
  toScanId: string,
  ctx: PluginContext,
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
    const baseline = ctx.storage.baselines.getActive();
    if (!baseline)
      return {
        ok: false,
        err: failDomain('unknown_scan_id', 'No baseline is set. Call `set_baseline` first.'),
      };
    return { ok: true, value: baseline.scan_id };
  }

  // mode === 'previous' — previous scan of the same scan_type.
  const toScan = ctx.storage.scans.getById(toScanId);
  if (!toScan)
    return {
      ok: false,
      err: failDomain('unknown_scan_id', `to scan '${toScanId}' not found`),
    };
  const history = ctx.storage.scans.listHistory(200);
  const previous = history.find(
    (s) =>
      s.scan_type === toScan.scan_type &&
      s.status === 'completed' &&
      s.scan_id !== toScanId &&
      s.started_at < toScan.started_at,
  );
  if (!previous)
    return {
      ok: false,
      err: failDomain(
        'unknown_scan_id',
        `No previous '${toScan.scan_type}' scan exists before ${toScanId}.`,
      ),
    };
  return { ok: true, value: previous.scan_id };
}

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
