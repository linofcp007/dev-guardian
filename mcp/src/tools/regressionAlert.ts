/**
 * `regression_alert` — compute a severity-weighted regression score
 * between the active baseline (or last completed scan) and the latest
 * scan of the same type, and flag whether action is warranted.
 *
 * Pure SQL — no scanners. Output:
 *   { regressed: boolean, score_delta, baseline_scan_id, current_scan_id,
 *     new_findings_by_severity, hint }
 *
 * The model decides what to do with `regressed: true` — open an issue,
 * call audit_executive, etc. We do not auto-trigger anything.
 */

import { z } from 'zod';
import type { PluginContext } from '../context.js';
import type { Finding, Severity, ToolResult } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

const SEVERITY_WEIGHT: Record<Severity, number> = {
  info: 0.5,
  low: 1,
  medium: 2,
  high: 5,
  critical: 10,
};

const inputSchema = {
  threshold: z
    .number()
    .min(0)
    .max(1000)
    .optional()
    .describe(
      'Score-delta threshold above which `regressed=true`. Default 5. ' +
        'A single new critical alone surpasses this; 5 new lows do not.',
    ),
};

const tool: ToolModule = {
  name: 'regression_alert',
  title: 'Regression alert',
  description:
    'Compare the active baseline (or previous completed scan) against the latest scan and flag ' +
    'when the severity-weighted change exceeds a threshold. Returns enough context for the model ' +
    'to recommend follow-up actions.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as { threshold?: number };
  const threshold = inp.threshold ?? 5;

  const latest = ctx.storage.scans.getLatest();
  if (!latest) {
    return {
      ok: true,
      regressed: false,
      score_delta: 0,
      baseline_scan_id: null,
      current_scan_id: null,
      hint: 'No scans recorded yet.',
    };
  }

  // Reference: explicit baseline, else previous scan of same type.
  const baseline = ctx.storage.baselines.getActive();
  let baselineId: string | null = baseline?.scan_id ?? null;
  if (!baselineId) {
    const history = ctx.storage.scans.listHistory(50);
    const prev = history.find(
      (s) => s.scan_type === latest.scan_type && s.scan_id !== latest.scan_id && s.status === 'completed',
    );
    baselineId = prev?.scan_id ?? null;
  }
  if (!baselineId) {
    return {
      ok: true,
      regressed: false,
      score_delta: 0,
      baseline_scan_id: null,
      current_scan_id: latest.scan_id,
      hint: 'No baseline / previous scan to compare against.',
    };
  }

  const prevFindings = ctx.storage.findings.listByScan(baselineId);
  const curFindings = ctx.storage.findings.listByScan(latest.scan_id);
  const prevFp = new Set(prevFindings.map((f) => f.fingerprint));
  const curFp = new Set(curFindings.map((f) => f.fingerprint));

  const newFindings = curFindings.filter((f) => !prevFp.has(f.fingerprint));
  const resolvedFindings = prevFindings.filter((f) => !curFp.has(f.fingerprint));
  const score = weightedScore(newFindings) - weightedScore(resolvedFindings);
  const regressed = score > threshold;

  return {
    ok: true,
    regressed,
    score_delta: Math.round(score * 10) / 10,
    threshold,
    baseline_scan_id: baselineId,
    current_scan_id: latest.scan_id,
    new_findings_by_severity: countBySeverity(newFindings),
    resolved_findings_by_severity: countBySeverity(resolvedFindings),
    hint: regressed
      ? 'Severity-weighted change exceeded the threshold. Consider triage_findings + audit_executive, or revert recent changes.'
      : 'No significant regression.',
  };
}

function weightedScore(findings: Finding[]): number {
  return findings.reduce((acc, f) => acc + (SEVERITY_WEIGHT[f.severity] ?? 0), 0);
}

function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const out: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const f of findings) out[f.severity] += 1;
  return out;
}

