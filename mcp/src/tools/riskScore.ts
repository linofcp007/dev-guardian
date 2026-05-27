/**
 * `risk_score` — single 0–100 number summarising the project's current risk
 * posture, plus a breakdown.
 *
 * Components (weighted sum, capped at 100):
 *   - 40 pts: severity-weighted finding count (critical=10, high=5, medium=2, low=1).
 *   - 30 pts: CVE count weighted by severity.
 *   - 15 pts: missing CI bots (renovate/dependabot) and policy docs.
 *   - 15 pts: stale baseline (more than 30 days old).
 *
 * Output is a JSON `{ score, band, components, recommended_next_action }`.
 * Read-only — does not spawn scanners.
 */

import type { PluginContext } from '../context.js';
import type { ToolResult } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

const tool: ToolModule = {
  name: 'risk_score',
  title: 'Risk score (0-100)',
  description:
    'Compute a single 0-100 risk score from the project\'s persisted scans/findings/CVEs/baseline. ' +
    'Returns the score, a band (low/medium/high/critical), per-component breakdown, and the next ' +
    'action the model should recommend. Pure read.',
  inputSchema: {},
  handler: async (_input, ctx) => handler(ctx),
};

registerToolModule(tool);

async function handler(ctx: PluginContext): Promise<ToolResult<Record<string, unknown>>> {
  const open = ctx.storage.findings.listOpen();
  const findingsScore = clamp(
    open.reduce((acc, f) => {
      switch (f.severity) {
        case 'critical': return acc + 10;
        case 'high':     return acc + 5;
        case 'medium':   return acc + 2;
        case 'low':      return acc + 1;
        default:         return acc;
      }
    }, 0),
    0,
    40,
  );

  // CVEs — use the latest deps-flavoured scan as the source.
  let cveScore = 0;
  let cveCount = 0;
  const latestDeps = findLatestOfType(ctx, ['deps', 'security_full']);
  if (latestDeps) {
    const cves = ctx.storage.cves.listActive(latestDeps.scan_id);
    cveCount = cves.length;
    cveScore = clamp(
      cves.reduce((acc, c) => {
        switch (c.severity) {
          case 'critical': return acc + 8;
          case 'high':     return acc + 4;
          case 'medium':   return acc + 1.5;
          default:         return acc + 0.5;
        }
      }, 0),
      0,
      30,
    );
  }

  // Compliance signals — penalise missing bots and policy docs.
  let complianceScore = 0;
  const latestCompliance = findLatestOfType(ctx, ['compliance']);
  let policiesMissing = 0;
  if (latestCompliance?.meta) {
    const m = latestCompliance.meta as {
      policy_documents_found?: Record<string, boolean | string[]>;
    };
    const docs = m.policy_documents_found ?? {};
    for (const key of ['privacy_policy', 'terms_of_service', 'security_policy']) {
      if (docs[key] === false) policiesMissing += 1;
    }
    complianceScore += policiesMissing * 3; // up to 9
  }
  const latestDepsAudit = findLatestOfType(ctx, ['deps']);
  if (latestDepsAudit?.meta) {
    const m = latestDepsAudit.meta as { bot_configured?: { renovate?: boolean; dependabot?: boolean } };
    const bot = m.bot_configured ?? {};
    if (!bot.renovate && !bot.dependabot) complianceScore += 6;
  }
  complianceScore = clamp(complianceScore, 0, 15);

  // Baseline freshness.
  let baselineScore = 0;
  const baseline = ctx.storage.baselines.getActive();
  if (!baseline) {
    baselineScore = 8; // never set a baseline → moderate penalty
  } else {
    const ageMs = Date.now() - new Date(baseline.set_at).getTime();
    const days = ageMs / (24 * 60 * 60 * 1000);
    if (days > 90) baselineScore = 15;
    else if (days > 30) baselineScore = 8;
  }

  const score = clamp(findingsScore + cveScore + complianceScore + baselineScore, 0, 100);
  const band = bandFor(score);

  return {
    ok: true,
    score: Math.round(score),
    band,
    components: {
      findings: { score: Math.round(findingsScore), open_findings: open.length },
      cves: { score: Math.round(cveScore), active_cves: cveCount },
      compliance: { score: Math.round(complianceScore), policies_missing: policiesMissing },
      baseline: { score: Math.round(baselineScore), has_active_baseline: baseline !== null },
    },
    recommended_next_action: recommendation(score, open.length, cveCount, baseline !== null),
  };
}

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

function bandFor(score: number): 'low' | 'medium' | 'high' | 'critical' {
  if (score >= 70) return 'critical';
  if (score >= 40) return 'high';
  if (score >= 15) return 'medium';
  return 'low';
}

function recommendation(score: number, open: number, cves: number, hasBaseline: boolean): string {
  if (score >= 70) return 'Run audit_executive and triage critical findings before any new deploy.';
  if (cves > 0) return 'Address active CVEs via deps_update_plan with prefer=security.';
  if (!hasBaseline) return 'Set a baseline with set_baseline so diff_scans can track regressions.';
  if (open > 50) return 'Run triage_findings to identify likely false positives, then suppress.';
  return 'Posture is stable. Consider a periodic audit_executive to confirm.';
}

function findLatestOfType(
  ctx: PluginContext,
  types: string[],
): ReturnType<typeof ctx.storage.scans.getById> {
  const history = ctx.storage.scans.listHistory(50);
  const found = history.find((s) => s.status === 'completed' && types.includes(s.scan_type));
  return found ? ctx.storage.scans.getById(found.scan_id) : null;
}

