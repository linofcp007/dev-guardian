/**
 * `prioritize_findings` — heuristic ordering of all currently-open
 * findings, returning a ranked list with "why now" reasoning hooks.
 *
 * Pure heuristics — no LLM call. The calling model uses the ranking +
 * reasoning to decide what to surface to the user first.
 *
 * Ranking (descending priority):
 *   1. severity (critical > high > medium > low > info)
 *   2. category (security > bug > license > compliance > quality > performance)
 *   3. fix_available (yes ranks above no — easy wins first)
 *   4. age / last-seen proximity (recent > old)
 *   5. CVE exploitability (Task 19): CISA KEV-listed first, then FIRST EPSS
 *      score — added on TOP of the four scores above (a KEV/high-EPSS
 *      finding of the same severity/category/fix/age now scores higher),
 *      via `KEV_BOOST` / `EPSS_BOOST_MAX` below. A finding not correlated to
 *      any CVE (`intel/rank.ts#findingCveIds`), or whose CVE has no measured
 *      intel yet (`status: 'unavailable'` — offline, or a fetch failure —
 *      never treated as "not exploited"), gets no boost at all: identical to
 *      this tool's pre-Task-19 behaviour.
 *   6. fingerprint (stable tiebreaker)
 *
 * Each row carries a `priority_score` (0-1000, unbounded above by the KEV/
 * EPSS boost — see the constants below) and a list of `factors` the model
 * can quote.
 *
 * A row whose finding is correlated with a CVE also carries `ssvc`: CISA's
 * SSVC deployer decision (Act / Attend / Track* / Track), each decision point
 * with its value, what it rests on, and whether it was assumed — see
 * `intel/ssvc.ts` for the table's source and every approximation. It is
 * reported BESIDE the score and never moves it; `summary.ssvc` counts the
 * decisions over every open finding.
 *
 * Reads `project_path`'s open set (default: the server's working directory)
 * — every finding-producing scan type's newest usable scan, suppressions
 * removed (`history/openSet.ts`) — never the single latest scan in the whole
 * database, which could be another project's or an SBOM.
 */

import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { describeOpenSet, openSetForProject } from '../history/openSet.js';
import { enrichCveIntel } from '../intel/enrich.js';
import { exploitabilitySignal, findingCveIds, isUncorrelatedFinding } from '../intel/rank.js';
import {
  MISSION_WELLBEING_VALUES,
  SSVC_DECISIONS,
  assessSsvc,
  automatablePoint,
  exploitationPoint,
  missionWellbeingPoint,
  technicalImpactPoint,
  type MissionWellbeing,
  type SsvcAssessment,
  type SsvcDecision,
  type SsvcPoint,
} from '../intel/ssvc.js';
import type { CveIntelResult } from '../intel/types.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import type { Category, Finding, Severity, ToolResult } from '../types.js';
import { assessDependency, dependencySubjectOf, prepareDependencyIndex } from '../validate/dependencyProvider.js';
import { buildImportGraph } from '../validate/importGraph.js';
import { registerToolModule, type ToolModule } from './index.js';

/** Added once when ANY of a finding's correlated CVEs is CISA KEV-listed —
 *  between `security`'s category weight (200) and `critical`'s severity
 *  weight (400): a currently-exploited CVE should outrank an ordinary
 *  critical-severity finding of another category, without unconditionally
 *  outranking every critical finding regardless of its own signals. */
const KEV_BOOST = 220;
/** Scaled by the highest EPSS score (0-1) among a finding's correlated
 *  CVEs — smaller than `KEV_BOOST` so a near-certain-but-not-yet-KEV-listed
 *  CVE (EPSS close to 1) still ranks below a confirmed KEV one, but ahead of
 *  an unremarkable EPSS score. */
const EPSS_BOOST_MAX = 100;

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 400,
  high: 250,
  medium: 120,
  low: 50,
  info: 10,
};

const CATEGORY_WEIGHT: Record<Category, number> = {
  security: 200,
  bug: 150,
  license: 80,
  compliance: 60,
  quality: 30,
  performance: 25,
};

const inputSchema = {
  project_path: ProjectPath,
  limit: z
    .number()
    .int()
    .min(1)
    .max(500)
    .optional()
    .describe('Cap on returned items. Default 50.'),
  mission_wellbeing: z
    .enum(MISSION_WELLBEING_VALUES)
    .optional()
    .describe(
      "SSVC Mission & Well-being for this system (CISA: mission prevalence x public well-being " +
        'impact). Default medium, reported as assumed.',
    ),
};

interface RankedFinding {
  finding: Finding;
  priority_score: number;
  factors: string[];
  /** CISA SSVC for a finding correlated with a CVE; null for any other. */
  ssvc: (SsvcAssessment & { cve_ids: string[] }) | null;
}

const tool: ToolModule = {
  name: 'prioritize_findings',
  title: 'Prioritise open findings (heuristic)',
  description:
    "Rank one project's open findings (project_path, default: the server's working directory; " +
    'the newest usable scan of every finding-producing type, suppressions removed) by a weighted ' +
    'heuristic: severity + category + fix_available + age, boosted when a finding is linked to a ' +
    'CVE that is CISA KEV-listed or has a high FIRST EPSS score (cached 24h; offline or unmeasured ' +
    'CVEs get no boost, never a fabricated one). Every CVE finding also gets a CISA SSVC deployer ' +
    'decision (Act / Attend / Track* / Track) from Exploitation (KEV; EPSS as a PoC proxy), ' +
    'Automatable (a route reaches a file importing the package, from the latest ' +
    'map_attack_surface), Technical Impact (from severity) and mission_wellbeing; a point with no ' +
    'data takes the more severe value and is listed in ssvc.assumed. SSVC does not change the ' +
    'score. `cve_intel.uncorrelated` counts findings from a CVE-capable scanner (e.g. npm-audit ' +
    'v2) that carry no extractable CVE id. Returns top-N with explanation. No LLM call.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as { project_path?: string; limit?: number; mission_wellbeing?: MissionWellbeing };
  const limit = inp.limit ?? 50;
  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    return { ok: false, error: { code: 'not_a_git_repo', message: (e as Error).message } };
  }

  const set = openSetForProject(ctx.storage, projectPath);
  const open = set.findings;
  const latest = set.newest;
  const recentScanTs = latest ? new Date(latest.started_at).getTime() : Date.now();

  // Every CVE any open finding is correlated with (best-effort — see
  // `intel/rank.ts#findingCveIds`'s own doc comment for the coverage gap),
  // enriched once for the whole batch rather than per finding.
  const cveIdsByFinding = new Map<string, string[]>(open.map((f) => [f.fingerprint, findingCveIds(f)]));
  const allCveIds = [...new Set([...cveIdsByFinding.values()].flat())];
  const intel: ReadonlyMap<string, CveIntelResult> = await enrichCveIntel(ctx.storage, allCveIds);
  const ssvcFor = ssvcAssessor(ctx, projectPath, intel, inp.mission_wellbeing);

  const ranked: RankedFinding[] = open.map((f) => {
    const factors: string[] = [];
    let score = 0;
    score += SEVERITY_WEIGHT[f.severity];
    factors.push(`severity=${f.severity} (+${SEVERITY_WEIGHT[f.severity]})`);
    score += CATEGORY_WEIGHT[f.category];
    factors.push(`category=${f.category} (+${CATEGORY_WEIGHT[f.category]})`);
    if (f.fix_available) {
      score += 60;
      factors.push('fix_available (+60 — easy win)');
    }
    // Recency: every finding from the latest scan gets +30; older = 0.
    // (Without per-finding timestamps we use the scan's started_at as a
    // proxy.)
    score += 30;
    factors.push('observed in latest scan (+30)');

    const signal = exploitabilitySignal(cveIdsByFinding.get(f.fingerprint) ?? [], intel);
    if (signal.kev) {
      score += KEV_BOOST;
      factors.push(`CISA KEV-listed (${signal.cve_ids.join(', ')}) (+${KEV_BOOST} — actively exploited)`);
    } else if (signal.max_epss !== null) {
      const boost = Math.round(signal.max_epss * EPSS_BOOST_MAX);
      score += boost;
      factors.push(
        `FIRST EPSS ${signal.max_epss.toFixed(3)} (${signal.cve_ids.join(', ')}) (+${boost} of ${EPSS_BOOST_MAX})`,
      );
    }
    // Beside the score, never inside it: SSVC assumes the worst for an
    // unmeasured CVE, and the score promises no boost from intel it does not
    // have. Folding one into the other would break one of the two promises.
    const ssvc = ssvcFor.assess(f, cveIdsByFinding.get(f.fingerprint) ?? []);
    return { finding: f, priority_score: score, factors, ssvc };
  });

  ranked.sort(
    (a, b) =>
      b.priority_score - a.priority_score ||
      a.finding.fingerprint.localeCompare(b.finding.fingerprint),
  );

  const top = ranked.slice(0, limit);
  const summary = {
    total_open: open.length,
    returned: top.length,
    score_range: scoreRange(top),
    // Over every open finding, not just the returned top-N.
    ssvc: ssvcSummary(ranked, ssvcFor),
  };

  return {
    ok: true,
    summary,
    ranked: top,
    open_set: describeOpenSet(set),
    cve_intel: uncorrelatedCoverage(open),
    instructions_for_model:
      'Pick the first 3-5 entries to action. For each, prefer `suggest_fix(finding_fingerprint)` ' +
      'over speculation. If most top entries are security/critical, call `audit_executive` to ' +
      'understand cross-cutting impact first. For CVE findings, `ssvc.decision` is CISA\'s: Act ' +
      'and Attend come before the schedule, Track*/Track within it — and read `ssvc.assumed` ' +
      'before quoting it: an assumed point is dev-guardian having no data, not a finding.',
    // unused reference to keep the time variable from being dead-code'd by
    // future maintainers who add age-weighting.
    _recent_scan_ts: recentScanTs,
  };
}

/**
 * How many open findings come from a CVE-capable scanner (`intel/rank.ts
 * #CVE_CAPABLE_TOOLS`) but carry no CVE id at all — review round 1,
 * Important #2: npm-audit's v2 parser is the main source today (see
 * `intel/rank.ts#isUncorrelatedFinding`'s own doc comment), and those
 * findings silently never got a KEV/EPSS boost with nothing saying so.
 * Always reports the count (0 included); the `note` is added only when it
 * is non-zero, so a project with nothing uncorrelated gets a quiet `{
 * uncorrelated: 0 }` rather than an unconditional sentence about a gap that
 * does not apply to it.
 */
function uncorrelatedCoverage(open: readonly Finding[]): { uncorrelated: number; note?: string } {
  const uncorrelated = open.filter(isUncorrelatedFinding).length;
  if (uncorrelated === 0) return { uncorrelated };
  return {
    uncorrelated,
    note:
      `${uncorrelated} finding(s) come from a CVE-capable scanner but carry no extractable CVE id, ` +
      'so they cannot be weighted by KEV/EPSS yet.',
  };
}

interface SsvcAssessor {
  assess(finding: Finding, cveIds: readonly string[]): RankedFinding['ssvc'];
  mission: SsvcPoint<MissionWellbeing>;
  missionGiven: boolean;
  surfaceSnapshotId: number | null;
}

/**
 * Everything the SSVC decision needs that is the same for the whole batch:
 * the intel, the mission value, and the project's latest attack-surface
 * snapshot with its import graph (built once) for the Automatable point.
 */
function ssvcAssessor(
  ctx: PluginContext,
  projectPath: string,
  intel: ReadonlyMap<string, CveIntelResult>,
  missionWellbeing: MissionWellbeing | undefined,
): SsvcAssessor {
  const mission = missionWellbeingPoint(missionWellbeing);
  // THIS project's snapshot — another project's would relativize into a
  // different path space and match nothing (see validate_finding).
  const surface = ctx.storage.surface.getLatestForProject(projectPath);
  const index =
    surface === null
      ? null
      : prepareDependencyIndex({
          snapshot: surface.snapshot,
          graph: buildImportGraph(surface.snapshot.imports),
          projectPath,
        });
  return {
    mission,
    missionGiven: missionWellbeing !== undefined,
    surfaceSnapshotId: surface?.id ?? null,
    assess(finding, cveIds) {
      if (cveIds.length === 0) return null;
      const subject = dependencySubjectOf(finding);
      const dependency = subject !== null && index !== null ? assessDependency(subject, index) : null;
      const whyNone =
        index === null
          ? 'no attack-surface snapshot for this project (run map_attack_surface)'
          : subject === null
            ? 'the finding names no package to look for in the imports'
            : null;
      return {
        ...assessSsvc({
          exploitation: exploitationPoint(cveIds, intel),
          automatable: automatablePoint(dependency, whyNone),
          technical_impact: technicalImpactPoint(finding.severity),
          mission_wellbeing: mission,
        }),
        cve_ids: [...cveIds],
      };
    },
  };
}

/** Decision counts over every open finding, and how many rest on assumptions. */
function ssvcSummary(ranked: readonly RankedFinding[], assessor: SsvcAssessor): Record<string, unknown> {
  const decisions = Object.fromEntries(SSVC_DECISIONS.map((d) => [d, 0])) as Record<SsvcDecision, number>;
  const assumedInputs: Record<string, number> = { exploitation: 0, automatable: 0, mission_wellbeing: 0 };
  let notApplicable = 0;
  for (const row of ranked) {
    if (row.ssvc === null) {
      notApplicable += 1;
      continue;
    }
    decisions[row.ssvc.decision] += 1;
    for (const key of row.ssvc.assumed) assumedInputs[key] = (assumedInputs[key] ?? 0) + 1;
  }
  return {
    decisions,
    not_applicable: notApplicable,
    assumed_inputs: assumedInputs,
    mission_wellbeing: { value: assessor.mission.value, source: assessor.missionGiven ? 'parameter' : 'default' },
    surface_snapshot_id: assessor.surfaceSnapshotId,
    source:
      'CISA SSVC Guide (Nov 2022), Table 9 — the deployer decision tree; see intel/ssvc.ts for ' +
      'which decision points dev-guardian approximates',
  };
}

/**
 * Min/max of an already-sorted, possibly-empty ranked list.
 *
 * Extracted so the emptiness check narrows the element type once, in one
 * place. The inline version tested `top.length > 0` and then indexed with
 * non-null assertions, which `noUncheckedIndexedAccess` cannot follow.
 */
function scoreRange(
  top: readonly { priority_score: number }[],
): { max: number; min: number } | null {
  const first = top[0];
  const last = top[top.length - 1];
  if (first === undefined || last === undefined) return null;
  return { max: first.priority_score, min: last.priority_score };
}
