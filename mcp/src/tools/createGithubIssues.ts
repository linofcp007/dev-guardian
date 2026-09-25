/**
 * `create_github_issues` — create GitHub issues for top-N findings via
 * the local `gh` CLI.
 *
 * Uses the developer's existing `gh` auth (`gh auth status`) — no API
 * keys handled by the server, no GitHub Actions involved, no cloud
 * spend. Idempotent: each issue's title carries the fingerprint, so
 * re-runs won't dupe (we skip if `gh issue list --search` returns a
 * match).
 *
 * dry_run lists what would be created without making API calls.
 *
 * **Whose findings.** `project_path`'s open set (`history/openSet.ts`):
 * every finding-producing scan type's newest usable scan of THIS project,
 * suppressions removed. It used to read the single latest scan in the whole
 * database, so it filed project B's findings on project A's repository
 * whenever B had scanned more recently — and filed suppressed findings too.
 *
 * **Dedupe against every issue, open or closed.** `gh issue list` returns
 * open issues unless told `--state all`, so a finding whose issue had been
 * closed was filed again on every run. The existing titles are listed once
 * per run, and a run that cannot list them files nothing rather than risk
 * duplicates.
 *
 * **Labels.** `gh issue create --label x` fails outright when label `x`
 * does not exist, and the default labels exist in almost no repository — so
 * the default call failed every plan. Missing labels are created; one that
 * cannot be created is left off (`labels_omitted`), never allowed to fail
 * the issue.
 *
 * **A run where every plan failed is `ok: false`**, with the first error.
 *
 * **Two filters, neither of them silent any more (`filtered` /
 * `filtered_reason`).** `severity_min` defaults to `high` and `max_issues`
 * to 10, and the result used to report only the survivors — so a project
 * whose findings are all `medium` produced `candidates: 0`, exactly what a
 * project with nothing to file produces. Same defect, and the same fix, as
 * `create_fix_pr`'s: every finding in the scan is accounted for, and the
 * suggested floor names how many it would actually recover rather than
 * leaving the caller to assume it recovers all of them. Neither default is
 * changed; both are now stated in the schema, which they were not.
 */

import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { openSetForProject } from '../history/openSet.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { runProcess } from '../runners/processRunner.js';
import { ProjectPath } from '../schemas.js';
import { scannerAvailable } from './scanHelpers.js';
import {
  describeShortfallTiers,
  lowestExcludedSeverity,
  severityShortfall,
  type SeverityShortfall,
} from '../severity/breakdown.js';
import type { DomainError, Finding, Severity, ToolResult } from '../types.js';
import { SEVERITY_ORDER } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

const inputSchema = {
  project_path: ProjectPath,
  severity_min: z
    .enum(['info', 'low', 'medium', 'high', 'critical'])
    .optional()
    .describe(
      'Minimum severity a finding must have to be filed. Default: high — what this drops is ' +
        'reported in `filtered`, never silently.',
    ),
  max_issues: z
    .number()
    .int()
    .min(1)
    .max(50)
    .optional()
    .describe(
      'Cap on issues filed in one run, highest severity first. Default: 10 — findings beyond ' +
        'the cap are counted in `filtered`, never silently dropped.',
    ),
  labels: z.array(z.string()).optional(),
  dry_run: z.boolean().optional(),
};

const tool: ToolModule = {
  name: 'create_github_issues',
  title: 'Create GitHub issues for top findings',
  description:
    'Use the local `gh` CLI to open one issue per top open finding of project_path (default: the ' +
    "server's working directory; suppressed findings are never filed). Uses the developer's " +
    'existing GitHub auth, no API keys handled here, no GitHub Actions involved. Title encodes the ' +
    'finding fingerprint; a finding with an issue in ANY state (open or closed) is skipped. ' +
    'Missing labels are created, or left off when they cannot be (`labels_omitted`). Pass ' +
    'dry_run=true to preview. severity_min defaults to high and max_issues to 10; every finding ' +
    'those two dropped is counted in `filtered` and summarised in `filtered_reason`. ok:false ' +
    'when every issue failed to file.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

interface IssuePlan {
  fingerprint: string;
  title: string;
  body: string;
  severity: string;
  status: 'would_create' | 'created' | 'skipped_existing' | 'failed';
  url?: string;
  error?: string;
}

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as {
    project_path?: string;
    severity_min?: Severity;
    max_issues?: number;
    labels?: string[];
    dry_run?: boolean;
  };
  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    return failDomain('not_a_git_repo', (e as Error).message);
  }

  const ghBin = await scannerAvailable('gh');
  if (!ghBin) {
    return failDomain(
      'missing_scanner',
      'GitHub CLI (`gh`) is not installed. See https://cli.github.com/. ' +
        'No API keys are handled here — gh uses your local auth.',
    );
  }
  const dryRun = inp.dry_run === true;
  const sevMin = inp.severity_min ?? 'high';
  const max = inp.max_issues ?? 10;
  const labels = inp.labels ?? ['dev-guardian', 'security'];

  const open = openSetForProject(ctx.storage, projectPath);
  if (open.sources.length === 0) {
    return failDomain(
      'unknown_scan_id',
      `No usable completed scan of ${projectPath} yet — nothing to file as issues.` +
        (open.skipped.length > 0
          ? ` ${open.skipped.length} scan(s) were skipped because their scanners did not run (coverage none).`
          : ''),
    );
  }
  const all = open.findings;
  const sevFloor = SEVERITY_ORDER[sevMin];
  const aboveFloor = all
    .filter((f) => SEVERITY_ORDER[f.severity] >= sevFloor)
    .sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);
  const top = aboveFloor.slice(0, max);
  // Computed here, from the same three arrays the slicing above used, so
  // the account cannot drift from what was actually filed.
  const belowFloor = severityShortfall(all, sevMin);
  const overMax = aboveFloor.length - top.length;

  // Listed once per run, before anything is created. Never inferred from a
  // failed listing: that would file every finding again.
  const existing = !dryRun && top.length > 0 ? await listExistingTags(projectPath) : null;
  // Resolved on the first issue actually filed, so a run where everything
  // already has an issue creates no labels either.
  let labelPlan: { applied: string[]; omitted: string[] } | null = null;

  const plans: IssuePlan[] = [];
  for (const f of top) {
    const title = buildTitle(f);
    const body = buildBody(f, f.scan_id);
    const plan: IssuePlan = {
      fingerprint: f.fingerprint,
      title,
      body,
      severity: f.severity,
      status: 'would_create',
    };
    if (existing !== null) {
      if (!existing.ok) {
        plan.status = 'failed';
        plan.error = `could not list existing issues to avoid duplicates: ${existing.error}`;
      } else if (existing.tags.has(tagOf(f))) {
        plan.status = 'skipped_existing';
      } else {
        labelPlan ??= await ensureLabels(projectPath, labels);
        const created = await createIssue(projectPath, title, body, labelPlan.applied);
        if (created.ok) {
          plan.status = 'created';
          plan.url = created.url;
        } else {
          plan.status = 'failed';
          plan.error = created.error;
        }
      }
    }
    plans.push(plan);
  }

  const failedPlans = plans.filter((p) => p.status === 'failed');
  if (plans.length > 0 && failedPlans.length === plans.length) {
    return failDomain(
      'scanner_failed',
      `All ${plans.length} issue(s) failed to file. First error: ${failedPlans[0]?.error ?? 'unknown'}`,
    );
  }

  const filtered = {
    considered: all.length,
    candidates: plans.length,
    excluded: all.length - plans.length,
    by_reason: { below_severity_min: belowFloor.total, over_max_issues: overMax },
    below_severity_min: belowFloor,
  };

  return {
    ok: true,
    applied: !dryRun,
    severity_min: sevMin,
    max_issues: max,
    candidates: plans.length,
    filtered,
    filtered_reason: describeFiltered(filtered, sevMin, max),
    ...(labelPlan === null
      ? { labels_requested: labels }
      : { labels_applied: labelPlan.applied, labels_omitted: labelPlan.omitted }),
    project_path: projectPath,
    // Newer scans passed over because their scanners did not run: the
    // findings above come from the scan before each of them.
    ...(open.skipped.length > 0 ? { skipped_scans: open.skipped } : {}),
    plans,
  };
}

/**
 * One line beside the structured `filtered`, on the same contract
 * `create_fix_pr` keeps: `null` iff nothing was excluded, and a severity
 * suggestion only where a lower floor genuinely recovers something.
 */
function describeFiltered(
  filtered: {
    considered: number;
    candidates: number;
    excluded: number;
    by_reason: { below_severity_min: number; over_max_issues: number };
    below_severity_min: SeverityShortfall;
  },
  severityMin: Severity,
  maxIssues: number,
): string | null {
  if (filtered.excluded === 0) return null;

  const parts: string[] = [];
  if (filtered.by_reason.below_severity_min > 0) {
    parts.push(
      `${filtered.by_reason.below_severity_min} below severity_min "${severityMin}" ` +
        `(${describeShortfallTiers(filtered.below_severity_min)})`,
    );
  }
  if (filtered.by_reason.over_max_issues > 0) {
    parts.push(
      `${filtered.by_reason.over_max_issues} beyond max_issues (${maxIssues}), lowest severity first`,
    );
  }

  const head =
    `${filtered.excluded} of ${filtered.considered} open finding(s) were excluded; ` +
    `${filtered.candidates} filed. Excluded: ${parts.join('; ')}.`;

  const suggested = filtered.below_severity_min.suggested_severity_min;
  if (suggested === null) return head;
  const lowest = lowestExcludedSeverity(filtered.below_severity_min);
  const rest =
    lowest !== null && lowest !== suggested
      ? `, or "${lowest}" for all ${filtered.below_severity_min.total}`
      : '';
  return (
    `${head} Pass severity_min "${suggested}" to include ` +
    `${filtered.below_severity_min.recovered_by_suggestion} of them${rest}.`
  );
}

function tagOf(f: Finding): string {
  return f.fingerprint.slice(0, 12);
}

function buildTitle(f: Finding): string {
  const tag = `[guardian:${tagOf(f)}]`;
  const head = `[${f.severity.toUpperCase()}] ${f.title}`.slice(0, 200);
  return `${head} ${tag}`;
}

function buildBody(f: Finding, scanId: string): string {
  return [
    `**Severity:** ${f.severity}`,
    `**Category:** ${f.category}${f.subcategory ? ` / ${f.subcategory}` : ''}`,
    `**Tool:** ${f.tool}${f.rule_id ? ` (\`${f.rule_id}\`)` : ''}`,
    f.file_path ? `**Location:** \`${f.file_path}${f.line_start ? `:${f.line_start}` : ''}\`` : '',
    f.message ? `\n${f.message}\n` : '',
    f.snippet ? `\n\`\`\`\n${f.snippet}\n\`\`\`\n` : '',
    `\n---`,
    `Fingerprint: \`${f.fingerprint}\``,
    `Scan id: \`${scanId}\``,
    `\n_Filed automatically by dev-guardian. Use \`suppress_finding\` to mark as false positive._`,
  ]
    .filter(Boolean)
    .join('\n');
}

/**
 * The `[guardian:<12 hex>]` tag of every issue in the repository, open AND
 * closed. `gh issue list` alone returns open issues only — which is how a
 * closed issue's finding got filed again on every run.
 */
async function listExistingTags(
  cwd: string,
): Promise<{ ok: true; tags: Set<string> } | { ok: false; error: string }> {
  const r = await runProcess({
    command: 'gh',
    args: ['issue', 'list', '--state', 'all', '--limit', '1000', '--json', 'number,title,state'],
    cwd,
    timeoutMs: 30_000,
  });
  if (r.outcome !== 'completed') {
    return { ok: false, error: firstLine(r.stderr) ?? `gh exited ${r.outcome}` };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(r.stdout || '[]');
  } catch {
    return { ok: false, error: 'gh issue list printed something that is not JSON' };
  }
  if (!Array.isArray(parsed)) return { ok: false, error: 'gh issue list did not return a JSON array' };
  const tags = new Set<string>();
  for (const issue of parsed) {
    const title = (issue as { title?: unknown }).title;
    if (typeof title !== 'string') continue;
    for (const m of title.matchAll(/\[guardian:([0-9a-f]{12})\]/g)) {
      const tag = m[1];
      if (tag !== undefined) tags.add(tag);
    }
  }
  return { ok: true, tags };
}

/**
 * Splits the requested labels into the ones the repository has (creating
 * the missing ones) and the ones it cannot have. A label `gh issue create`
 * does not know fails the whole issue, so an uncreatable label is dropped
 * from the issue rather than allowed to fail it.
 */
async function ensureLabels(
  cwd: string,
  labels: readonly string[],
): Promise<{ applied: string[]; omitted: string[] }> {
  if (labels.length === 0) return { applied: [], omitted: [] };
  const listed = await runProcess({
    command: 'gh',
    args: ['label', 'list', '--limit', '1000', '--json', 'name'],
    cwd,
    timeoutMs: 15_000,
  });
  const known = new Set<string>();
  if (listed.outcome === 'completed') {
    try {
      const parsed = JSON.parse(listed.stdout || '[]') as unknown;
      if (Array.isArray(parsed)) {
        for (const l of parsed) {
          const name = (l as { name?: unknown }).name;
          if (typeof name === 'string') known.add(name.toLowerCase());
        }
      }
    } catch {
      /* treated as "none known": each label is then created, or found to exist, below */
    }
  }
  const applied: string[] = [];
  const omitted: string[] = [];
  for (const label of labels) {
    if (known.has(label.toLowerCase())) {
      applied.push(label);
      continue;
    }
    const created = await runProcess({
      command: 'gh',
      args: ['label', 'create', label, '--description', 'Filed by dev-guardian'],
      cwd,
      timeoutMs: 15_000,
    });
    if (created.outcome === 'completed' || /already exists/i.test(created.stderr)) applied.push(label);
    else omitted.push(label);
  }
  return { applied, omitted };
}

function firstLine(text: string): string | undefined {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .find((l) => l.length > 0);
}

async function createIssue(
  cwd: string,
  title: string,
  body: string,
  labels: string[],
): Promise<{ ok: true; url: string } | { ok: false; error: string }> {
  const args = ['issue', 'create', '--title', title, '--body', body];
  for (const l of labels) args.push('--label', l);
  const r = await runProcess({ command: 'gh', args, cwd, timeoutMs: 30_000 });
  if (r.outcome === 'completed') {
    // gh prints the URL of the created issue.
    const url = r.stdout
      .split(/\r?\n/)
      .map((s) => s.trim())
      .find((s) => s.startsWith('https://'));
    return { ok: true, url: url ?? '' };
  }
  return {
    ok: false,
    error: firstLine(r.stderr) ?? `gh exited ${r.outcome}`,
  };
}

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
