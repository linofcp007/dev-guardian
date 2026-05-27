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
 */

import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { runProcess } from '../runners/processRunner.js';
import { ProjectPath } from '../schemas.js';
import { scannerAvailable } from './scanHelpers.js';
import type { DomainError, Finding, Severity, ToolResult } from '../types.js';
import { SEVERITY_ORDER } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

const inputSchema = {
  project_path: ProjectPath,
  severity_min: z.enum(['info', 'low', 'medium', 'high', 'critical']).optional(),
  max_issues: z.number().int().min(1).max(50).optional(),
  labels: z.array(z.string()).optional(),
  dry_run: z.boolean().optional(),
};

const tool: ToolModule = {
  name: 'create_github_issues',
  title: 'Create GitHub issues for top findings',
  description:
    'Use the local `gh` CLI to open one issue per top finding. Uses the developer\'s existing ' +
    'GitHub auth, no API keys handled here, no GitHub Actions involved. Title encodes the ' +
    'finding fingerprint for idempotency. Pass dry_run=true to preview.',
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

  const latest = ctx.storage.scans.getLatest();
  if (!latest) {
    return failDomain('unknown_scan_id', 'No completed scans yet — nothing to file as issues.');
  }
  const all = ctx.storage.findings.listByScan(latest.scan_id);
  const sevFloor = SEVERITY_ORDER[sevMin];
  const top = all
    .filter((f) => SEVERITY_ORDER[f.severity] >= sevFloor)
    .sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity])
    .slice(0, max);

  const plans: IssuePlan[] = [];
  for (const f of top) {
    const title = buildTitle(f);
    const body = buildBody(f, latest.scan_id);
    const plan: IssuePlan = {
      fingerprint: f.fingerprint,
      title,
      body,
      severity: f.severity,
      status: 'would_create',
    };
    if (!dryRun) {
      const exists = await issueExistsByFingerprint(projectPath, f.fingerprint);
      if (exists) {
        plan.status = 'skipped_existing';
      } else {
        const created = await createIssue(projectPath, title, body, labels);
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

  return {
    ok: true,
    applied: !dryRun,
    severity_min: sevMin,
    max_issues: max,
    candidates: plans.length,
    plans,
  };
}

function buildTitle(f: Finding): string {
  const tag = `[guardian:${f.fingerprint.slice(0, 12)}]`;
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

async function issueExistsByFingerprint(
  cwd: string,
  fingerprint: string,
): Promise<boolean> {
  // `gh issue list --search "[guardian:<short>]" --json number`
  const short = fingerprint.slice(0, 12);
  const r = await runProcess({
    command: 'gh',
    args: ['issue', 'list', '--search', `[guardian:${short}] in:title`, '--json', 'number', '--limit', '5'],
    cwd,
    timeoutMs: 15_000,
  });
  if (r.outcome !== 'completed') return false;
  try {
    const arr = JSON.parse(r.stdout || '[]') as unknown[];
    return Array.isArray(arr) && arr.length > 0;
  } catch {
    return false;
  }
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
    error: r.stderr.split(/\r?\n/)[0] ?? `gh exited ${r.outcome}`,
  };
}

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
