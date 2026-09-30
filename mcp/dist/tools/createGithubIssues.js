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
import { isCredentialFinding } from '../fingerprint/findingIdentity.js';
import { openSetForProject } from '../history/openSet.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { runProcess } from '../runners/processRunner.js';
import { ProjectPath } from '../schemas.js';
import { scannerAvailable } from './scanHelpers.js';
import { describeShortfallTiers, lowestExcludedSeverity, severityShortfall, } from '../severity/breakdown.js';
import { SEVERITY_ORDER } from '../types.js';
import { registerToolModule } from './index.js';
const inputSchema = {
    project_path: ProjectPath,
    severity_min: z
        .enum(['info', 'low', 'medium', 'high', 'critical'])
        .optional()
        .describe('Minimum severity a finding must have to be filed. Default: high — what this drops is ' +
        'reported in `filtered`, never silently.'),
    max_issues: z
        .number()
        .int()
        .min(1)
        .max(50)
        .optional()
        .describe('Cap on issues filed in one run, highest severity first. Default: 10 — findings beyond ' +
        'the cap are counted in `filtered`, never silently dropped.'),
    labels: z
        .array(z.string())
        .optional()
        .describe('Labels for every issue. Missing ones are created; one that cannot be is left off (labels_omitted). ' +
        'Default: ["dev-guardian", "security"].'),
    dry_run: z
        .boolean()
        .optional()
        .describe('true: list the issues that would be created and call nothing. Default: false — the call FILES REAL ' +
        'ISSUES on GitHub through the local gh CLI.'),
};
const tool = {
    name: 'create_github_issues',
    title: 'Create GitHub issues for top findings',
    description: 'Use the local `gh` CLI to open one issue per top open finding of project_path (default: the ' +
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
async function handler(input, ctx) {
    const inp = input;
    let projectPath;
    try {
        projectPath = resolveProjectPath(inp.project_path).path;
    }
    catch (e) {
        return failDomain('not_a_git_repo', e.message);
    }
    const ghBin = await scannerAvailable('gh');
    if (!ghBin) {
        return failDomain('missing_scanner', 'GitHub CLI (`gh`) is not installed. See https://cli.github.com/. ' +
            'No API keys are handled here — gh uses your local auth.');
    }
    const dryRun = inp.dry_run === true;
    const sevMin = inp.severity_min ?? 'high';
    const max = inp.max_issues ?? 10;
    const labels = inp.labels ?? ['dev-guardian', 'security'];
    const open = openSetForProject(ctx.storage, projectPath);
    if (open.sources.length === 0) {
        return failDomain('unknown_scan_id', `No usable completed scan of ${projectPath} yet — nothing to file as issues.` +
            (open.skipped.count > 0
                ? ` ${open.skipped.count} scan(s) were skipped because their scanners did not run (coverage none).`
                : ''));
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
    let labelPlan = null;
    const plans = [];
    for (const f of top) {
        const title = buildTitle(f);
        const body = buildBody(f, f.scan_id);
        const plan = {
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
            }
            else if (existing.tags.has(tagOf(f))) {
                plan.status = 'skipped_existing';
            }
            else {
                labelPlan ??= await ensureLabels(projectPath, labels);
                const created = await createIssue(projectPath, title, body, labelPlan.applied);
                if (created.ok) {
                    plan.status = 'created';
                    plan.url = created.url;
                }
                else {
                    plan.status = 'failed';
                    plan.error = created.error;
                }
            }
        }
        plans.push(plan);
    }
    const failedPlans = plans.filter((p) => p.status === 'failed');
    if (plans.length > 0 && failedPlans.length === plans.length) {
        return failDomain('scanner_failed', `All ${plans.length} issue(s) failed to file. First error: ${failedPlans[0]?.error ?? 'unknown'}`);
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
        ...(open.skipped.count > 0 ? { skipped_scans: open.skipped } : {}),
        plans,
    };
}
/**
 * One line beside the structured `filtered`, on the same contract
 * `create_fix_pr` keeps: `null` iff nothing was excluded, and a severity
 * suggestion only where a lower floor genuinely recovers something.
 */
function describeFiltered(filtered, severityMin, maxIssues) {
    if (filtered.excluded === 0)
        return null;
    const parts = [];
    if (filtered.by_reason.below_severity_min > 0) {
        parts.push(`${filtered.by_reason.below_severity_min} below severity_min "${severityMin}" ` +
            `(${describeShortfallTiers(filtered.below_severity_min)})`);
    }
    if (filtered.by_reason.over_max_issues > 0) {
        parts.push(`${filtered.by_reason.over_max_issues} beyond max_issues (${maxIssues}), lowest severity first`);
    }
    const head = `${filtered.excluded} of ${filtered.considered} open finding(s) were excluded; ` +
        `${filtered.candidates} filed. Excluded: ${parts.join('; ')}.`;
    const suggested = filtered.below_severity_min.suggested_severity_min;
    if (suggested === null)
        return head;
    const lowest = lowestExcludedSeverity(filtered.below_severity_min);
    const rest = lowest !== null && lowest !== suggested
        ? `, or "${lowest}" for all ${filtered.below_severity_min.total}`
        : '';
    return (`${head} Pass severity_min "${suggested}" to include ` +
        `${filtered.below_severity_min.recovered_by_suggestion} of them${rest}.`);
}
function tagOf(f) {
    return f.fingerprint.slice(0, 12);
}
function buildTitle(f) {
    const tag = `[guardian:${tagOf(f)}]`;
    const head = `[${f.severity.toUpperCase()}] ${f.title}`.slice(0, 200);
    return `${head} ${tag}`;
}
function buildBody(f, scanId) {
    // A credential finding's snippet is the leaked secret's own line — never
    // pasted into a GitHub issue, which is visible to everyone with read
    // access to the repository (and, for a public one, the internet). This is
    // a second line of defence: the snippet should already be redacted by the
    // time it reaches storage (`redaction/secretFindingRedaction.ts`), but a
    // row written before that existed, or by a path this file does not
    // control, must not leak here either.
    const showSnippet = f.snippet && !isCredentialFinding(f);
    return [
        `**Severity:** ${f.severity}`,
        `**Category:** ${f.category}${f.subcategory ? ` / ${f.subcategory}` : ''}`,
        `**Tool:** ${f.tool}${f.rule_id ? ` (\`${f.rule_id}\`)` : ''}`,
        f.file_path ? `**Location:** \`${f.file_path}${f.line_start ? `:${f.line_start}` : ''}\`` : '',
        f.message ? `\n${f.message}\n` : '',
        showSnippet ? `\n\`\`\`\n${f.snippet}\n\`\`\`\n` : '',
        isCredentialFinding(f)
            ? '\n_This finding flags a credential. Rotate/revoke it at its source and remove it from the ' +
                "file — dev-guardian withholds the matched value from this issue._\n"
            : '',
        `\n---`,
        `Fingerprint: \`${f.fingerprint}\``,
        `Scan id: \`${scanId}\``,
        `\n_Filed automatically by dev-guardian. Use \`suppress_finding\` to mark as false positive._`,
    ]
        .filter(Boolean)
        .join('\n');
}
/** The most issues one dedupe listing asks `gh` for. */
export const ISSUE_LIST_LIMIT = 1000;
/**
 * The `[guardian:<12 hex>]` tag of every dev-guardian issue in the
 * repository, open AND closed. `gh issue list` alone returns open issues
 * only — which is how a closed issue's finding got filed again on every run.
 *
 * Narrowed to dev-guardian's own issues by a title search, so the limit is
 * spent on them rather than on the repository's other issues; and a listing
 * that comes back AT the limit may have been cut — the issue for this very
 * finding could be the one past it — so it fails closed: nothing is filed,
 * rather than a duplicate public issue.
 */
async function listExistingTags(cwd) {
    const r = await runProcess({
        command: 'gh',
        args: [
            'issue', 'list',
            '--state', 'all',
            '--search', '"[guardian:" in:title',
            '--limit', String(ISSUE_LIST_LIMIT),
            '--json', 'number,title,state',
        ],
        cwd,
        timeoutMs: 30_000,
    });
    if (r.outcome !== 'completed') {
        return { ok: false, error: firstLine(r.stderr) ?? `gh exited ${r.outcome}` };
    }
    let parsed;
    try {
        parsed = JSON.parse(r.stdout || '[]');
    }
    catch {
        return { ok: false, error: 'gh issue list printed something that is not JSON' };
    }
    if (!Array.isArray(parsed))
        return { ok: false, error: 'gh issue list did not return a JSON array' };
    if (parsed.length >= ISSUE_LIST_LIMIT) {
        return {
            ok: false,
            error: `gh issue list returned ${parsed.length} dev-guardian issues, its limit of ${ISSUE_LIST_LIMIT}: ` +
                'the listing may be cut, so an existing issue for a finding could be missing from it. Nothing ' +
                'was filed, to avoid duplicates — close or relabel old [guardian:…] issues, or file by hand.',
        };
    }
    const tags = new Set();
    for (const issue of parsed) {
        const title = issue.title;
        if (typeof title !== 'string')
            continue;
        for (const m of title.matchAll(/\[guardian:([0-9a-f]{12})\]/g)) {
            const tag = m[1];
            if (tag !== undefined)
                tags.add(tag);
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
async function ensureLabels(cwd, labels) {
    if (labels.length === 0)
        return { applied: [], omitted: [] };
    const listed = await runProcess({
        command: 'gh',
        args: ['label', 'list', '--limit', '1000', '--json', 'name'],
        cwd,
        timeoutMs: 15_000,
    });
    const known = new Set();
    if (listed.outcome === 'completed') {
        try {
            const parsed = JSON.parse(listed.stdout || '[]');
            if (Array.isArray(parsed)) {
                for (const l of parsed) {
                    const name = l.name;
                    if (typeof name === 'string')
                        known.add(name.toLowerCase());
                }
            }
        }
        catch {
            /* treated as "none known": each label is then created, or found to exist, below */
        }
    }
    const applied = [];
    const omitted = [];
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
        if (created.outcome === 'completed' || /already exists/i.test(created.stderr))
            applied.push(label);
        else
            omitted.push(label);
    }
    return { applied, omitted };
}
function firstLine(text) {
    return text
        .split(/\r?\n/)
        .map((l) => l.trim())
        .find((l) => l.length > 0);
}
async function createIssue(cwd, title, body, labels) {
    const args = ['issue', 'create', '--title', title, '--body', body];
    for (const l of labels)
        args.push('--label', l);
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
function failDomain(code, message) {
    return { ok: false, error: { code, message } };
}
//# sourceMappingURL=createGithubIssues.js.map