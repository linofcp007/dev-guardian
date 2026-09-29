/**
 * `create_fix_pr` — orchestrates Tasks 1–6 into the tool that applies fixes
 * the scanners themselves already produced, proves them, and opens a pull
 * request (the design of record).
 *
 * Flow: resolve the project path → refuse if not a git repository → read the
 * project's open findings → ask `deps_update_plan` for upgrade steps (when
 * `sources` includes `'deps'`) → `buildGroups` → `selectGroups` → for every
 * SELECTED group: create an isolated worktree, apply the group's fix,
 * re-scan inside the worktree, judge the scan and test differentials, and —
 * only when the fix verifies AND `apply` is true — open a pull request.
 *
 * **`apply` defaults to `false`, and that is the whole safety story** (design
 * §6). Everything expensive and everything verifiable still runs — the
 * worktree is created, the fix is applied, both differentials execute. What
 * sits behind the flag is only what leaves the machine: commit, push, and
 * `gh pr create`. That gate is enforced in exactly one place below (the
 * `if (!apply)` short-circuit before `openPr` is ever called) and nowhere
 * else, so it cannot be bypassed by a path that forgets to check it.
 *
 * **The worktree is removed on every path, including every failure path.**
 * Each selected group gets its own worktree (branched fresh from committed
 * HEAD) and its own `try { … } finally { await worktree.remove(); }` — a
 * failure in one group's worktree creation, fix application, re-scan, or PR
 * step never leaves that group's worktree registered, and never prevents the
 * remaining selected groups from being attempted.
 *
 * **A failed verification is `ok: true` with a verdict, not a `DomainError`.**
 * The only precondition that fails the WHOLE call is not being inside a git
 * repository at all — nothing downstream is meaningful without one, and nothing
 * has been created yet at that point. Every other failure this design
 * enumerates (the design of record's items 2–8: no `gh`, worktree creation failed, the fix
 * command failed, the scan differential failed, the fix broke the tests, push
 * failed, `gh pr create` failed) happens PER GROUP, inside a per-group
 * worktree that is always cleaned up, and is reported as that group's own
 * result rather than aborting sibling groups that may have already succeeded
 * or may yet succeed. `gh` missing is not special-cased here at all: `openPr`
 * (Task 6) already refuses cleanly when it cannot determine PR existence —
 * exactly what happens when `gh` is not on PATH — and that refusal surfaces
 * as this group's own `pr.status === 'refused'`.
 *
 * **`GroupResult.outcome` is structural, not prose (task-7-review.md I6).**
 * `note` is still always populated, for a human, but nothing that decides
 * "did this group's infrastructure break, or did we choose not to publish"
 * should have to string-match it — `outcome` names exactly which of those
 * happened. `'worktree_failed'` was reserved as a top-level `DomainErrorCode`
 * by Task 1 for this feature and was never emitted there; deleted from
 * `DOMAIN_ERROR_CODES` (`../types.js`) rather than left dead, since the
 * per-group shape this whole file settled on (confirmed correct on review)
 * has no top-level use for it, and the string now names a `GroupOutcome`
 * instead — the same failure, reported where it actually happens.
 *
 * **The local branch is deleted whenever nothing keeps it meaningful
 * (task-7-review.md C2).** `git worktree remove` never deletes the branch a
 * worktree was checked out on (confirmed by `pr.ts`'s own `push_failed`/
 * `create_failed` messages, which rely on exactly that). Left alone, EVERY
 * run that does not end in a created PR — not just a dry run — leaves a
 * stray branch behind: the design of record's "not a branch" violated literally, and a
 * later call for the SAME group collides on that branch name in
 * `createWorktree`, before `prExists`'s own idempotency check is ever
 * reached. `deleteLocalBranch` (`../fixpr/pr.js`) runs in the same `finally`
 * as the worktree teardown, for every outcome except the three where
 * `pr.ts`'s own module comment already documents the branch surviving on
 * purpose: `created` (now the PR's branch), `push_failed` and `create_failed`
 * (a human may need to find it by hand).
 *
 * **That collision is unavoidable, by design, for those same three outcomes
 * (final review, 2026-08-16-create-fix-pr, finding I1).** C2 only deletes the
 * branch when nothing keeps it meaningful — `created`, `push_failed` and
 * `create_failed` keep it ON PURPOSE, so a repeat run for the SAME group
 * always hits exactly the collision the paragraph above describes: for the
 * entire life of an open pull request, every re-run's `createWorktree` fails
 * before `prExists` is ever reached, and — unfixed — reported that as
 * `worktree_failed`, structurally indistinguishable from a genuine
 * infrastructure break. `processGroup` below now calls `prExists` itself the
 * moment `createWorktree` fails, and reports a genuine hit as `pr_exists`
 * (`pr.ts#existsOutcome`) — the outcome `openPr`'s own check would have
 * produced had the collision not kept it from running at all. This runs
 * whether or not `apply` is true: the branch collision, and hence whether a
 * PR already exists for it, does not depend on this run's own `apply` value,
 * and `prExists` performs only the same read `openPr` would eventually have
 * made anyway on an `apply: true` repeat — never a write, so it does not
 * compromise the design of record's actual boundary, which is stated in terms of what
 * "leaves the machine" (commit, push, `gh pr create`), not in terms of `gh`
 * being touched at all.
 *
 * **Nothing is filtered silently (`filtered` / `filtered_reason`).** The
 * default `severity_min` is `high`, and the 1.9.0 audit took the `ERROR`
 * tier — the only Semgrep tier the parser maps to `high` — from 20 rules of
 * 34 to 4 of 58. A default run against a project whose findings all come
 * from the local packs therefore selects nothing, and used to say so only by
 * returning `groups: []`, indistinguishable from a project with nothing to
 * fix. The floor is not the bug and has NOT been lowered: `floating-mutation`
 * matches on a method name alone and cannot tell `repo.save()` from Canvas
 * 2D's `ctx.save()`, so a lower default would open pull requests rewriting
 * code that was never wrong. What was missing was the account of what the
 * floor (and the other two gates) removed, which `fixpr/exclusions.ts` now
 * produces — reported whenever ANYTHING was excluded, not only when
 * everything was: a run that fixes 2 of 42 is nearly as opaque as one that
 * fixes 0.
 *
 * **Task 11 (2026-09-25 review) — what a run touches, and what proves it.**
 *
 *   - A DRY RUN CHANGES NOTHING OUTSIDE ITS WORKTREE. Its worktree is
 *     detached (no branch written to the user's refs); the failing-test
 *     comparison runs in a second, disposable tree of the base commit, never
 *     in the user's own working tree (`judgeTests`' `baseTree`); a pip fix
 *     edits the pin inside the worktree, never `pip install` on the host;
 *     every npm install runs with `--ignore-scripts`; and the verification
 *     scans' rows are deleted once read.
 *   - "Before" and "after" come from the SAME tool and rule packs: each
 *     target is re-scanned by the tool that produced it (`fixpr/rescan.ts`:
 *     `scan_sast` with its `local_only`, `bug_hunt` with its language packs,
 *     `deps_audit` / `scan_deps`), with the original project's rule
 *     configuration (`ToolCallMeta.originProjectPath`), against the findings
 *     of the scans that produced the targets — the project-scoped open set
 *     (Task 8), not "the latest scan of any type". A finding nothing can
 *     re-scan that way is no candidate.
 *   - The Semgrep fix applies ONLY the target rules (`fixpr/semgrepFix.ts`),
 *     with metrics off; a dependency finding is paired with its upgrade step
 *     by its structured package, never by words in its advisory.
 */
import { existsSync, readFileSync } from 'node:fs';
import { isAbsolute, join, relative } from 'node:path';
import { z } from 'zod';
import { applyGroup } from '../fixpr/apply.js';
import { buildGroups, DEP_SCANNER_TOOLS, findingEcosystem, rankCandidates, selectGroups, } from '../fixpr/candidates.js';
import { describeExclusions, summariseExclusions } from '../fixpr/exclusions.js';
import { branchName, deleteLocalBranch, existsOutcome, openPr, prExists } from '../fixpr/pr.js';
import { disposeSemgrepFixPlan, planSemgrepFix } from '../fixpr/semgrepFix.js';
import { deriveTestCommand, TEST_MANIFESTS } from '../fixpr/testCommand.js';
import { prepareTestEnvironment } from '../fixpr/testEnv.js';
import { projectTreeState } from '../fixpr/treeState.js';
import { rescanOriginOf, scannerNotVerified } from '../fixpr/rescan.js';
import { judgeScan, judgeTests, mayOpenPr } from '../fixpr/verify.js';
import { createWorktree } from '../fixpr/worktree.js';
import { openSetForProject } from '../history/openSet.js';
import { enrichCveIntel } from '../intel/enrich.js';
import { findingCveIds } from '../intel/rank.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { runProcess } from '../runners/processRunner.js';
import { planSemgrepConfigs } from '../runners/semgrepConfigs.js';
import { ProjectPath, SeverityMin } from '../schemas.js';
import { passes } from '../severity/filter.js';
import { deleteScans } from '../storage/maintenance.js';
import { bugHuntLocalConfigs } from './bugHunt.js';
import { isGitRepo } from './gitState.js';
import { registerToolModule, TOOLS } from './index.js';
const DEFAULT_SOURCES = ['deps', 'semgrep'];
const DEFAULT_SEVERITY_MIN = 'high';
const DEFAULT_MAX_PRS = 3;
/** `PrOutcome.status` → `GroupOutcome`, once `openPr` has actually been
 *  called. A plain `Record`, not a switch: exhaustiveness is enforced by
 *  `PrOutcome['status']` being a closed union, so a status this map does not
 *  cover is a compile error here, not a silent `undefined` at runtime. */
const PR_STATUS_OUTCOME = {
    created: 'pr_created',
    exists: 'pr_exists',
    refused: 'pr_refused',
    no_changes: 'pr_no_changes',
    push_failed: 'pr_push_failed',
    create_failed: 'pr_create_failed',
};
/** The three `PrOutcome.status` values `pr.ts` documents the local branch
 *  surviving for on purpose — see this module's own comment (C2). Every
 *  other outcome (including never reaching `openPr` at all) deletes it. */
const KEEPS_BRANCH = new Set([
    'created', 'push_failed', 'create_failed',
]);
const tool = {
    name: 'create_fix_pr',
    title: 'Apply scanner-produced fixes and open a pull request',
    description: 'Apply fixes the scanners themselves already produced — deps_update_plan pinned upgrade ' +
        'steps (npm with --ignore-scripts, pip pins edited in place) and the target rules\' own ' +
        'Semgrep autofix (only those rules, --metrics=off) — inside an isolated git worktree, prove ' +
        'them by re-running the SAME tool and rule packs that found them (scan_sast, bug_hunt, ' +
        'deps_audit or scan_deps) plus a lazy test differential against a pristine base-commit tree, ' +
        'and open one pull request per ecosystem or scanner. apply defaults to false: a dry run works ' +
        'in a detached worktree, writes no branch, never runs tests in your tree and leaves no scan ' +
        'rows behind; only commit/push/gh pr create sit behind apply=true. Every open finding ' +
        'that did NOT become a candidate is accounted for in `filtered` (below severity_min, no ' +
        'scanner-produced fix, file changed since HEAD, no requested source or re-scan covers it) and in ' +
        '`filtered_reason`. ' +
        'A cancelled call answers ok with cancelled: true and the groups it finished.',
    inputSchema: {
        project_path: ProjectPath,
        // .describe() override, not the shared SeverityMin as-is (M8): that
        // schema's own description says "Default: include all", correct for
        // every OTHER tool that uses it (no zod .default(), so the description
        // is the only place the default is stated) but wrong for this tool,
        // whose actual default is 'high' (DEFAULT_SEVERITY_MIN below). Reusing
        // the shared schema is still right — .describe() returns a new instance
        // rather than mutating the shared one, so every other caller keeps
        // seeing "include all".
        severity_min: SeverityMin.describe('Minimum severity a finding must have to be considered a fix candidate. Default: high.'),
        sources: z
            .array(z.enum(['deps', 'semgrep']))
            .optional()
            .describe("Which fix sources to consider. Default: both ('deps' and 'semgrep')."),
        max_prs: z
            .number()
            .int()
            .min(1)
            .max(10)
            .optional()
            .describe('Maximum number of groups (pull requests) to act on in one run, highest severity ' +
            'first, then CISA KEV-listed, then higher FIRST EPSS. Groups beyond the cap are reported ' +
            'in `deferred`, never dropped silently. Default: 3.'),
        apply: z
            .boolean()
            .optional()
            .describe('When true, commit, push and open a pull request for every group that verifies. ' +
            'Default: false — a dry run that still computes candidates, applies the fix in a ' +
            'worktree, and runs both differentials, but never leaves the machine.'),
    },
    handler: async (input, ctx, callMeta) => handler(input, ctx, callMeta),
};
registerToolModule(tool);
async function handler(input, ctx, callMeta) {
    const inp = input;
    let projectPath;
    try {
        projectPath = resolveProjectPath(inp.project_path).path;
    }
    catch (e) {
        return failDomain('not_a_git_repo', e.message);
    }
    if (!(await isGitRepo(projectPath))) {
        return failDomain('not_a_git_repo', `'${projectPath}' is not inside a git working tree.`);
    }
    const severityMin = inp.severity_min ?? DEFAULT_SEVERITY_MIN;
    // `??`, not `||`: an explicit empty array is a deliberate "consider
    // nothing" and must not be silently reinterpreted as "use the default".
    const sources = inp.sources ?? DEFAULT_SOURCES;
    const maxPrs = inp.max_prs ?? DEFAULT_MAX_PRS;
    const apply = inp.apply === true;
    // The project's open set (Task 8): every state scan type's newest usable
    // scan of THIS project, suppressions applied — each finding carrying the
    // scan it was read from, which is what decides how it is re-verified.
    const openSet = openSetForProject(ctx.storage, projectPath);
    const allFindings = openSet.findings;
    const scansById = new Map(openSet.scans.map((s) => [s.scan_id, s]));
    const origins = new Map();
    for (const f of allFindings) {
        const scan = scansById.get(f.scan_id) ?? ctx.storage.scans.getById(f.scan_id);
        const origin = scan === null || scan === undefined ? null : rescanOriginOf(f, scan);
        if (origin !== null)
            origins.set(f.fingerprint, origin);
    }
    // Where the project sits in its repository (a worktree is a checkout of the
    // whole repository), and which of its files differ from HEAD: a finding in
    // such a file came from the working tree while the fix and its re-scan run
    // on HEAD — no verdict about it would mean anything (Task 11 fix round 1).
    const tree = await projectTreeState(projectPath);
    if (!tree.ok)
        return failDomain('not_a_git_repo', tree.reason);
    const uncommitted = (f) => f.file_path !== undefined && f.file_path.length > 0 && tree.dirty.has(tree.prefix + projectRelative(projectPath, f.file_path));
    // A finding no tool can re-scan with the packs that produced it, or one in
    // an uncommitted file, is not a candidate: its fix could never be verified.
    const verifiable = (f) => origins.has(f.fingerprint) && !uncommitted(f);
    // The plan is only worth its disposable worktree when some finding could
    // take a step from it.
    const needsPlan = sources.includes('deps') &&
        allFindings.some((f) => DEP_SCANNER_TOOLS.includes(f.tool) && f.fix_available && passes(f.severity, severityMin) && verifiable(f));
    const plan = needsPlan
        ? await fetchUpgradeSteps(projectPath, tree.prefix, ctx, callMeta)
        : { steps: [], error: null, runnerFailures: [] };
    // A dependency finding whose ecosystem the plan could not cover is not
    // "no fix source" — nobody knows (Task 11 fix round 2).
    const failedEcosystems = new Set(plan.runnerFailures.map((f) => f.ecosystem));
    const planFailed = (f) => {
        if (!needsPlan || !DEP_SCANNER_TOOLS.includes(f.tool))
            return false;
        if (plan.error !== null)
            return true;
        const ecosystem = findingEcosystem(f);
        return ecosystem !== null && failedEcosystems.has(ecosystem);
    };
    const groups = buildGroups({
        findings: allFindings,
        upgradeSteps: plan.steps,
        sources,
        severityMin,
        rescannable: verifiable,
    });
    // Every open finding this run did NOT turn into a candidate, and why —
    // computed from `groups`, i.e. BEFORE `max_prs` defers any of them, so the
    // two "not acted on" reports stay disjoint: `filtered` is about findings
    // that never became candidates, `deferred` about candidate groups the cap
    // held back. See `fixpr/exclusions.ts` for why silence here was a defect.
    const filtered = summariseExclusions({ findings: allFindings, groups, severityMin, uncommitted, planFailed });
    const filtered_reason = describeExclusions(filtered, severityMin, sources);
    // Which fixes are attempted first (Task 24, item 5): within a severity
    // band, a CISA KEV-listed CVE, then a higher FIRST EPSS score — which
    // groups the `max_prs` cap keeps, and the order a group's fixes are applied
    // in (`applyGroup` stops at the first that fails). Intel is cached 24h and
    // offline-safe (`GUARDIAN_OFFLINE=1`); an unmeasured CVE changes nothing.
    const exploitability = await exploitabilityOf(groups, allFindings, ctx, callMeta);
    const { selected, deferred, deferred_reason } = selectGroups(groups.map((group) => rankCandidates(group, exploitability)), maxPrs, exploitability);
    const results = [];
    let cancelled = false;
    for (const group of selected) {
        // Checked before each group: once the host cancels, no further worktree
        // is created and no further fix is applied. The group in flight when the
        // cancel arrived has already stopped (its re-scan shares the signal) and
        // cleaned up in processGroup's own `finally`; the rest are reported, not
        // dropped — groups before the cancel may already have opened a PR.
        if (callMeta?.signal?.aborted === true) {
            cancelled = true;
            results.push({
                key: group.key,
                source: group.source,
                severity: group.severity,
                branch: branchName(group.source, group.key, group.hash),
                findings: findingsForGroup(allFindings, group),
                commands: [],
                outcome: 'cancelled',
                scan: null,
                tests: null,
                pr: null,
                note: 'cancelled: the host cancelled this call before this group started — no worktree was created and nothing was applied',
            });
            continue;
        }
        try {
            results.push(await processGroup({ group, allFindings, origins, projectPath, prefix: tree.prefix, apply, ctx, callMeta }));
        }
        catch (e) {
            // Every ANTICIPATED failure mode (worktree creation, apply, re-scan,
            // push, gh pr create) is reported by processGroup as a normal return,
            // not a throw — see its own `finally`. This catch exists only for a
            // genuinely unexpected exception, and its purpose is narrow: that
            // group's own worktree is already gone (processGroup's `finally` ran
            // before this exception reached here, whatever raised it), and a bug
            // isolated to one group must not also cost the report on every OTHER
            // selected group, some of which may already have succeeded or may
            // yet succeed.
            results.push({
                key: group.key,
                source: group.source,
                severity: group.severity,
                branch: branchName(group.source, group.key, group.hash),
                findings: findingsForGroup(allFindings, group),
                commands: [],
                outcome: 'internal_error',
                scan: null,
                tests: null,
                pr: null,
                note: `internal_error: unexpected failure while processing this group — ${errorMessage(e)}`,
            });
        }
    }
    return {
        ok: true,
        applied: apply,
        project_path: projectPath,
        severity_min: severityMin,
        sources,
        ...(cancelled ? { cancelled: true } : {}),
        // The deps side found nothing to pair because the plan itself could not
        // be computed — said, never left to read as "no upgrade available".
        ...(plan.error !== null ? { deps_plan_error: plan.error } : {}),
        ...(plan.runnerFailures.length > 0 ? { deps_plan_runner_failures: plan.runnerFailures } : {}),
        filtered,
        filtered_reason,
        groups: results,
        deferred,
        deferred_reason,
    };
}
/**
 * The KEV/EPSS signal of every candidate's findings — `intel/rank.ts
 * #findingCveIds` per finding, enriched once for the whole run over only the
 * CVEs a candidate targets (never every open finding's).
 */
async function exploitabilityOf(groups, allFindings, ctx, callMeta) {
    const targets = new Set(groups.flatMap((g) => g.candidates.flatMap((c) => c.fingerprints)));
    const cveIds = new Map();
    for (const f of allFindings) {
        if (targets.has(f.fingerprint) && !cveIds.has(f.fingerprint))
            cveIds.set(f.fingerprint, findingCveIds(f));
    }
    const intel = await enrichCveIntel(ctx.storage, [...cveIds.values()].flat(), callMeta?.signal !== undefined ? { signal: callMeta.signal } : {});
    return { cveIdsOf: (fingerprint) => cveIds.get(fingerprint) ?? [], intel };
}
/**
 * `deps_update_plan`'s handler, called the way `audit_executive` calls its
 * own sub-tools (`TOOLS.find` + `.handler(input, ctx)`). Its result shape is
 * read defensively — `plan` may be absent or malformed only if that tool's
 * own contract ever changes — rather than assumed, matching how
 * `auditExecutive.ts` treats every sub-tool's JSON result as untyped input.
 * A missing tool or a failed plan degrades to "no deps candidates" rather
 * than failing this whole call: the deps side of the run simply finds
 * nothing to group, which `buildGroups` already reports honestly (no group
 * silently invents a fix) — and the response names the failure
 * (`deps_plan_error`).
 *
 * **It runs on a detached worktree of HEAD, never on the user's project**
 * (Task 11 fix round 1). Its .NET branch runs `dotnet restore` where it is
 * pointed (writing `obj/`, executing the project's MSBuild), and a dry run
 * changes nothing outside a worktree. It is also the more correct input: the
 * plan's installed versions and pip `file`s are HEAD's, which is exactly
 * what the fix edits. The CVE history it plans against is the project's own
 * (`ToolCallMeta.originProjectPath`).
 */
async function fetchUpgradeSteps(projectPath, prefix, ctx, callMeta) {
    const depsPlanTool = TOOLS.find((t) => t.name === 'deps_update_plan');
    if (depsPlanTool === undefined) {
        return { steps: [], error: "the 'deps_update_plan' tool is not registered", runnerFailures: [] };
    }
    const created = await createWorktree({ projectPath, branch: null });
    if (!created.ok) {
        return { steps: [], error: `could not create a worktree to plan in: ${created.reason}`, runnerFailures: [] };
    }
    try {
        const meta = {
            ...(callMeta?.signal !== undefined ? { signal: callMeta.signal } : {}),
            ...(callMeta?.progressToken !== undefined ? { progressToken: callMeta.progressToken } : {}),
            originProjectPath: projectPath,
        };
        const result = await depsPlanTool.handler({ project_path: inWorktree(created.worktree.path, prefix) }, ctx, meta);
        if (!result.ok)
            return { steps: [], error: `deps_update_plan failed: ${result.error.message}`, runnerFailures: [] };
        const r = result;
        return {
            steps: Array.isArray(r.plan) ? r.plan : [],
            error: null,
            runnerFailures: Array.isArray(r.runner_failures) ? r.runner_failures.filter(isRunnerFailure) : [],
        };
    }
    finally {
        await created.worktree.remove();
    }
}
function isRunnerFailure(v) {
    if (typeof v !== 'object' || v === null)
        return false;
    const o = v;
    return typeof o['ecosystem'] === 'string' && typeof o['code'] === 'string' && typeof o['reason'] === 'string';
}
/** The project's directory inside a worktree: `prefix` (`app/`, or empty)
 *  under its root, with no trailing separator. */
function inWorktree(root, prefix) {
    return join(root, ...prefix.split('/').filter((segment) => segment.length > 0));
}
/** A finding's file as a POSIX path relative to the project. */
function projectRelative(projectPath, filePath) {
    const rel = isAbsolute(filePath) ? relative(projectPath, filePath) : filePath;
    return rel.replace(/\\/g, '/').replace(/^(\.\/)+/, '');
}
async function processGroup(opts) {
    const { group, allFindings, origins, projectPath, prefix, apply, ctx, callMeta } = opts;
    const branch = branchName(group.source, group.key, group.hash);
    const targets = group.candidates.flatMap((c) => c.fingerprints);
    const findings = findingsForGroup(allFindings, group);
    const base = { key: group.key, source: group.source, severity: group.severity, branch, findings };
    // A dry run changes nothing outside its worktree (Task 11 item 1): its
    // worktree is DETACHED, so no branch is ever written to the user's refs.
    // A branch an earlier apply=true run kept (KEEPS_BRANCH) still decides what
    // apply=true would do next, so a dry run reports it the way apply would.
    if (!apply && (await localBranchExists(projectPath, branch))) {
        const existing = await prExists({ projectPath, branch });
        if (existing.known && existing.exists) {
            const pr = existsOutcome(branch);
            return { ...base, commands: [], outcome: PR_STATUS_OUTCOME[pr.status], scan: null, tests: null, pr, note: prNote(pr) };
        }
        return {
            ...base,
            commands: [],
            outcome: 'worktree_failed',
            scan: null,
            tests: null,
            pr: null,
            note: `worktree_failed: branch '${branch}' already exists locally (kept by an earlier run) and no pull ` +
                'request was found for it — apply=true would collide on it',
        };
    }
    const created = await createWorktree({ projectPath, branch: apply ? branch : null });
    if (!created.ok) {
        // The module comment (I1) explains why this is reachable at all: a
        // branch collision here can only mean a PREVIOUS run reached `openPr`
        // and kept this exact branch (KEEPS_BRANCH). Ask `prExists` before
        // reporting an infrastructure failure — if a pull request genuinely
        // exists, that is the honest report, not `worktree_failed`. No worktree
        // was ever created on this path, so there is nothing to clean up and
        // nothing that could make deleting the branch here safe (see below).
        const existing = await prExists({ projectPath, branch });
        if (existing.known && existing.exists) {
            const pr = existsOutcome(branch);
            return {
                ...base,
                commands: [],
                outcome: PR_STATUS_OUTCOME[pr.status],
                scan: null,
                tests: null,
                pr,
                note: prNote(pr),
            };
        }
        return {
            ...base,
            commands: [],
            outcome: 'worktree_failed',
            scan: null,
            tests: null,
            pr: null,
            note: `worktree_failed: could not create an isolated worktree for branch '${branch}': ${created.reason}`,
        };
    }
    const { worktree } = created;
    // Set true only at the one point below where openPr's own status says the
    // branch should survive — see the module comment (C2) and KEEPS_BRANCH.
    // A dry run's worktree is detached: there is no branch to delete at all.
    let keepBranch = !apply;
    let semgrepFix;
    try {
        // The test command must be known BEFORE applyGroup runs — it decides
        // lockfileOnly, which applyGroup needs as an input — so manifests are
        // read from the worktree (the fix has not been applied yet, but the
        // worktree already reflects the exact committed content that will be
        // tested, which projectPath's own possibly-dirty working tree might not).
        // The project's own directory inside the worktree (a checkout of the
        // whole repository): where the fix, the test run and the re-scan happen.
        // Git operations (openPr) use the worktree root.
        const projectDir = inWorktree(worktree.path, prefix);
        const derivedTest = deriveTestCommand(readManifests(projectDir));
        const commands = [];
        // The same dependency install the base-commit tree gets, if any — see
        // fixpr/testEnv.ts: the test differential compares like with like.
        const env = await prepareTestEnvironment({ treePath: projectDir, derived: derivedTest });
        if (env.command !== null)
            commands.push(`${env.command} (test environment)`);
        if (!env.ok) {
            return {
                ...base,
                commands,
                outcome: 'apply_failed',
                scan: null,
                tests: null,
                pr: null,
                note: `apply_failed: could not prepare the test environment — ${env.reason}`,
            };
        }
        if (group.source === 'semgrep') {
            const planned = planSemgrepFix(semgrepFixSources(findings, origins, projectPath, ctx));
            if (!planned.ok) {
                return {
                    ...base,
                    commands,
                    outcome: 'apply_failed',
                    scan: null,
                    tests: null,
                    pr: null,
                    note: `apply_failed: the fix could not be applied — ${planned.reason}`,
                };
            }
            semgrepFix = planned.plan;
        }
        let applied;
        try {
            applied = await applyGroup({
                group,
                worktreePath: projectDir,
                lockfileOnly: derivedTest === null,
                ...(semgrepFix !== undefined ? { semgrepFix } : {}),
            });
        }
        finally {
            if (semgrepFix !== undefined)
                disposeSemgrepFixPlan(semgrepFix);
        }
        commands.push(...applied.commands);
        if (!applied.applied) {
            return {
                ...base,
                commands,
                outcome: 'apply_failed',
                scan: null,
                tests: null,
                pr: null,
                note: applyFailedNote(applied.failure),
            };
        }
        const rescan = await rescanAfterFix(findings, origins, projectDir, projectPath, ctx, callMeta);
        if (!rescan.ok) {
            return {
                ...base,
                commands,
                outcome: 'verification_failed',
                scan: null,
                tests: null,
                pr: null,
                note: `verification_failed: could not verify the fix — ${rescan.reason}`,
            };
        }
        // "Before" is exactly the scans that produced the targets — the same
        // tools and packs the re-scan just ran (Task 11 item 2) — never "the
        // project's latest scan of any type".
        const sourceScanIds = [...new Set(findings.map((f) => f.scan_id))].sort();
        const before = sourceScanIds.flatMap((id) => ctx.storage.findings.listByScan(id));
        const scanVerdict = judgeScan(targets, { scan_id: sourceScanIds.join(','), findings: before }, { scan_id: rescan.scanIds.join(','), findings: rescan.findings });
        const testVerdict = await judgeTests({
            derived: derivedTest,
            worktreePath: projectDir,
            baseTree: baseTreeProvider(projectPath, prefix, derivedTest),
        });
        if (!mayOpenPr(scanVerdict, testVerdict)) {
            const why = !scanVerdict.passed
                ? `the scan differential did not pass (${scanVerdict.still_present.length} target(s) still ` +
                    `present, ${scanVerdict.new_findings.length} new finding(s))`
                : testVerdict.outcome === 'unattributed'
                    ? 'the test suite failed after the fix and the base-commit comparison could not be run'
                    : 'the fix broke the test suite';
            return {
                ...base,
                commands,
                outcome: 'not_verified',
                scan: scanVerdict,
                tests: testVerdict,
                pr: null,
                note: `not_verified: ${why} — no pull request opened`,
            };
        }
        if (!apply) {
            return {
                ...base,
                commands,
                outcome: 'verified_dry_run',
                scan: scanVerdict,
                tests: testVerdict,
                pr: null,
                note: 'verified: dry run (apply=false) — re-run with apply=true to open a pull request',
            };
        }
        const title = buildPrTitle(group, targets.length);
        const body = buildPrBody({ group, findings, commands, scan: scanVerdict, tests: testVerdict });
        const pr = await openPr({ projectPath, worktreePath: worktree.path, branch, title, body });
        keepBranch = KEEPS_BRANCH.has(pr.status);
        return {
            ...base,
            commands,
            outcome: PR_STATUS_OUTCOME[pr.status],
            scan: scanVerdict,
            tests: testVerdict,
            pr,
            note: prNote(pr),
        };
    }
    finally {
        // Per group, on every path above — success, every early return, and any
        // throw. `await`ed so the worktree is actually gone (or reported unable
        // to be) before this group's turn ends, matching worktree.ts's own
        // "teardown verified by observing the world" discipline rather than
        // trusting a fire-and-forget call.
        await worktree.remove();
        // C2: best-effort, like worktree.remove() above — a branch that fails to
        // delete is a stray local ref, not a lie the tool tells.
        if (!keepBranch) {
            await deleteLocalBranch({ projectPath, branch });
        }
    }
}
/** Whether `refs/heads/<branch>` exists in the user's repository. A read. */
async function localBranchExists(projectPath, branch) {
    const r = await runProcess({
        command: 'git',
        args: ['-C', projectPath, 'rev-parse', '--verify', '--quiet', `refs/heads/${branch}`],
        cwd: projectPath,
    });
    return r.outcome === 'completed';
}
/**
 * The base-commit tree the test differential compares a failing run against:
 * a fresh DETACHED worktree of HEAD, prepared exactly like the fix's tree
 * (`prepareTestEnvironment`), removed after the run — never the user's own
 * working tree (Task 11 item 1).
 */
function baseTreeProvider(projectPath, prefix, derived) {
    return async () => {
        const created = await createWorktree({ projectPath, branch: null });
        if (!created.ok)
            return { ok: false, reason: created.reason };
        const dir = inWorktree(created.worktree.path, prefix);
        const env = await prepareTestEnvironment({ treePath: dir, derived });
        if (!env.ok) {
            await created.worktree.remove();
            return { ok: false, reason: env.reason };
        }
        return { ok: true, path: dir, dispose: async () => { await created.worktree.remove(); } };
    };
}
/**
 * The human-readable half of a `PrOutcome` (`GroupResult.note` is always
 * populated — see the module comment, I6). Shared by both places
 * `processGroup` learns a `PrOutcome`: the normal path, where `openPr` itself
 * just ran, and the `createWorktree`-collision path (I1), where `prExists`
 * alone determined it — same shape, same wording, either way.
 */
function prNote(pr) {
    return pr.status === 'created'
        ? `pull request opened: ${pr.url ?? '(gh reported no URL)'}`
        : `pull request not opened (${pr.status}): ${pr.detail ?? 'no further detail'}`;
}
function readManifests(worktreePath) {
    const files = {};
    for (const name of TEST_MANIFESTS) {
        const path = join(worktreePath, name);
        if (!existsSync(path))
            continue;
        try {
            files[name] = readFileSync(path, 'utf8');
        }
        catch {
            // Unreadable is treated as absent — deriveTestCommand cannot use
            // content it cannot read, and this is not a failure worth aborting
            // the group over: the other manifests are still tried.
        }
    }
    return files;
}
/**
 * The `apply_failed` note: what went wrong applying the group. A Semgrep pass
 * whose fix was written but whose run is incomplete (`fixpr/apply.ts`,
 * outcome `incomplete`) is said as such — the fix was applied in the
 * disposable worktree and discarded with it, because the scan that would
 * verify it would be incomplete; nothing "could not be applied".
 */
export function applyFailedNote(failure) {
    if (failure?.outcome === 'incomplete') {
        return `apply_failed: applied, then discarded: the verification scan would be incomplete (${failure.stderr_head})`;
    }
    return `apply_failed: the fix could not be applied — ${describeApplyFailure(failure)}`;
}
function describeApplyFailure(failure) {
    if (failure === null)
        return 'unknown failure';
    const exit = failure.exit_code !== null ? ` (exit ${failure.exit_code})` : '';
    return `'${failure.command}' ${failure.outcome}${exit}: ${failure.stderr_head}`;
}
/**
 * For each origin among the group's Semgrep targets: the targets, the LOCAL
 * rule files that origin's scan loads for this project, and whether it loads
 * the registry at all — what `planSemgrepFix` needs to apply exactly the
 * target rules.
 */
function semgrepFixSources(targets, origins, projectPath, ctx) {
    const byKey = new Map();
    for (const f of targets) {
        const origin = origins.get(f.fingerprint);
        if (origin === undefined)
            continue;
        const entry = byKey.get(origin.key) ?? { origin, targets: [] };
        entry.targets.push({ rule_id: f.rule_id ?? '', file_path: f.file_path ?? '' });
        byKey.set(origin.key, entry);
    }
    return [...byKey.values()].map(({ origin, targets: t }) => {
        if (origin.toolName === 'bug_hunt') {
            return { targets: t, localConfigs: bugHuntLocalConfigs(ctx, projectPath), registryAllowed: true };
        }
        const localOnly = origin.input['local_only'] === true;
        const plan = planSemgrepConfigs(projectPath, ctx, localOnly);
        return {
            targets: t,
            localConfigs: plan.rulePacks.filter((p) => !plan.registry.includes(p)),
            registryAllowed: !localOnly,
        };
    });
}
/**
 * Re-runs, inside the already-fixed worktree, the tool and rule packs that
 * produced each target (see {@link rescanOriginOf}) — with the ORIGINAL
 * project's rule configuration (`ToolCallMeta.originProjectPath`: its own
 * `.semgrep.yml`, its registered rules), since the worktree is a different
 * path and may not even hold an uncommitted config.
 *
 * **Every scanner that produced a target must have run ok in the re-scan**,
 * or the verification fails: an empty after-set from a scanner that did not
 * run would read "fixed". That is checked per target on the re-scan's own
 * bookkeeping — including Trivy's per-ecosystem gaps (`trivy:<ecosystem>` in
 * `missing_tools`) for the target's own ecosystem, which leave Trivy's own
 * status `ok` while that ecosystem went unscanned (Task 10 handoff).
 *
 * **The re-scan's rows are deleted once read** (Task 11 item 1): they
 * describe a disposable worktree, and a dry run leaves the database as it
 * found it.
 */
async function rescanAfterFix(targets, origins, worktreePath, projectPath, ctx, callMeta) {
    const byKey = new Map();
    for (const f of targets) {
        const origin = origins.get(f.fingerprint);
        if (origin === undefined)
            return { ok: false, reason: `no tool can re-scan the target ${f.fingerprint.slice(0, 12)}` };
        const entry = byKey.get(origin.key) ?? { origin, targets: [] };
        entry.targets.push(f);
        byKey.set(origin.key, entry);
    }
    const meta = {
        ...(callMeta?.signal !== undefined ? { signal: callMeta.signal } : {}),
        ...(callMeta?.progressToken !== undefined ? { progressToken: callMeta.progressToken } : {}),
        originProjectPath: projectPath,
    };
    const scanIds = [];
    const findings = [];
    for (const { origin, targets: own } of byKey.values()) {
        const subTool = TOOLS.find((t) => t.name === origin.toolName);
        if (subTool === undefined)
            return { ok: false, reason: `the '${origin.toolName}' tool is not registered` };
        const result = await subTool.handler({ project_path: worktreePath, force: true, ...origin.input }, ctx, meta);
        if (!result.ok)
            return { ok: false, reason: `${origin.toolName} failed: ${result.error.message}` };
        const scanId = result.scan_id;
        if (typeof scanId !== 'string')
            return { ok: false, reason: `${origin.toolName} returned no scan_id` };
        const row = ctx.storage.scans.getById(scanId);
        const rows = ctx.storage.findings.listByScan(scanId);
        try {
            deleteScans(ctx.storage.rawHandle(), [scanId]);
        }
        catch {
            /* best effort — a stray row describes a deleted worktree, nothing more */
        }
        if (row === null)
            return { ok: false, reason: `${origin.toolName}'s scan row is missing` };
        const unverified = [...new Set(own.map((t) => scannerNotVerified(t, row)).filter((x) => x !== null))];
        if (unverified.length > 0) {
            return {
                ok: false,
                reason: `${unverified.join(', ')} did not run ok inside the worktree (${origin.toolName} reported it ` +
                    'missing, failed or partial for this target, or cannot check it at all) — cannot verify',
            };
        }
        scanIds.push(scanId);
        findings.push(...rows);
    }
    return { ok: true, scanIds, findings };
}
function buildPrTitle(group, findingCount) {
    const noun = group.source === 'deps' ? `${group.key} dependency` : 'Semgrep';
    const plural = findingCount === 1 ? '' : 's';
    return `dev-guardian: automated ${noun} fix (${findingCount} finding${plural})`;
}
/**
 * States exactly what the design of record requires: the findings covered, the exact
 * commands run, the scan differential, and the test verdict — including,
 * VERBATIM when the outcome is `not_run`, "behaviour was not verified: this
 * project declares no test command".
 *
 * Exported (task-7-review.md M7), unlike every other helper in this file:
 * it is pure (typed inputs in, a string out, no I/O), the same reason
 * `fixpr/*.ts`'s own pure modules export their logic for direct unit
 * testing rather than only through a real tool call. No test in this
 * feature reached a genuinely created PR through `gh` alone — the stub
 * `gh.cmd`'s own `echo %*` truncates a multi-line `--body` argument at its
 * first embedded newline, a real limitation of that capture mechanism, not
 * something a differently-shaped integration test could route around —
 * so the verbatim phrase this function's own doc comment promises had zero
 * regression protection until this export made a direct test possible.
 */
export function buildPrBody(opts) {
    const { group, findings, commands, scan, tests } = opts;
    const lines = [];
    lines.push(`Automated fix opened by dev-guardian's \`create_fix_pr\` for the **${group.key}** ` +
        `(${group.source}) group.`);
    lines.push('', '## Findings covered');
    for (const f of findings) {
        const loc = f.file_path ? ` (\`${f.file_path}${f.line_start ? `:${f.line_start}` : ''}\`)` : '';
        lines.push(`- \`${f.fingerprint.slice(0, 12)}\` [${f.severity}] ${f.title}${loc}`);
    }
    lines.push('', '## Commands run');
    for (const c of commands)
        lines.push(`- \`${c}\``);
    lines.push('', '## Scan differential', `- Resolved: ${scan.resolved.length}`, `- Still present: ${scan.still_present.length}`, `- New findings introduced: ${scan.new_findings.length}`);
    for (const nf of scan.new_findings) {
        lines.push(`  - \`${nf.fingerprint.slice(0, 12)}\` [${nf.severity}] ${nf.title}`);
    }
    lines.push('', '## Test verdict');
    switch (tests.outcome) {
        case 'not_run':
            lines.push('behaviour was not verified: this project declares no test command');
            break;
        case 'passed':
            lines.push(`Passed: \`${tests.command ?? ''}\` (${tests.origin ?? 'unknown origin'}).`);
            break;
        case 'already_failing':
            lines.push(`The test suite was already failing on the base commit BEFORE this change ` +
                `(not caused by this fix): \`${tests.command ?? ''}\` (${tests.origin ?? 'unknown origin'}).`);
            if (tests.output_head)
                lines.push('', '```', tests.output_head, '```');
            break;
        case 'broken_by_fix':
            // Never actually reaches here — mayOpenPr refuses a PR whenever
            // outcome === 'broken_by_fix'. Handled anyway so every TestOutcome has
            // an explicit branch rather than a silently-missing one.
            lines.push('the fix broke the test suite; this pull request should not exist.');
            break;
        case 'unattributed':
            // Never reaches here either — mayOpenPr refuses it too.
            lines.push('the tests failed and the base-commit comparison could not run; this pull request should not exist.');
            break;
    }
    lines.push('', "_Generated by dev-guardian's `create_fix_pr`. This tool verifies that the target findings " +
        'resolved, that no new finding appeared, and that the test suite still passes — it does not ' +
        'review the change itself. Verify before merging._');
    return lines.join('\n');
}
/** The Finding objects a group's candidates target — by fingerprint set
 *  membership, not array order, so a fingerprint's origin candidate never
 *  matters to which findings end up attached to the group's own report. */
function findingsForGroup(allFindings, group) {
    const targetSet = new Set(group.candidates.flatMap((c) => c.fingerprints));
    return allFindings.filter((f) => targetSet.has(f.fingerprint));
}
function errorMessage(e) {
    return e instanceof Error ? e.message : String(e);
}
function failDomain(code, message) {
    return { ok: false, error: { code, message } };
}
//# sourceMappingURL=createFixPr.js.map