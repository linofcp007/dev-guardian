/**
 * `create_fix_pr` — orchestrates Tasks 1–6 into the tool that applies fixes
 * the scanners themselves already produced, proves them, and opens a pull
 * request (design doc `docs/superpowers/specs/2026-08-16-create-fix-pr-design.md`).
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
 * enumerates (design §7 items 2–8: no `gh`, worktree creation failed, the fix
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
 * stray branch behind: design §6's "not a branch" violated literally, and a
 * later call for the SAME group collides on that branch name in
 * `createWorktree`, before `prExists`'s own idempotency check is ever
 * reached. `deleteLocalBranch` (`../fixpr/pr.js`) runs in the same `finally`
 * as the worktree teardown, for every outcome except the three where
 * `pr.ts`'s own module comment already documents the branch surviving on
 * purpose: `created` (now the PR's branch), `push_failed` and `create_failed`
 * (a human may need to find it by hand).
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { applyGroup } from '../fixpr/apply.js';
import { buildGroups, selectGroups } from '../fixpr/candidates.js';
import { branchName, deleteLocalBranch, openPr } from '../fixpr/pr.js';
import { deriveTestCommand, TEST_MANIFESTS } from '../fixpr/testCommand.js';
import { judgeScan, judgeTests, mayOpenPr } from '../fixpr/verify.js';
import { createWorktree } from '../fixpr/worktree.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath, SeverityMin } from '../schemas.js';
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
        'commands and Semgrep --autofix — inside an isolated git worktree, prove them with a scan ' +
        'differential and a (lazy) test differential, and open one pull request per ecosystem or ' +
        'scanner. apply defaults to false: candidates, the worktree, the fix, and both differentials ' +
        'always run; only commit/push/gh pr create sit behind apply=true.',
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
            'first. Groups beyond the cap are reported in `deferred`, never dropped silently. Default: 3.'),
        apply: z
            .boolean()
            .optional()
            .describe('When true, commit, push and open a pull request for every group that verifies. ' +
            'Default: false — a dry run that still computes candidates, applies the fix in a ' +
            'worktree, and runs both differentials, but never leaves the machine.'),
    },
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
    if (!(await isGitRepo(projectPath))) {
        return failDomain('not_a_git_repo', `'${projectPath}' is not inside a git working tree.`);
    }
    const severityMin = inp.severity_min ?? DEFAULT_SEVERITY_MIN;
    // `??`, not `||`: an explicit empty array is a deliberate "consider
    // nothing" and must not be silently reinterpreted as "use the default".
    const sources = inp.sources ?? DEFAULT_SOURCES;
    const maxPrs = inp.max_prs ?? DEFAULT_MAX_PRS;
    const apply = inp.apply === true;
    const allFindings = ctx.storage.findings.listOpenForProject(projectPath);
    const upgradeSteps = sources.includes('deps') ? await fetchUpgradeSteps(projectPath, ctx) : [];
    const groups = buildGroups({ findings: allFindings, upgradeSteps, sources, severityMin });
    const { selected, deferred, deferred_reason } = selectGroups(groups, maxPrs);
    const results = [];
    for (const group of selected) {
        try {
            results.push(await processGroup({ group, allFindings, projectPath, apply, ctx }));
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
        groups: results,
        deferred,
        deferred_reason,
    };
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
 * silently invents a fix).
 */
async function fetchUpgradeSteps(projectPath, ctx) {
    const depsPlanTool = TOOLS.find((t) => t.name === 'deps_update_plan');
    if (depsPlanTool === undefined)
        return [];
    const result = await depsPlanTool.handler({ project_path: projectPath }, ctx);
    if (!result.ok)
        return [];
    const r = result;
    return Array.isArray(r.plan) ? r.plan : [];
}
async function processGroup(opts) {
    const { group, allFindings, projectPath, apply, ctx } = opts;
    const branch = branchName(group.source, group.key, group.hash);
    const targets = group.candidates.flatMap((c) => c.fingerprints);
    const findings = findingsForGroup(allFindings, group);
    const base = { key: group.key, source: group.source, severity: group.severity, branch, findings };
    const created = await createWorktree({ projectPath, branch });
    if (!created.ok) {
        // No branch to clean up here: `git worktree add -b` failed before ever
        // creating one (worktree.ts's own module comment) — nothing was made.
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
    // Everything else, including every early return above this point never
    // being reached at all, deletes it in the `finally`.
    let keepBranch = false;
    try {
        // The test command must be known BEFORE applyGroup runs — it decides
        // lockfileOnly, which applyGroup needs as an input — so manifests are
        // read from the worktree (the fix has not been applied yet, but the
        // worktree already reflects the exact committed content that will be
        // tested, which projectPath's own possibly-dirty working tree might not).
        const derivedTest = deriveTestCommand(readManifests(worktree.path));
        const applied = await applyGroup({
            group,
            worktreePath: worktree.path,
            lockfileOnly: derivedTest === null,
        });
        if (!applied.applied) {
            return {
                ...base,
                commands: applied.commands,
                outcome: 'apply_failed',
                scan: null,
                tests: null,
                pr: null,
                note: `apply_failed: the fix could not be applied — ${describeApplyFailure(applied.failure)}`,
            };
        }
        const rescan = await rescanAfterFix(group, findings, worktree.path, ctx);
        if (!rescan.ok) {
            return {
                ...base,
                commands: applied.commands,
                outcome: 'verification_failed',
                scan: null,
                tests: null,
                pr: null,
                note: `verification_failed: could not verify the fix — ${rescan.reason}`,
            };
        }
        const beforeScanId = ctx.storage.scans.getLatestForProject(projectPath)?.scan_id ?? 'unknown';
        const scanVerdict = judgeScan(targets, { scan_id: beforeScanId, findings: allFindings }, { scan_id: rescan.scanId, findings: rescan.findings });
        const testVerdict = await judgeTests({
            derived: derivedTest,
            worktreePath: worktree.path,
            projectPath,
        });
        if (!mayOpenPr(scanVerdict, testVerdict)) {
            const why = !scanVerdict.passed
                ? `the scan differential did not pass (${scanVerdict.still_present.length} target(s) still ` +
                    `present, ${scanVerdict.new_findings.length} new finding(s))`
                : 'the fix broke the test suite';
            return {
                ...base,
                commands: applied.commands,
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
                commands: applied.commands,
                outcome: 'verified_dry_run',
                scan: scanVerdict,
                tests: testVerdict,
                pr: null,
                note: 'verified: dry run (apply=false) — re-run with apply=true to open a pull request',
            };
        }
        const title = buildPrTitle(group, targets.length);
        const body = buildPrBody({ group, findings, commands: applied.commands, scan: scanVerdict, tests: testVerdict });
        const pr = await openPr({ projectPath, worktreePath: worktree.path, branch, title, body });
        keepBranch = KEEPS_BRANCH.has(pr.status);
        const note = pr.status === 'created'
            ? `pull request opened: ${pr.url ?? '(gh reported no URL)'}`
            : `pull request not opened (${pr.status}): ${pr.detail ?? 'no further detail'}`;
        return {
            ...base,
            commands: applied.commands,
            outcome: PR_STATUS_OUTCOME[pr.status],
            scan: scanVerdict,
            tests: testVerdict,
            pr,
            note,
        };
    }
    finally {
        // Per group, on every path above — success, every early return, and any
        // throw. `await`ed so the worktree is actually gone (or reported unable
        // to be) before this group's turn ends, matching worktree.ts's own
        // "teardown verified by observing the world" discipline rather than
        // trusting a fire-and-forget call.
        await worktree.remove();
        // C2: best-effort, like worktree.remove() above and unlike the rest of
        // this function — deleteLocalBranch's own {deleted, warning} is not
        // threaded back into GroupResult. Doing so would mean restructuring
        // every `return` above into an intermediate variable so this `finally`
        // could still enrich it, which risks the control-flow bug this project
        // has been bitten by before (a safety property that looks like
        // plumbing) for a warning message, not a correctness property: a branch
        // that fails to delete is a stray local ref, not a lie the tool tells.
        if (!keepBranch) {
            await deleteLocalBranch({ projectPath, branch });
        }
    }
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
function describeApplyFailure(failure) {
    if (failure === null)
        return 'unknown failure';
    const exit = failure.exit_code !== null ? ` (exit ${failure.exit_code})` : '';
    return `'${failure.command}' ${failure.outcome}${exit}: ${failure.stderr_head}`;
}
/**
 * `Finding.tool` → the name `deps_audit`'s OWN `missing_tools` array uses
 * for it, when `deps_audit` is even capable of re-checking that tool at all
 * (task-7-review.md I5). `'trivy'` matches directly. `'npm-audit'`
 * (`NPM_AUDIT_TOOL_NAME`, scannerParsers/npmAudit.ts) does NOT: `deps_audit`
 * names the COMMAND it ran ('npm') in `missing_tools`, a different string
 * for the same scanner — a literal `.includes('npm-audit')` would never
 * match even when npm audit genuinely did not run. `'wpscan'` maps to
 * `null`: `deps_audit` never attempts wpscan at all (design §10's own
 * documented gap), so it can never report it as either present or missing —
 * `missing_tools` simply never mentions it either way, and treating "never
 * mentioned" as "ran fine" would be the exact false positive this map
 * exists to close, for a scanner `deps_audit` does not even know exists.
 */
const DEPS_AUDIT_MISSING_TOOLS_NAME = {
    trivy: 'trivy',
    'npm-audit': 'npm',
    wpscan: null,
};
/**
 * Re-runs the group's originating scanner(s) inside the already-fixed
 * worktree (design §4.1) via the same MCP tool that would have produced
 * this group's findings in the first place: `scan_sast` for `semgrep`,
 * `deps_audit` for `deps`.
 *
 * **Which scanner(s) must have run is derived from the group's OWN target
 * findings' `tool` values, never a single hardcoded guess
 * (task-7-review.md I5).** A `deps` group's targets can come from trivy,
 * npm-audit OR wpscan (`DEP_SCANNER_TOOLS`, `../fixpr/candidates.ts`) — a
 * group covering an npm-audit-sourced CVE re-verified only by checking
 * whether TRIVY ran would trust an empty after-set even when the specific
 * scanner that found that CVE never ran at all, and a wpscan-sourced target
 * would be judged resolved on literally every run, since `deps_audit` never
 * attempts wpscan in the first place. `targetFindings` is this group's own
 * `findingsForGroup` result, not `group` itself, which carries no `Finding`
 * objects (only fingerprints).
 *
 * A required scanner that did not run is treated as a verification failure,
 * not as "0 findings": `scan_sast`/`deps_audit` both report `ok: true` with
 * an EMPTY finding set when a scanner could not run at all (consistent with
 * every other scan tool in this repo — a coverage gap, not a clean bill of
 * health). Trusting that empty set at face value here would read "the
 * scanner didn't run" as "nothing is wrong any more" — exactly the false
 * positive the scan differential exists to prevent, in a new costume.
 */
async function rescanAfterFix(group, targetFindings, worktreePath, ctx) {
    const toolName = group.source === 'semgrep' ? 'scan_sast' : 'deps_audit';
    const subTool = TOOLS.find((t) => t.name === toolName);
    if (subTool === undefined) {
        return { ok: false, reason: `the '${toolName}' tool is not registered` };
    }
    const result = await subTool.handler({ project_path: worktreePath }, ctx);
    if (!result.ok) {
        return { ok: false, reason: `${toolName} failed: ${result.error.message}` };
    }
    const r = result;
    if (typeof r.scan_id !== 'string') {
        return { ok: false, reason: `${toolName} returned no scan_id` };
    }
    const missingTools = Array.isArray(r.missing_tools) ? r.missing_tools : [];
    const requiredTools = new Set(targetFindings.map((f) => f.tool));
    const uncheckable = [...requiredTools].filter((tool) => scannerCouldNotBeVerified(group.source, tool, missingTools));
    if (uncheckable.length > 0) {
        return {
            ok: false,
            reason: `${uncheckable.join(', ')} did not run inside the worktree (reported missing, or ${toolName} ` +
                `does not cover it at all) — cannot verify`,
        };
    }
    return { ok: true, scanId: r.scan_id, findings: ctx.storage.findings.listByScan(r.scan_id) };
}
function scannerCouldNotBeVerified(source, tool, missingTools) {
    if (source === 'semgrep') {
        // buildSemgrepGroup (../fixpr/candidates.js) only ever pairs
        // tool === 'semgrep' findings, so `tool` here is always 'semgrep' in
        // practice — checked by name anyway rather than assumed.
        return tool === 'semgrep' && missingTools.includes('semgrep');
    }
    const missingToolsName = DEPS_AUDIT_MISSING_TOOLS_NAME[tool];
    // Not one of DEP_SCANNER_TOOLS (../fixpr/candidates.js) — unreachable
    // today, since buildGroups only ever pairs those three tools into a
    // `deps` group, but permissive rather than blocking on a tool this
    // module has no more precise information about.
    if (missingToolsName === undefined)
        return false;
    if (missingToolsName === null)
        return true; // deps_audit can never check this one (wpscan)
    return missingTools.includes(missingToolsName);
}
function buildPrTitle(group, findingCount) {
    const noun = group.source === 'deps' ? `${group.key} dependency` : 'Semgrep';
    const plural = findingCount === 1 ? '' : 's';
    return `dev-guardian: automated ${noun} fix (${findingCount} finding${plural})`;
}
/**
 * States exactly what design §6 requires: the findings covered, the exact
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