/**
 * What the three LLM-scan tools do, apart from their MCP shape: make a plan,
 * report on it, lease its next task, and take an answer for a leased task.
 * The tools (`tools/llmScan{Start,Task,Submit}.ts`) only parse their input and
 * call these, so sampling (a later task) can drive the same lease and the
 * same submission without a second copy of either.
 *
 * Every state change of a task goes through the guarded primitives of
 * `storage/llmScanRepo.ts` (D-2): there is no unconditional update here.
 * Time is read once per call as an ISO string with milliseconds and `Z` — the
 * repository compares instants as text.
 *
 * Nothing here calls a model, and nothing stores code: briefs are rebuilt
 * from file and line when a task is handed out, and answers are validated
 * against the disk before anything is written (`submission.ts`).
 */
import { createHash, randomUUID } from 'node:crypto';
import { posix, relative, isAbsolute } from 'node:path';
import { assignIdentities, makeSourceReader } from '../fingerprint/findingIdentity.js';
import { openSetForProject } from '../history/openSet.js';
import { readProjectBytes, readProjectText } from '../platform/projectFs.js';
import { listProjectFiles } from '../runners/projectFiles.js';
import { makeFinding } from '../runners/scannerParsers/index.js';
import { computeTreeHash } from '../treeHash/computeTreeHash.js';
import { CURRENT_PROMPT_VERSION, randomBoundary, renderBrief, responseSchema } from './briefs.js';
import { huntSeverity } from './classes.js';
import { buildPlan, DEFAULT_BRIEF_TOKENS, entryPointId, OVER_LIMIT_REASON_PREFIX } from './plan.js';
import { computeReport } from './report.js';
import { toFindingValidation, validateHuntSubmission, validateVerifySubmission } from './submission.js';
import { LLM_SCAN_DEFAULTS, } from './types.js';
export const fail = (code, message, retry_with) => ({
    ok: false,
    error: { code, message, ...(retry_with !== undefined ? { retry_with } : {}) },
});
export const nowIso = () => new Date().toISOString();
/** US-1.AC-4: the third invalid submission closes the task. */
export const MAX_INVALID_SUBMISSIONS = 3;
/**
 * The planner's own ceiling on tasks. `max_tasks` is what a scan may DELIVER
 * (US-4.AC-2: delivery stops, and the undelivered tasks are named); planning
 * stops only here, so a plan is never silently cut below what the user asked
 * to be told about.
 */
export const MAX_PLANNED_TASKS = 1_000;
/** A brief is held to this, under the 25 000-token cap a whole response has: JSON escaping and the rest of the response need room. */
const HOST_BRIEF_MAX_TOKENS = 20_000;
/** Names listed in one response (not-eligible findings, undelivered tasks); the count is always given. */
const MAX_LISTED = 100;
/** Distinct code files a hunt without entry points walks. */
const MAX_FALLBACK_CODE_FILES = 2_000;
const CODE_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.go', '.java', '.cs', '.php', '.rb', '.rs'];
const isOverLimit = (reason) => reason.startsWith(OVER_LIMIT_REASON_PREFIX);
function listed(items) {
    return { items: items.slice(0, MAX_LISTED), total: items.length };
}
function relPosix(project, file) {
    const rel = (isAbsolute(file) ? relative(project, file) : file).replace(/\\/g, '/');
    return rel === '' || rel.startsWith('../') || rel === '..' || isAbsolute(rel) ? null : rel.replace(/^\.\//, '');
}
/** sha256 of a project file's bytes, read through the contained reader; a file that cannot be read has a fixed hash of its own. */
function fileHash(project, rel) {
    const read = readProjectBytes(project, rel);
    return read.status === 'ok' ? createHash('sha256').update(read.bytes).digest('hex') : 'unreadable';
}
const hashesOf = (project, files) => Object.fromEntries(files.map((f) => [f, fileHash(project, f)]));
/** US-1.AC-9: a file of the target changed since the plan was made. */
function isStale(project, task) {
    return Object.entries(task.file_hashes).some(([file, hash]) => fileHash(project, file) !== hash);
}
// ---- loading -----------------------------------------------------------
/** The plan, or why not: unknown, unreadable (corrupt row), or abandoned by retention. */
export function loadPlan(storage, planId, opts = {}) {
    const plan = storage.llmScan.getPlan(planId);
    if (plan === null) {
        return storage.llmScan.planRowExists(planId)
            ? fail('plan_corrupt', `The stored plan ${planId} cannot be read (its row is damaged); it cannot be resumed. Start a new plan.`)
            : fail('not_found', `No LLM scan plan with id ${planId}.`);
    }
    if (plan.status === 'abandoned' && opts.allowAbandoned !== true) {
        return fail('plan_abandoned', `Plan ${planId} was abandoned (no activity for a long time). Start a new plan with llm_scan_start.`, { plan_id: planId });
    }
    return { ok: true, plan };
}
/** `open` -> `complete` once every task is closed. Returns the plan as it now stands. */
export function settlePlan(storage, plan) {
    if (plan.status !== 'open')
        return plan;
    const tasks = storage.llmScan.listTasks(plan.id);
    if (tasks.length > 0 && tasks.every((t) => t.status === 'closed')) {
        storage.llmScan.updatePlan(plan.id, 'complete', nowIso());
        return storage.llmScan.getPlan(plan.id) ?? plan;
    }
    return plan;
}
export function reportOf(storage, plan) {
    return computeReport(plan, storage.llmScan.listTasks(plan.id));
}
/** D-4: `confirm` authorises the start only; delivery still stops at max_estimated_tokens. */
export const tokenLimitNote = (n) => `About ${String(n)} task(s) still to deliver fit under max_estimated_tokens by the plan's estimate; delivery stops there with limit_reached (the real brief sizes decide, so it can differ a little). To cover the whole plan, start again with a larger max_estimated_tokens.`;
/**
 * A projection, not a promise: how many of the tasks not yet delivered, in delivery order, fit in what is
 * left of the budget (max_estimated_tokens minus what `limitReason` counts as spent) and of max_tasks —
 * with the default brief size per kind, since their briefs are not rendered yet, and the cross-cutting
 * task's reserved slot honoured.
 */
function deliverableWithinTokenLimit(plan, tasks) {
    const { limits } = plan;
    const delivered = tasks.filter((t) => t.delivered_at !== null);
    let spent = delivered.reduce((sum, t) => sum + Math.ceil((t.brief_chars ?? 0) / 4) + limits.per_task_overhead, 0);
    const slots = limits.max_tasks - delivered.filter((t) => t.target.origin_task_id === undefined).length;
    const pending = tasks.filter((t) => t.delivered_at === null && t.status !== 'closed');
    const crosscutPending = pending.some((t) => t.kind === 'crosscut');
    let counted = 0;
    let n = 0;
    for (const t of pending) {
        const exempt = t.target.origin_task_id !== undefined;
        if (!exempt && counted >= slots - (t.kind !== 'crosscut' && crosscutPending ? 1 : 0)) {
            if (t.kind !== 'crosscut' && crosscutPending)
                continue; // look on, to the cross-cutting task
            break;
        }
        spent += DEFAULT_BRIEF_TOKENS[t.kind] + limits.per_task_overhead;
        if (spent > limits.max_estimated_tokens)
            break;
        if (!exempt)
            counted += 1;
        n += 1;
    }
    return n;
}
/** The fields that tell a user what a plan above the token limit will deliver, about. */
function tokenLimitFields(plan, tasks) {
    if (plan.estimate.total_tokens <= plan.limits.max_estimated_tokens)
        return {};
    const n = deliverableWithinTokenLimit(plan, tasks);
    return { deliverable_within_token_limit: n, token_limit_note: tokenLimitNote(n) };
}
const needsConfirm = (plan) => !plan.confirmed && plan.estimate.total_tokens > plan.limits.max_estimated_tokens;
const RECIPE = {
    loop: [
        'llm_scan_task { plan_id } -> one task: task_id, lease_token, brief, response_schema. Repeat for the next one (tasks may be leased in parallel).',
        'Run the brief in a FRESH context — a subagent with its own context, one per task — and take its JSON answer. The brief says what the subagent may read.',
        'llm_scan_submit { plan_id, task_id, lease_token, independence, payload } with that answer. An invalid answer is refused with the reason: fix it and submit again (up to two more tries).',
        'Until llm_scan_task answers { done: true, report }. llm_scan_start { plan_id } gives the report at any time.',
    ],
    independence: "'subagent' when a fresh context ran the brief; 'same_context' when you ran it yourself (shown, and never used to demote or confirm).",
    lease: `A leased task is yours for ${String(LLM_SCAN_DEFAULTS.lease_minutes)} minutes; after that it goes to whoever asks next.`,
};
/** The scanner findings a verify plan checks: named fingerprints, one scan, or the project's open set (hunt findings are checked by their own tasks). */
function findingsToVerify(storage, input) {
    if (input.fingerprints !== undefined) {
        const found = [];
        const unknown = [];
        for (const fp of input.fingerprints) {
            const hit = storage.findings.findLatestInProject(input.project, fp);
            if (hit === null)
                unknown.push(fp);
            else
                found.push(hit.finding);
        }
        return { ok: true, findings: found, unknown };
    }
    if (input.scan_id !== undefined) {
        const scan = storage.scans.getById(input.scan_id);
        if (scan === null || scan.project_path !== input.project)
            return fail('unknown_scan_id', `No scan ${input.scan_id} for this project.`);
        return { ok: true, findings: storage.findings.listByScan(input.scan_id).filter((f) => f.tool !== 'llm-hunt'), unknown: [] };
    }
    return { ok: true, findings: openSetForProject(storage, input.project).findings.filter((f) => f.tool !== 'llm-hunt'), unknown: [] };
}
/** US-1.AC-1, US-2.AC-1: the plan and its tasks, estimated and stored before anything is handed out. */
export async function startPlan(storage, input) {
    const { project, modes } = input;
    const now = nowIso();
    const active = storage.llmScan.listActivePlanIds(project, now);
    if (active.length >= LLM_SCAN_DEFAULTS.max_open_plans) {
        return fail('too_many_open_plans', `This project already has ${String(active.length)} open LLM scan plans (the limit is ${String(LLM_SCAN_DEFAULTS.max_open_plans)}). Finish one, or read its report with llm_scan_start { plan_id }: ${active.join(', ')}.`, { open_plans: active });
    }
    const treeHash = await computeTreeHash(project);
    const hunting = modes.includes('hunt');
    const persisted = hunting ? storage.surface.getLatestForProject(project) : null;
    if (hunting && (persisted === null || persisted.tree_hash !== treeHash)) {
        return fail('needs_surface', persisted === null
            ? 'The hunt starts from the attack surface, and this project has no snapshot. Run map_attack_surface first.'
            : 'The latest attack surface snapshot is of an older tree than the project now is. Run map_attack_surface again first.');
    }
    let findings = [];
    const unknown = [];
    if (modes.includes('verify')) {
        const chosen = findingsToVerify(storage, input);
        if (!chosen.ok)
            return chosen;
        findings = chosen.findings;
        unknown.push(...chosen.unknown);
    }
    const codeFiles = hunting
        ? listProjectFiles(project).filter((f) => CODE_EXTENSIONS.some((e) => f.toLowerCase().endsWith(e))).slice(0, MAX_FALLBACK_CODE_FILES)
        : [];
    const plan = buildPlan({
        project_path: project,
        modes,
        findings,
        surface: persisted === null ? null : { id: persisted.id, snapshot: persisted.snapshot },
        code_files: codeFiles,
        limits: { ...input.limits, max_tasks: MAX_PLANNED_TASKS },
    });
    const notEligible = [
        ...plan.not_eligible.map((n) => (isOverLimit(n.reason) ? { ...n, overflow: true } : n)),
        ...unknown.map((fingerprint) => ({ fingerprint, reason: 'not found among this project\'s stored findings' })),
    ];
    const setAside = plan.set_aside.map((s) => (isOverLimit(s.reason) ? { ...s, overflow: true } : s));
    if (plan.nothing_to_plan !== null) {
        return fail('nothing_to_plan', plan.nothing_to_plan, { not_eligible: listed(notEligible).items });
    }
    const planId = randomUUID();
    const scanId = randomUUID();
    // Delivery order is the planner's: verifications, entry-point hunts, the cross-cutting task last. The
    // cross-cutting task keeps a slot when max_tasks cuts (see `limitReason`), so it is still delivered (D-3).
    const ordered = plan.tasks;
    // D-3: the estimate that decides the confirm gate is the DELIVERABLE tasks' — max_tasks of them.
    const crosscuts = ordered.filter((t) => t.kind === 'crosscut');
    const deliverable = ordered.length <= input.limits.max_tasks
        ? ordered
        : [...ordered.filter((t) => t.kind !== 'crosscut').slice(0, Math.max(0, input.limits.max_tasks - crosscuts.length)), ...crosscuts].slice(0, input.limits.max_tasks);
    const deliverableBrief = deliverable.reduce((sum, t) => sum + DEFAULT_BRIEF_TOKENS[t.kind], 0);
    const estimate = {
        tasks: deliverable.length,
        brief_tokens: deliverableBrief,
        total_tokens: deliverableBrief + deliverable.length * input.limits.per_task_overhead,
        assumptions: `${plan.estimate.assumptions}; counted over the ${String(deliverable.length)} task(s) that can be delivered (max_tasks ${String(input.limits.max_tasks)}), in delivery order`,
    };
    const tasks = ordered.map((t) => ({
        plan_id: planId,
        task_id: t.task_id,
        kind: t.kind,
        target: t.target,
        status: 'open',
        lease_token: null,
        lease_expires_at: null,
        attempts: 0,
        // Only a verdict can go stale (US-1.AC-9).
        file_hashes: t.kind === 'verify' ? hashesOf(project, t.target.files) : {},
        brief_chars: null,
        response_chars: null,
        independence: null,
        result: null,
        closed_reason: null,
        delivered_at: null,
        closed_at: null,
    }));
    const stored = {
        id: planId,
        project_path: project,
        scan_id: scanId,
        modes,
        prompt_version: CURRENT_PROMPT_VERSION,
        tree_hash: treeHash,
        surface_snapshot_id: persisted?.id ?? null,
        limits: input.limits,
        estimate,
        confirmed: input.confirm,
        status: 'open',
        not_eligible: notEligible,
        set_aside: setAside,
        created_at: now,
        updated_at: now,
    };
    // The plan's scan holds the hunt's findings (tool `llm-hunt`); it is
    // completed at once, and the findings are added as hunt tasks close.
    storage.rawHandle().transaction(() => {
        storage.scans.insert({ scan_id: scanId, scan_type: 'llm_scan', project_path: project, tree_hash: treeHash, meta: { plan_id: planId, modes } });
        storage.scans.finalize({
            scan_id: scanId,
            status: 'completed',
            tools_run: hunting ? [{ name: 'llm-hunt', status: 'ok' }] : [],
            missing_tools: [],
        });
        storage.llmScan.insertPlan(stored, tasks);
    })();
    const byKind = {};
    for (const t of tasks)
        byKind[t.kind] = (byKind[t.kind] ?? 0) + 1;
    const ne = listed(notEligible);
    const sa = listed(setAside);
    return {
        ok: true,
        plan_id: planId,
        scan_id: scanId,
        tasks_total: tasks.length,
        by_kind: byKind,
        not_eligible: ne.items,
        not_eligible_total: ne.total,
        set_aside: sa.items,
        set_aside_total: sa.total,
        estimate,
        deliverable_tasks: deliverable.length,
        beyond_max_tasks: tasks.length - deliverable.length,
        needs_confirm: needsConfirm(stored),
        ...tokenLimitFields(stored, tasks),
        ...(needsConfirm(stored) ? { confirm_with: 'llm_scan_start { plan_id, confirm: true }' } : {}),
        notes: plan.notes,
        recipe: RECIPE,
        prompt_version: CURRENT_PROMPT_VERSION,
    };
}
/** The plan's status and report (`llm_scan_start { plan_id }`), confirming it first when asked. */
export function planStatus(storage, planId, project, confirm) {
    const loaded = loadPlan(storage, planId);
    if (!loaded.ok)
        return loaded;
    if (project !== null && loaded.plan.project_path !== project)
        return fail('not_found', `No LLM scan plan with id ${planId} for this project.`);
    if (confirm && loaded.plan.status === 'open')
        storage.llmScan.confirmPlan(planId, nowIso());
    const plan = settlePlan(storage, storage.llmScan.getPlan(planId) ?? loaded.plan);
    return {
        ok: true,
        plan_id: plan.id,
        scan_id: plan.scan_id,
        status: plan.status,
        modes: plan.modes,
        limits: plan.limits,
        estimate: plan.estimate,
        needs_confirm: needsConfirm(plan),
        ...tokenLimitFields(plan, storage.llmScan.listTasks(plan.id)),
        prompt_version: plan.prompt_version,
        report: reportOf(storage, plan),
    };
}
// ---- leasing -----------------------------------------------------------
const isLeasable = (t, now) => t.status === 'open' || (t.status === 'leased' && t.lease_expires_at !== null && t.lease_expires_at <= now);
function briefFor(storage, plan, task) {
    const root = plan.project_path;
    const base = { root, reader: readProjectText, boundary: randomBoundary, prompt_version: plan.prompt_version, max_tokens: HOST_BRIEF_MAX_TOKENS };
    if (task.kind === 'verify') {
        const fp = task.target.fingerprint;
        const hit = fp === undefined ? null : storage.findings.findLatestInProject(root, fp);
        return hit === null ? null : renderBrief(task, { ...base, finding: hit.finding }).text;
    }
    const ids = new Set(task.target.entry_points ?? []);
    const surface = plan.surface_snapshot_id === null ? null : storage.surface.getById(plan.surface_snapshot_id);
    const routes = (surface?.snapshot.routes ?? []).filter((r) => ids.has(entryPointId(r, root)));
    const files = new Set(task.target.files);
    const known = files.size === 0 ? [] : openSetForProject(storage, root).findings.filter((f) => {
        const rel = f.file_path === undefined ? null : relPosix(root, f.file_path);
        return f.tool !== 'llm-hunt' && rel !== null && files.has(rel);
    });
    return renderBrief(task, { ...base, entry_points: routes, scanner_findings: known }).text;
}
/** Delivery stops at the plan's limits (US-4.AC-2): tasks, and estimated tokens. */
function limitReason(plan, tasks, next, briefTokens) {
    const delivered = tasks.filter((t) => t.delivered_at !== null);
    // The verify tasks of a hunt's findings are outside max_tasks, like they are outside the plan's count.
    const counted = delivered.filter((t) => t.target.origin_task_id === undefined).length;
    // The cross-cutting task keeps its slot: the tasks before it stop one short of max_tasks while it is still undelivered (D-3).
    const reserved = next.kind !== 'crosscut' && tasks.some((t) => t.kind === 'crosscut' && t.delivered_at === null && t.status !== 'closed') ? 1 : 0;
    if (next.target.origin_task_id === undefined && counted >= plan.limits.max_tasks - reserved) {
        return `the task limit (max_tasks ${String(plan.limits.max_tasks)}) is reached`;
    }
    const spent = delivered.reduce((sum, t) => sum + Math.ceil((t.brief_chars ?? 0) / 4) + plan.limits.per_task_overhead, 0);
    if (spent + briefTokens + plan.limits.per_task_overhead > plan.limits.max_estimated_tokens) {
        return `the estimated-token limit (max_estimated_tokens ${String(plan.limits.max_estimated_tokens)}) is reached`;
    }
    return null;
}
/** The next task of the plan, or its end, or why none can be handed out. */
export function leaseNext(storage, planId, only = {}) {
    const loaded = loadPlan(storage, planId);
    if (!loaded.ok)
        return loaded;
    let plan = loaded.plan;
    const repo = storage.llmScan;
    const done = () => {
        plan = settlePlan(storage, plan);
        return { ok: true, done: true, report: reportOf(storage, plan) };
    };
    if (plan.status === 'complete')
        return done();
    if (needsConfirm(plan)) {
        return fail('needs_confirm', `The plan's estimate (${String(plan.estimate.total_tokens)} tokens) is above the limit (${String(plan.limits.max_estimated_tokens)}). Confirm with llm_scan_start { plan_id: "${plan.id}", confirm: true } before any task is handed out. ${tokenLimitNote(deliverableWithinTokenLimit(plan, repo.listTasks(plan.id)))}`, { plan_id: plan.id, confirm: true, ...tokenLimitFields(plan, repo.listTasks(plan.id)) });
    }
    const now = nowIso();
    const tasks = repo.listTasks(plan.id);
    const candidates = tasks.filter((t) => isLeasable(t, now) && (only.kinds === undefined || only.kinds.includes(t.kind)));
    for (const task of candidates) {
        if (task.kind === 'verify' && isStale(plan.project_path, task)) {
            repo.closeUnleased(plan.id, task.task_id, 'stale', now);
            continue;
        }
        const brief = briefFor(storage, plan, task);
        if (brief === null) {
            // The finding this task checks is gone from the database (retention): nothing to hand out.
            repo.closeUnleased(plan.id, task.task_id, 'stale', now);
            continue;
        }
        if (task.delivered_at === null) {
            const reason = limitReason(plan, tasks, task, Math.ceil(brief.length / 4));
            if (reason !== null) {
                // The cross-cutting task keeps its slot (D-3): look past the tasks that no longer fit, to it.
                const crosscutLeft = task.kind !== 'crosscut' && candidates.some((c) => c.kind === 'crosscut' && c.delivered_at === null);
                if (crosscutLeft)
                    continue;
                return stopDelivery(storage, plan, candidates, reason, now);
            }
        }
        const token = randomUUID();
        const expires = new Date(Date.parse(now) + LLM_SCAN_DEFAULTS.lease_minutes * 60_000).toISOString();
        if (!repo.claimTask(plan.id, task.task_id, token, expires, now))
            continue; // another server leased it first
        repo.recordBriefChars(plan.id, task.task_id, token, brief.length);
        return {
            ok: true,
            task_id: task.task_id,
            kind: task.kind,
            lease_token: token,
            lease_expires_at: expires,
            brief,
            response_schema: responseSchema(task.kind),
            attempts_left: Math.max(0, MAX_INVALID_SUBMISSIONS - task.attempts),
        };
    }
    const after = repo.listTasks(plan.id);
    if (after.every((t) => t.status === 'closed'))
        return done();
    return {
        ok: true,
        done: false,
        waiting: true,
        message: 'Every task still to do is leased to someone. Answer yours, or ask again once a lease expires.',
        leased: after.filter((t) => t.status === 'leased').map((t) => ({ task_id: t.task_id, lease_expires_at: t.lease_expires_at })).slice(0, MAX_LISTED),
    };
}
/** US-4.AC-2: close what was never delivered, and name it. */
function stopDelivery(storage, plan, candidates, reason, now) {
    const undelivered = candidates.filter((t) => t.delivered_at === null).map((t) => t.task_id);
    for (const id of undelivered)
        storage.llmScan.closeUnleased(plan.id, id, 'not_delivered', now);
    settlePlan(storage, plan);
    const named = listed(undelivered);
    return fail('limit_reached', `Delivery stopped: ${reason}. Coverage is partial. ${String(named.total)} task(s) were not delivered: ${named.items.join(', ')}${named.total > named.items.length ? ', …' : ''}.`, { plan_id: plan.id, undelivered: named.items, undelivered_total: named.total });
}
const sizeOf = (payload) => {
    try {
        return JSON.stringify(payload)?.length ?? 0;
    }
    catch {
        return 0;
    }
};
function progressOf(storage, plan) {
    const r = reportOf(storage, plan);
    return { coverage: r.coverage, tasks: r.tasks, missing_total: r.missing.length };
}
/** A guarded write found nothing to change: the task is closed, or someone else holds it. */
function lostRace(storage, input) {
    const t = storage.llmScan.getTask(input.plan_id, input.task_id);
    return t?.status === 'closed' ? fail('already_closed', `Task ${input.task_id} is already closed.`) : fail('bad_lease', 'The lease token does not hold this task.');
}
function huntFindingRow(f) {
    return makeFinding({
        tool: 'llm-hunt',
        rule_id: f.class,
        severity: huntSeverity(f.class),
        category: 'security',
        title: f.title,
        message: `Attacker: ${f.attacker} Evidence: ${f.evidence}`,
        file_path: posix.normalize(f.file.replace(/\\/g, '/')),
        line_start: f.line,
    });
}
/** Takes an answer for a leased task: validated, then stored — and, for a hunt, its findings and their verify tasks, in ONE transaction. */
export function submitAnswer(storage, input) {
    const loaded = loadPlan(storage, input.plan_id);
    if (!loaded.ok)
        return loaded;
    const plan = loaded.plan;
    const repo = storage.llmScan;
    const task = repo.getTask(plan.id, input.task_id);
    // Plan, task and token must all match: no clue is given about which one did not.
    if (task === null || task.lease_token === null || task.lease_token !== input.lease_token) {
        return fail('bad_lease', 'The lease token does not hold this task.');
    }
    if (task.status === 'closed')
        return fail('already_closed', `Task ${task.task_id} is already closed; its first answer stands.`);
    if (task.status !== 'leased')
        return fail('bad_lease', 'The lease token does not hold this task.');
    const ctx = { root: plan.project_path, reader: readProjectText };
    const responseChars = sizeOf(input.payload);
    const check = task.kind === 'verify' ? validateVerifySubmission(input.payload, ctx) : validateHuntSubmission(input.payload, ctx);
    const now = nowIso();
    if (!check.ok) {
        if (check.code === 'too_large')
            return fail('too_large', check.errors.map((e) => e.problem).join('; '));
        return refuseInvalid(storage, plan, task, input, check.errors, responseChars, now);
    }
    try {
        // The kind picked the validator above; the value's shape follows it.
        if ('verdict' in check.value)
            return acceptVerdict(storage, plan, task, input, check.value, responseChars, now);
        return acceptHunt(storage, plan, task, input, check.value, check.rejected, responseChars, now);
    }
    catch {
        // The transaction rolled back: the task is still leased and nothing was half-written.
        return fail('store_failed', 'The answer could not be stored; nothing was changed and the task is still yours. Submit it again.');
    }
}
function refuseInvalid(storage, plan, task, input, errors, responseChars, now) {
    const repo = storage.llmScan;
    const attempts = repo.recordInvalidSubmission(plan.id, task.task_id, input.lease_token);
    if (attempts === null)
        return lostRace(storage, input);
    const left = Math.max(0, MAX_INVALID_SUBMISSIONS - attempts);
    if (left > 0)
        return { ok: true, accepted: false, errors, attempts_left: left };
    // US-1.AC-4: out of tries — undetermined, with its reason.
    repo.closeTask(plan.id, task.task_id, input.lease_token, { independence: input.independence, result: null, closed_reason: 'invalid_submissions', response_chars: responseChars }, now);
    settlePlan(storage, plan);
    return { ok: true, accepted: false, errors, attempts_left: 0, closed: 'undetermined', closed_reason: 'invalid_submissions' };
}
function acceptVerdict(storage, plan, task, input, verdict, responseChars, now) {
    const repo = storage.llmScan;
    const outcome = { independence: input.independence, result: verdict, response_chars: responseChars };
    if (isStale(plan.project_path, task)) {
        // US-1.AC-9: the verdict is about code that is no longer there; it demotes nothing.
        if (!repo.closeTask(plan.id, task.task_id, input.lease_token, { ...outcome, closed_reason: 'stale' }, now))
            return lostRace(storage, input);
        const current = settlePlan(storage, plan);
        return { ok: true, accepted: true, stale: true, note: 'A file of the target changed after the plan was made: the verdict is recorded as stale and is not used.', progress: progressOf(storage, current) };
    }
    const fingerprint = task.target.fingerprint;
    const closed = storage.rawHandle().transaction(() => {
        if (!repo.closeTask(plan.id, task.task_id, input.lease_token, { ...outcome, closed_reason: 'valid' }, now))
            return false;
        if (fingerprint !== undefined) {
            storage.validations.upsert(plan.project_path, [
                toFindingValidation({
                    fingerprint,
                    verdict: verdict.verdict === 'real' ? 'exploitable' : verdict.verdict === 'not_real' ? 'not_exploitable' : 'undetermined',
                    independence: input.independence,
                    decisive_line: verdict.decisive_line,
                    reasoning: verdict.reasoning,
                    prompt_version: plan.prompt_version,
                    tree_hash: plan.tree_hash,
                    computed_at: now,
                }),
            ]);
        }
        return true;
    })();
    if (!closed)
        return lostRace(storage, input);
    return { ok: true, accepted: true, progress: progressOf(storage, settlePlan(storage, plan)) };
}
function acceptHunt(storage, plan, task, input, value, rejected, responseChars, now) {
    const repo = storage.llmScan;
    const rows = new Map(value.findings.map((f) => huntFindingRow(f)).map((r) => [r.fingerprint, r]));
    // Everything that depends on what other submissions wrote (the findings already stored, the next
    // task number) is read INSIDE the transaction: BEGIN IMMEDIATE serialises two servers on one file.
    const stored = storage.rawHandle().transaction(() => {
        const result = { entry_points_reviewed: value.entry_points_reviewed, findings: value.findings, fingerprints: [...rows.keys()] };
        if (!repo.closeTask(plan.id, task.task_id, input.lease_token, { independence: input.independence, result, closed_reason: 'valid', response_chars: responseChars }, now))
            return null;
        const known = new Set(storage.findings.listByScan(plan.scan_id).map((f) => f.fingerprint));
        const fresh = [...rows.values()].filter((f) => !known.has(f.fingerprint));
        const withIdentity = assignIdentities(fresh, { projectPath: plan.project_path, readSource: makeSourceReader(plan.project_path) });
        storage.findings.bulkInsert(withIdentity.map((f) => ({ ...f, scan_id: plan.scan_id })));
        const firstNumber = repo.nextTaskNumber(plan.id);
        // Created with the hunt's own close: a finding is never stored without the task that will check it (US-2.AC-4),
        // and these tasks are outside max_tasks.
        const verifyTasks = fresh.map((f, i) => ({
            plan_id: plan.id,
            task_id: `t-${String(firstNumber + i).padStart(4, '0')}`,
            kind: 'verify',
            target: { fingerprint: f.fingerprint, files: [f.file_path ?? ''], origin_task_id: task.task_id },
            status: 'open',
            lease_token: null,
            lease_expires_at: null,
            attempts: 0,
            file_hashes: hashesOf(plan.project_path, [f.file_path ?? '']),
            brief_chars: null,
            response_chars: null,
            independence: null,
            result: null,
            closed_reason: null,
            delivered_at: null,
            closed_at: null,
        }));
        if (verifyTasks.length > 0 && !repo.appendTasks(plan.id, verifyTasks))
            throw new Error('the plan is no longer open');
        return { stored: withIdentity.length, verify: verifyTasks.length };
    })();
    if (stored === null)
        return lostRace(storage, input);
    return {
        ok: true,
        accepted: true,
        stored: stored.stored,
        verify_tasks_created: stored.verify,
        ...(rejected.length > 0 ? { rejected } : {}),
        progress: progressOf(storage, settlePlan(storage, plan)),
    };
}
//# sourceMappingURL=service.js.map