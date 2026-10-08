/**
 * The planner — pure: the open set's findings, the latest surface snapshot
 * and the limits in, the tasks out. No I/O, no clock, no storage; the tool
 * (`tools/llmScanStart.ts`) reads the inputs and persists the result.
 *
 *   - verify: one task per eligible finding — one with a file and a line;
 *     every other finding is `not_eligible`, with the reason (EC-1).
 *   - hunt: one task per group of at most {@link MAX_ROUTES_PER_HUNT_TASK}
 *     routes of the same handler file, plus one cross-cutting task
 *     (US-2.AC-1). With no entry points at all, tasks per group of code
 *     files, and the plan says so (US-2.AC-2).
 *   - nothing at all to plan: an empty plan with the reason (EC-3), never a
 *     clean one.
 *
 * Task ids are sequential (`t-0001`, …).
 */
import { isAbsolute, relative } from 'node:path';
/** US-2.AC-1 */
export const MAX_ROUTES_PER_HUNT_TASK = 5;
/**
 * Reason prefix of a finding left out only because the plan is full. Unlike
 * the EC-1 reasons (no file, no line, outside the project), these could have
 * been verified: the report counts them as missing, never as full coverage.
 */
export const OVER_LIMIT_REASON_PREFIX = "over the plan's max_tasks limit";
/** Files per task when the hunt has no entry points and goes by groups of code files (US-2.AC-2). */
const FILES_PER_GROUP = 5;
/** Brief tokens assumed per task kind when the caller has no better estimate: below the 8 000 P95 limit. */
export const DEFAULT_BRIEF_TOKENS = { verify: 2_000, hunt: 3_000, crosscut: 2_500 };
/** The project-relative POSIX path of `file`, or null when it lies outside the project. */
function relativize(file, projectPath) {
    const rel = isAbsolute(file) ? relative(projectPath, file) : file;
    const posix = rel.replace(/\\/g, '/');
    if (posix === '' || posix === '..' || posix.startsWith('../') || isAbsolute(posix) || /^[A-Za-z]:/.test(posix))
        return null;
    return posix.replace(/^\.\//, '');
}
/**
 * The stable name of one entry point — what a hunt task's
 * `target.entry_points`, `set_aside` and the report's accounting all use.
 * Method, resolved path and the handler's `file:line`, so two routes never share one.
 */
export function entryPointId(route, projectPath) {
    const where = relativize(route.file, projectPath) ?? route.file.replace(/\\/g, '/');
    return `${route.method} ${route.path_resolved} (${where}:${String(route.line)})`;
}
function verifyDrafts(input) {
    const drafts = [];
    const notEligible = [];
    const seen = new Set();
    for (const f of input.findings) {
        if (seen.has(f.fingerprint))
            continue;
        seen.add(f.fingerprint);
        if (f.file_path === undefined || f.file_path === '') {
            notEligible.push({ fingerprint: f.fingerprint, reason: 'no file: nothing to read and cite (dependency, configuration)' });
            continue;
        }
        if (f.line_start === undefined || !Number.isInteger(f.line_start) || f.line_start < 1) {
            notEligible.push({ fingerprint: f.fingerprint, reason: 'no line: the finding names a file but not where' });
            continue;
        }
        const rel = relativize(f.file_path, input.project_path);
        if (rel === null) {
            notEligible.push({ fingerprint: f.fingerprint, reason: 'the file is outside the project' });
            continue;
        }
        drafts.push({ kind: 'verify', target: { fingerprint: f.fingerprint, files: [rel] } });
    }
    return { drafts, notEligible };
}
function huntDrafts(input, notes, setAside) {
    const byFile = new Map();
    const seen = new Set();
    for (const route of input.surface?.snapshot.routes ?? []) {
        const id = entryPointId(route, input.project_path);
        if (seen.has(id))
            continue;
        seen.add(id);
        const rel = relativize(route.file, input.project_path);
        if (rel === null) {
            setAside.push({ entry_point: id, reason: 'handler file is outside the project' });
            continue;
        }
        const list = byFile.get(rel) ?? [];
        list.push({ id, line: route.line });
        byFile.set(rel, list);
    }
    const drafts = [];
    for (const file of [...byFile.keys()].sort()) {
        const routes = (byFile.get(file) ?? []).sort((a, b) => a.line - b.line || (a.id < b.id ? -1 : 1));
        for (let i = 0; i < routes.length; i += MAX_ROUTES_PER_HUNT_TASK) {
            const entry_points = routes.slice(i, i + MAX_ROUTES_PER_HUNT_TASK).map((r) => r.id);
            drafts.push({ kind: 'hunt', target: { entry_points, files: [file] } });
        }
    }
    if (seen.size > 0)
        return drafts;
    // No entry points: say so, and go by groups of code files (US-2.AC-2).
    notes.push(input.surface === null
        ? 'No attack surface snapshot: no entry points are known, so the hunt goes by groups of code files. Coverage stays partial.'
        : 'The attack surface found no entry points: the hunt goes by groups of code files. Coverage stays partial.');
    const files = [...new Set(input.code_files)].sort();
    for (let i = 0; i < files.length; i += FILES_PER_GROUP) {
        drafts.push({ kind: 'hunt', target: { files: files.slice(i, i + FILES_PER_GROUP) } });
    }
    return drafts;
}
export function buildPlan(input) {
    const notes = [];
    const set_aside = [];
    const not_eligible = [];
    const work = [];
    if (input.modes.includes('verify')) {
        const v = verifyDrafts(input);
        work.push(...v.drafts);
        not_eligible.push(...v.notEligible);
    }
    const hunting = input.modes.includes('hunt');
    if (hunting)
        work.push(...huntDrafts(input, notes, set_aside));
    // The cross-cutting task goes with any hunt that has something to hunt in,
    // and counts against max_tasks like any other (no room: it is not planned).
    const wantsCrosscut = hunting && work.some((d) => d.kind === 'hunt');
    const crosscut = wantsCrosscut && input.limits.max_tasks >= 1 ? { kind: 'crosscut', target: { files: [] } } : null;
    // max_tasks: what does not fit is left out and named, never silently dropped.
    const room = Math.max(0, input.limits.max_tasks - (crosscut === null ? 0 : 1));
    const kept = work.slice(0, room);
    const reason = `${OVER_LIMIT_REASON_PREFIX} (${String(input.limits.max_tasks)})`;
    for (const d of work.slice(room)) {
        if (d.target.fingerprint !== undefined)
            not_eligible.push({ fingerprint: d.target.fingerprint, reason });
        else if (d.target.entry_points !== undefined)
            for (const ep of d.target.entry_points)
                set_aside.push({ entry_point: ep, reason });
        else
            set_aside.push({ entry_point: `files: ${d.target.files.join(', ')}`, reason });
    }
    if (crosscut !== null)
        kept.push(crosscut);
    if (work.length > room)
        notes.push(`${String(work.length - room)} planned task(s) did not fit in max_tasks (${String(input.limits.max_tasks)}); coverage will be partial.`);
    const tasks = kept.map((d, i) => ({ task_id: `t-${String(i + 1).padStart(4, '0')}`, ...d }));
    const briefTokens = (t) => (input.estimate_brief ?? ((x) => DEFAULT_BRIEF_TOKENS[x.kind]))(t);
    const brief_tokens = tasks.reduce((sum, t) => sum + briefTokens(t), 0);
    const estimate = {
        tasks: tasks.length,
        brief_tokens,
        total_tokens: brief_tokens + tasks.length * input.limits.per_task_overhead,
        assumptions: `brief tokens per task (about 4 characters per token) plus ${String(input.limits.per_task_overhead)} tokens of fixed host cost per task; the host's real use is not known to the server`,
    };
    let nothing_to_plan = null;
    if (tasks.length === 0 && work.length > 0) {
        nothing_to_plan = `${reason}: no task fits`;
    }
    else if (tasks.length === 0) {
        nothing_to_plan = hunting
            ? 'No entry points, no code files and no eligible findings: there is nothing to hunt in or to verify.'
            : 'No finding is eligible for verification (each needs a file and a line).';
    }
    return { tasks, not_eligible, set_aside, estimate, notes, nothing_to_plan };
}
//# sourceMappingURL=plan.js.map