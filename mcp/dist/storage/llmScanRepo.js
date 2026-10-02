/**
 * LLM-scan plans and tasks (migration `017_llm_scan.sql`): the plan's state
 * lives in the project's database so it survives a server restart and can be
 * resumed by `plan_id` (NFR-2, US-3.AC-4).
 *
 * Holds no code and no prompts: excerpts are rebuilt from file and line.
 *
 * Two server processes can share one database file (two hosts), so every
 * state change of a task is ONE conditional UPDATE that says what it expects
 * (D-2): `claimTask` / `claimNextTask` lease, `recordInvalidSubmission` and
 * `closeTask` answer only the holder of the lease, and nothing rewrites a
 * `closed` task. There is deliberately no unconditional `updateTask`: the
 * primitives cover every transition (lease, invalid attempt, close).
 */
/** A plan idle this long stops counting toward the open-plan limit (it stays resumable by plan_id). D-2. */
export const PLAN_INACTIVE_DAYS = 7;
/** Retention marks a plan idle this long `abandoned`; it then stops protecting its scan. D-2. */
export const PLAN_ABANDON_DAYS = 30;
const DAY_MS = 86_400_000;
/** The ISO instant `days` before `now` (ISO strings of one format compare as text). */
function daysBefore(now, days) {
    return new Date(Date.parse(now) - days * DAY_MS).toISOString();
}
/**
 * Marks `open` plans idle for more than {@link PLAN_ABANDON_DAYS} `abandoned`.
 * A free function so retention, which holds a `DB`, can call it; the repo
 * delegates. Returns how many plans changed.
 */
export function abandonStalePlans(db, now) {
    return db
        .prepare(`UPDATE llm_scan_plans SET status = 'abandoned', updated_at = @now
        WHERE status = 'open' AND last_activity_at < @cutoff`)
        .run({ now, cutoff: daysBefore(now, PLAN_ABANDON_DAYS) }).changes;
}
const PLAN_COLUMNS = `id, project_path, scan_id, modes, prompt_version, tree_hash, surface_snapshot_id,
  limits, estimate, confirmed, status, not_eligible, set_aside, created_at, updated_at, last_activity_at`;
const TASK_COLUMNS = `plan_id, task_id, kind, target, status, lease_token, lease_expires_at, attempts,
  file_hashes, brief_chars, response_chars, independence, result, closed_reason, delivered_at, closed_at`;
/** A task is leasable when open, or leased with an expired lease. `@now` is bound by the caller. */
const LEASABLE_SQL = `(status = 'open' OR (status = 'leased' AND lease_expires_at <= @now))`;
/**
 * The JSON columns are ours, but a database is a file other builds and people
 * can touch. A row whose JSON does not parse is skipped from lists and is
 * `null` from a get — it reads as absent instead of throwing through a whole
 * `llm_scan_start`, the way `validationsRepo` degrades a corrupt row.
 */
function toPlan(r) {
    try {
        return {
            id: r.id,
            project_path: r.project_path,
            scan_id: r.scan_id,
            modes: JSON.parse(r.modes),
            prompt_version: r.prompt_version,
            tree_hash: r.tree_hash,
            surface_snapshot_id: r.surface_snapshot_id,
            limits: JSON.parse(r.limits),
            estimate: JSON.parse(r.estimate),
            confirmed: r.confirmed === 1,
            status: r.status,
            not_eligible: JSON.parse(r.not_eligible),
            set_aside: JSON.parse(r.set_aside),
            created_at: r.created_at,
            updated_at: r.updated_at,
        };
    }
    catch {
        return null;
    }
}
function toTask(r) {
    try {
        return {
            ...r,
            target: JSON.parse(r.target),
            file_hashes: JSON.parse(r.file_hashes),
            result: r.result === null ? null : JSON.parse(r.result),
        };
    }
    catch {
        return null;
    }
}
function present(x) {
    return x !== null;
}
export class LlmScanRepo {
    db;
    constructor(db) {
        this.db = db;
    }
    /** The plan and all its tasks, or nothing: one transaction. Activity starts at `created_at`. */
    insertPlan(plan, tasks) {
        this.db.transaction(() => {
            this.db
                .prepare(`INSERT INTO llm_scan_plans (${PLAN_COLUMNS})
           VALUES (@id, @project_path, @scan_id, @modes, @prompt_version, @tree_hash, @surface_snapshot_id,
                   @limits, @estimate, @confirmed, @status, @not_eligible, @set_aside, @created_at, @updated_at,
                   @last_activity_at)`)
                .run({
                ...plan,
                modes: JSON.stringify(plan.modes),
                limits: JSON.stringify(plan.limits),
                estimate: JSON.stringify(plan.estimate),
                confirmed: plan.confirmed ? 1 : 0,
                not_eligible: JSON.stringify(plan.not_eligible),
                set_aside: JSON.stringify(plan.set_aside),
                last_activity_at: plan.created_at,
            });
            const insert = this.db.prepare(`INSERT INTO llm_scan_tasks (${TASK_COLUMNS})
         VALUES (@plan_id, @task_id, @kind, @target, @status, @lease_token, @lease_expires_at, @attempts,
                 @file_hashes, @brief_chars, @response_chars, @independence, @result, @closed_reason,
                 @delivered_at, @closed_at)`);
            for (const t of tasks) {
                insert.run({
                    ...t,
                    target: JSON.stringify(t.target),
                    file_hashes: JSON.stringify(t.file_hashes),
                    result: t.result === null ? null : JSON.stringify(t.result),
                });
            }
        })();
    }
    /** `null` when there is no such plan, or its row is corrupt. */
    getPlan(planId) {
        const r = this.db.prepare(`SELECT ${PLAN_COLUMNS} FROM llm_scan_plans WHERE id = ?`).get(planId);
        return r === undefined ? null : toPlan(r);
    }
    /** Plans of one project, newest first; a corrupt row is skipped. */
    listPlans(projectPath) {
        return this.db
            .prepare(`SELECT ${PLAN_COLUMNS} FROM llm_scan_plans WHERE project_path = ? ORDER BY created_at DESC, rowid DESC`)
            .all(projectPath)
            .map(toPlan)
            .filter(present);
    }
    /** `open` plans of the project with activity in the last {@link PLAN_INACTIVE_DAYS} days, newest first. */
    listActivePlanIds(projectPath, now) {
        return this.db
            .prepare(`SELECT id FROM llm_scan_plans
          WHERE project_path = ? AND status = 'open' AND last_activity_at >= ?
          ORDER BY created_at DESC, rowid DESC`)
            .all(projectPath, daysBefore(now, PLAN_INACTIVE_DAYS))
            .map((r) => r.id);
    }
    /** What the limit of open plans counts: {@link listActivePlanIds}. */
    countOpenPlans(projectPath, now) {
        return this.listActivePlanIds(projectPath, now).length;
    }
    /** Tasks of one plan, by task id; a corrupt row is skipped. */
    listTasks(planId) {
        return this.db
            .prepare(`SELECT ${TASK_COLUMNS} FROM llm_scan_tasks WHERE plan_id = ? ORDER BY task_id`)
            .all(planId)
            .map(toTask)
            .filter(present);
    }
    getTask(planId, taskId) {
        const r = this.db
            .prepare(`SELECT ${TASK_COLUMNS} FROM llm_scan_tasks WHERE plan_id = ? AND task_id = ?`)
            .get(planId, taskId);
        return r === undefined ? null : toTask(r);
    }
    /**
     * Leases one task, atomically: a single conditional UPDATE, so two server
     * processes on the same database file cannot both win (D-2). True only when
     * exactly one row changed. Bumps the plan's activity and records the first
     * delivery.
     */
    claimTask(planId, taskId, token, expiresAt, now) {
        return this.db.transaction(() => {
            const changed = this.db
                .prepare(`UPDATE llm_scan_tasks
              SET status = 'leased', lease_token = @token, lease_expires_at = @expiresAt,
                  delivered_at = COALESCE(delivered_at, @now)
            WHERE plan_id = @planId AND task_id = @taskId AND ${LEASABLE_SQL}`)
                .run({ planId, taskId, token, expiresAt, now }).changes;
            if (changed !== 1)
                return false;
            this.touchPlan(planId, now);
            return true;
        })();
    }
    /**
     * Leases the lowest-numbered leasable task of the plan, or returns null when
     * there is none. One UPDATE that picks the task in a subquery: SQLite runs
     * the statement under the write lock, so choosing and claiming cannot be
     * interleaved by another process — no retry loop is needed, and the outer
     * condition repeats the guard of {@link claimTask}.
     */
    claimNextTask(planId, token, expiresAt, now) {
        return this.db.transaction(() => {
            const changed = this.db
                .prepare(`UPDATE llm_scan_tasks
              SET status = 'leased', lease_token = @token, lease_expires_at = @expiresAt,
                  delivered_at = COALESCE(delivered_at, @now)
            WHERE plan_id = @planId AND ${LEASABLE_SQL}
              AND task_id = (SELECT task_id FROM llm_scan_tasks
                              WHERE plan_id = @planId AND ${LEASABLE_SQL}
                              ORDER BY task_id LIMIT 1)`)
                .run({ planId, token, expiresAt, now }).changes;
            if (changed !== 1)
                return null;
            this.touchPlan(planId, now);
            const row = this.db
                .prepare(`SELECT ${TASK_COLUMNS} FROM llm_scan_tasks WHERE plan_id = ? AND lease_token = ?`)
                .get(planId, token);
            return row === undefined ? null : toTask(row);
        })();
    }
    /**
     * Counts an invalid submission against a task the caller still holds
     * (`lease_token` matches, status `leased`). Returns the new attempts, or
     * null when the guard failed (the tool answers `bad_lease` / `already_closed`).
     */
    recordInvalidSubmission(planId, taskId, token) {
        const r = this.db
            .prepare(`UPDATE llm_scan_tasks SET attempts = attempts + 1
          WHERE plan_id = ? AND task_id = ? AND lease_token = ? AND status = 'leased'
          RETURNING attempts`)
            .get(planId, taskId, token);
        return r === undefined ? null : r.attempts;
    }
    /**
     * Closes a task the caller holds, with its outcome. Guarded by
     * `lease_token = ? AND status = 'leased'`: a late submit under an old token
     * (after a re-claim) or on a closed task changes nothing and returns false.
     * The token stays on the row. Bumps the plan's activity.
     */
    closeTask(planId, taskId, token, outcome, now) {
        return this.db.transaction(() => {
            const changed = this.db
                .prepare(`UPDATE llm_scan_tasks
              SET status = 'closed', independence = @independence, result = @result,
                  closed_reason = @closedReason, brief_chars = COALESCE(@briefChars, brief_chars),
                  response_chars = @responseChars, closed_at = @now
            WHERE plan_id = @planId AND task_id = @taskId AND lease_token = @token AND status = 'leased'`)
                .run({
                planId,
                taskId,
                token,
                now,
                independence: outcome.independence,
                result: outcome.result === null ? null : JSON.stringify(outcome.result),
                closedReason: outcome.closed_reason,
                briefChars: outcome.brief_chars ?? null,
                responseChars: outcome.response_chars,
            }).changes;
            if (changed !== 1)
                return false;
            this.touchPlan(planId, now);
            return true;
        })();
    }
    /**
     * Closes a task nobody holds: `open`, or `leased` with an expired lease —
     * never a live lease, never a closed row. Clears the lease token. Does NOT
     * bump the plan's activity: closing undelivered work at plan end is not use.
     */
    closeUnleased(planId, taskId, reason, now) {
        return (this.db
            .prepare(`UPDATE llm_scan_tasks
              SET status = 'closed', closed_reason = @reason, closed_at = @now, lease_token = NULL,
                  lease_expires_at = NULL
            WHERE plan_id = @planId AND task_id = @taskId AND ${LEASABLE_SQL}`)
            .run({ planId, taskId, reason, now }).changes === 1);
    }
    /** {@link closeUnleased} for every such task of the plan at once (limit reached, plan complete). Returns how many closed. */
    closeAllUnleased(planId, reason, now) {
        return this.db
            .prepare(`UPDATE llm_scan_tasks
            SET status = 'closed', closed_reason = @reason, closed_at = @now, lease_token = NULL,
                lease_expires_at = NULL
          WHERE plan_id = @planId AND ${LEASABLE_SQL}`)
            .run({ planId, reason, now }).changes;
    }
    /** Records that an `open` plan was used just now. */
    touchPlan(planId, now) {
        this.db
            .prepare(`UPDATE llm_scan_plans SET last_activity_at = ?, updated_at = ? WHERE id = ? AND status = 'open'`)
            .run(now, now, planId);
    }
    /** `open` -> `complete` | `abandoned`, nothing else. True when the plan changed. */
    updatePlan(planId, status, now) {
        return (this.db
            .prepare(`UPDATE llm_scan_plans SET status = ?, updated_at = ? WHERE id = ? AND status = 'open'`)
            .run(status, now, planId).changes === 1);
    }
    abandonStalePlans(now) {
        return abandonStalePlans(this.db, now);
    }
}
//# sourceMappingURL=llmScanRepo.js.map