/**
 * LLM-scan plans and tasks (migration `017_llm_scan.sql`): the plan's state
 * lives in the project's database so it survives a server restart and can be
 * resumed by `plan_id` (NFR-2, US-3.AC-4).
 *
 * Holds no code and no prompts: excerpts are rebuilt from file and line.
 */

import type { DB } from './db.js';
import type { LlmScanPlan, LlmScanTask } from '../llmscan/types.js';

type PlanRow = Omit<LlmScanPlan, 'modes' | 'limits' | 'estimate' | 'confirmed' | 'not_eligible' | 'set_aside'> & {
  modes: string;
  limits: string;
  estimate: string;
  confirmed: number;
  not_eligible: string;
  set_aside: string;
};

type TaskRow = Omit<LlmScanTask, 'target' | 'file_hashes' | 'result'> & {
  target: string;
  file_hashes: string;
  result: string | null;
};

const PLAN_COLUMNS = `id, project_path, scan_id, modes, prompt_version, tree_hash, surface_snapshot_id,
  limits, estimate, confirmed, status, not_eligible, set_aside, created_at, updated_at`;
const TASK_COLUMNS = `plan_id, task_id, kind, target, status, lease_token, lease_expires_at, attempts,
  file_hashes, brief_chars, response_chars, independence, result, closed_reason, delivered_at, closed_at`;

function toPlan(r: PlanRow): LlmScanPlan {
  return {
    ...r,
    modes: JSON.parse(r.modes) as LlmScanPlan['modes'],
    limits: JSON.parse(r.limits) as LlmScanPlan['limits'],
    estimate: JSON.parse(r.estimate) as LlmScanPlan['estimate'],
    confirmed: r.confirmed === 1,
    not_eligible: JSON.parse(r.not_eligible) as LlmScanPlan['not_eligible'],
    set_aside: JSON.parse(r.set_aside) as LlmScanPlan['set_aside'],
  };
}

function toTask(r: TaskRow): LlmScanTask {
  return {
    ...r,
    target: JSON.parse(r.target) as LlmScanTask['target'],
    file_hashes: JSON.parse(r.file_hashes) as LlmScanTask['file_hashes'],
    result: r.result === null ? null : (JSON.parse(r.result) as LlmScanTask['result']),
  };
}

function taskParams(t: LlmScanTask): Record<string, unknown> {
  return {
    ...t,
    target: JSON.stringify(t.target),
    file_hashes: JSON.stringify(t.file_hashes),
    result: t.result === null ? null : JSON.stringify(t.result),
  };
}

export class LlmScanRepo {
  private readonly insertPlanStmt;
  private readonly insertTaskStmt;
  private readonly updateTaskStmt;
  private readonly updatePlanStmt;
  private readonly getPlanStmt;
  private readonly listPlansStmt;
  private readonly countOpenStmt;
  private readonly listTasksStmt;
  private readonly getTaskStmt;

  constructor(private readonly db: DB) {
    this.insertPlanStmt = db.prepare(`
      INSERT INTO llm_scan_plans (${PLAN_COLUMNS})
      VALUES (@id, @project_path, @scan_id, @modes, @prompt_version, @tree_hash, @surface_snapshot_id,
              @limits, @estimate, @confirmed, @status, @not_eligible, @set_aside, @created_at, @updated_at)
    `);
    this.insertTaskStmt = db.prepare(`
      INSERT INTO llm_scan_tasks (${TASK_COLUMNS})
      VALUES (@plan_id, @task_id, @kind, @target, @status, @lease_token, @lease_expires_at, @attempts,
              @file_hashes, @brief_chars, @response_chars, @independence, @result, @closed_reason,
              @delivered_at, @closed_at)
    `);
    this.updateTaskStmt = db.prepare(`
      UPDATE llm_scan_tasks SET status = @status, lease_token = @lease_token,
        lease_expires_at = @lease_expires_at, attempts = @attempts, brief_chars = @brief_chars,
        response_chars = @response_chars, independence = @independence, result = @result,
        closed_reason = @closed_reason, delivered_at = @delivered_at, closed_at = @closed_at
      WHERE plan_id = @plan_id AND task_id = @task_id
    `);
    this.updatePlanStmt = db.prepare(
      `UPDATE llm_scan_plans SET status = @status, confirmed = @confirmed, updated_at = @updated_at WHERE id = @id`,
    );
    this.getPlanStmt = db.prepare<[string], PlanRow>(`SELECT ${PLAN_COLUMNS} FROM llm_scan_plans WHERE id = ?`);
    this.listPlansStmt = db.prepare<[string], PlanRow>(
      `SELECT ${PLAN_COLUMNS} FROM llm_scan_plans WHERE project_path = ? ORDER BY created_at DESC, rowid DESC`,
    );
    this.countOpenStmt = db.prepare<[string], { n: number }>(
      `SELECT COUNT(*) AS n FROM llm_scan_plans WHERE project_path = ? AND status = 'open'`,
    );
    this.listTasksStmt = db.prepare<[string], TaskRow>(
      `SELECT ${TASK_COLUMNS} FROM llm_scan_tasks WHERE plan_id = ? ORDER BY task_id`,
    );
    this.getTaskStmt = db.prepare<[string, string], TaskRow>(
      `SELECT ${TASK_COLUMNS} FROM llm_scan_tasks WHERE plan_id = ? AND task_id = ?`,
    );
  }

  /** The plan and all its tasks, or nothing: one transaction. */
  insertPlan(plan: LlmScanPlan, tasks: readonly LlmScanTask[]): void {
    this.db.transaction(() => {
      this.insertPlanStmt.run({
        ...plan,
        modes: JSON.stringify(plan.modes),
        limits: JSON.stringify(plan.limits),
        estimate: JSON.stringify(plan.estimate),
        confirmed: plan.confirmed ? 1 : 0,
        not_eligible: JSON.stringify(plan.not_eligible),
        set_aside: JSON.stringify(plan.set_aside),
      });
      for (const t of tasks) this.insertTaskStmt.run(taskParams(t));
    })();
  }

  getPlan(planId: string): LlmScanPlan | null {
    const r = this.getPlanStmt.get(planId);
    return r === undefined ? null : toPlan(r);
  }

  /** Plans of one project, newest first. */
  listPlans(projectPath: string): LlmScanPlan[] {
    return this.listPlansStmt.all(projectPath).map(toPlan);
  }

  countOpenPlans(projectPath: string): number {
    return this.countOpenStmt.get(projectPath)?.n ?? 0;
  }

  /** Tasks of one plan, by task id. */
  listTasks(planId: string): LlmScanTask[] {
    return this.listTasksStmt.all(planId).map(toTask);
  }

  getTask(planId: string, taskId: string): LlmScanTask | null {
    const r = this.getTaskStmt.get(planId, taskId);
    return r === undefined ? null : toTask(r);
  }

  /** Writes a task's mutable state (lease, attempts, result, close). Its identity and target never change. */
  updateTask(task: LlmScanTask): void {
    this.updateTaskStmt.run({
      plan_id: task.plan_id,
      task_id: task.task_id,
      status: task.status,
      lease_token: task.lease_token,
      lease_expires_at: task.lease_expires_at,
      attempts: task.attempts,
      brief_chars: task.brief_chars,
      response_chars: task.response_chars,
      independence: task.independence,
      result: task.result === null ? null : JSON.stringify(task.result),
      closed_reason: task.closed_reason,
      delivered_at: task.delivered_at,
      closed_at: task.closed_at,
    });
  }

  /** Writes a plan's mutable state: status, confirmation, `updated_at`. */
  updatePlan(plan: Pick<LlmScanPlan, 'id' | 'status' | 'confirmed' | 'updated_at'>): void {
    this.updatePlanStmt.run({ ...plan, confirmed: plan.confirmed ? 1 : 0 });
  }
}
