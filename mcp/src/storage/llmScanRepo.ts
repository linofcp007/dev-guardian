/**
 * LLM-scan plans and tasks (migration `017_llm_scan.sql`): the plan's state
 * lives in the project's database so it survives a server restart and can be
 * resumed by `plan_id` (NFR-2, US-3.AC-4).
 *
 * Holds no code and no prompts: excerpts are rebuilt from file and line.
 */

import type { DB } from './db.js';
import type { LlmScanPlan, LlmScanTask } from '../llmscan/types.js';

export class LlmScanRepo {
  constructor(_db: DB) {}

  insertPlan(_plan: LlmScanPlan, _tasks: readonly LlmScanTask[]): void {
    throw new Error('NotImplemented: LlmScanRepo.insertPlan');
  }

  getPlan(_planId: string): LlmScanPlan | null {
    throw new Error('NotImplemented: LlmScanRepo.getPlan');
  }

  /** Plans of one project, newest first. */
  listPlans(_projectPath: string): LlmScanPlan[] {
    throw new Error('NotImplemented: LlmScanRepo.listPlans');
  }

  countOpenPlans(_projectPath: string): number {
    throw new Error('NotImplemented: LlmScanRepo.countOpenPlans');
  }

  /** Tasks of one plan, by task id. */
  listTasks(_planId: string): LlmScanTask[] {
    throw new Error('NotImplemented: LlmScanRepo.listTasks');
  }

  getTask(_planId: string, _taskId: string): LlmScanTask | null {
    throw new Error('NotImplemented: LlmScanRepo.getTask');
  }
}
