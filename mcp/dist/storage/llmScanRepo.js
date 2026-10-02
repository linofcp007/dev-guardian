/**
 * LLM-scan plans and tasks (migration `017_llm_scan.sql`): the plan's state
 * lives in the project's database so it survives a server restart and can be
 * resumed by `plan_id` (NFR-2, US-3.AC-4).
 *
 * Holds no code and no prompts: excerpts are rebuilt from file and line.
 */
export class LlmScanRepo {
    constructor(_db) { }
    insertPlan(_plan, _tasks) {
        throw new Error('NotImplemented: LlmScanRepo.insertPlan');
    }
    getPlan(_planId) {
        throw new Error('NotImplemented: LlmScanRepo.getPlan');
    }
    /** Plans of one project, newest first. */
    listPlans(_projectPath) {
        throw new Error('NotImplemented: LlmScanRepo.listPlans');
    }
    countOpenPlans(_projectPath) {
        throw new Error('NotImplemented: LlmScanRepo.countOpenPlans');
    }
    /** Tasks of one plan, by task id. */
    listTasks(_planId) {
        throw new Error('NotImplemented: LlmScanRepo.listTasks');
    }
    getTask(_planId, _taskId) {
        throw new Error('NotImplemented: LlmScanRepo.getTask');
    }
}
//# sourceMappingURL=llmScanRepo.js.map