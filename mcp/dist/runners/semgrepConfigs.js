/**
 * Which Semgrep rules a project scan runs — one definition, shared by
 * `scan_sast` (its argv AND its cache key), `security_scan_full` (which runs
 * `scan_sast`) and `review_pr`.
 *
 * The registry ruleset (`--config=auto`, plus `p/csharp` for a .NET project)
 * unless `local_only`; the project's own Semgrep config (`.semgrep.yml`, or
 * whatever `.dev-guardian/configs.json` records — see
 * `platform/projectSemgrepConfig.ts`); and every rule file registered for
 * this project with `register_custom_rules`. `local_only` also turns metrics
 * off, which is only possible once `--config=auto` is gone: Semgrep refuses
 * to build an auto config with metrics off.
 */
import { readdirSync } from 'node:fs';
import { inspectCustomSemgrepConfigs, legacyRegistrationNote, legacyRegistrationsNotApplied, } from '../platform/customRules.js';
import { inspectProjectSemgrepConfigs } from '../platform/projectSemgrepConfig.js';
export function planSemgrepConfigs(projectPath, plugin, localOnly) {
    const inspection = inspectProjectSemgrepConfigs(projectPath);
    const custom = inspectCustomSemgrepConfigs(plugin, projectPath);
    const legacy = legacyRegistrationNote(legacyRegistrationsNotApplied(plugin, projectPath));
    const projectConfigs = inspection.usable.map((c) => c.path);
    const local = [...projectConfigs, ...custom.usable];
    const registry = localOnly ? [] : ['auto', ...(hasDotnetProject(projectPath) ? ['p/csharp'] : [])];
    const rulePacks = [...registry, ...local];
    return {
        args: [...(localOnly ? ['--metrics=off'] : []), ...rulePacks.map((c) => `--config=${c}`)],
        rulePacks,
        registry,
        projectConfigs,
        notes: [
            ...inspection.unusable.map((u) => `${u.target} not loaded (${u.reason})`),
            ...custom.unusable.map((u) => `${u.path} not loaded (${u.reason})`),
            ...(legacy !== null ? [legacy] : []),
        ],
        nothingToRun: rulePacks.length === 0,
    };
}
/** A `.csproj` / `.fsproj` at the project root — `scan_sast`'s own .NET signal. */
export function hasDotnetProject(projectPath) {
    try {
        return readdirSync(projectPath).some((n) => n.endsWith('.csproj') || n.endsWith('.fsproj'));
    }
    catch {
        return false;
    }
}
//# sourceMappingURL=semgrepConfigs.js.map