/**
 * Which Semgrep rules a project scan runs — one definition, shared by
 * `scan_sast` (its cache key), `security_scan_full` (which runs `scan_sast`)
 * and `review_pr`.
 *
 * The registry ruleset (`--config=auto`, plus `p/csharp` for a .NET project)
 * unless `local_only`; the project's own Semgrep config (`.semgrep.yml`, or
 * whatever `.dev-guardian/configs.json` records — see
 * `platform/projectSemgrepConfig.ts`); and every rule file registered with
 * `register_custom_rules`. `local_only` also turns metrics off, which is only
 * possible once `--config=auto` is gone: Semgrep refuses to build an auto
 * config with metrics off.
 */
import { readdirSync } from 'node:fs';
import { resolveCustomSemgrepConfigs } from '../platform/customRules.js';
import { inspectProjectSemgrepConfigs } from '../platform/projectSemgrepConfig.js';
export function planSemgrepConfigs(projectPath, plugin, localOnly) {
    const inspection = inspectProjectSemgrepConfigs(projectPath);
    const local = [...inspection.usable.map((c) => c.path), ...resolveCustomSemgrepConfigs(plugin)];
    const registry = localOnly ? [] : ['auto', ...(hasDotnetProject(projectPath) ? ['p/csharp'] : [])];
    const rulePacks = [...registry, ...local];
    return {
        args: [...(localOnly ? ['--metrics=off'] : []), ...rulePacks.map((c) => `--config=${c}`)],
        rulePacks,
        notes: inspection.unusable.map((u) => `${u.target} not loaded (${u.reason})`),
        nothingToRun: rulePacks.length === 0,
    };
}
/** A `.csproj` / `.fsproj` at the project root — `scan_sast`'s own .NET signal. */
function hasDotnetProject(projectPath) {
    try {
        return readdirSync(projectPath).some((n) => n.endsWith('.csproj') || n.endsWith('.fsproj'));
    }
    catch {
        return false;
    }
}
//# sourceMappingURL=semgrepConfigs.js.map