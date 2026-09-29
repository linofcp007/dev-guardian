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
 *
 * Last, the plugin's own LLM-application pack (`configs/semgrep/llm.yml`:
 * model output reaching an interpreter, remote code in a model load, request
 * data in a system prompt, a completion with no token cap), in both modes — it
 * is a rule file on disk, so `local_only` runs it too. It is an ADDITION, not
 * a SAST ruleset: `local_only` with no project or registered rules is still
 * no scan (`nothingToRun`), because a run of a dozen LLM rules reported as a
 * clean SAST scan would be exactly the false clean this product refuses. For
 * the same reason it cannot MAKE a SAST scan either: "no rule loaded" is
 * judged over `ruleConfigs` (registry, project and registered configs), so a
 * `local_only` run whose every project rule is broken stays failed whatever
 * the pack found — its findings are still recorded. Its rule ids come out bare
 * (`runners/semgrepRuleIds.ts`: a file directly in the plugin's pack
 * directory). The Docker fallback mounts that directory read-only at
 * {@link CONTAINER_PACKS_ROOT}. A damaged install without the pack runs
 * without it, and the run is partial with the gap named (`packMissing`).
 */

import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type { PluginContext } from '../context.js';
import {
  inspectCustomSemgrepConfigs,
  legacyRegistrationNote,
  legacyRegistrationsNotApplied,
} from '../platform/customRules.js';
import { inspectProjectSemgrepConfigs } from '../platform/projectSemgrepConfig.js';
import { pluginPacksDir } from './semgrepRuleIds.js';

/** The plugin's LLM-application pack, by file name in `configs/semgrep/`. */
export const LLM_RULES_FILE = 'llm.yml';

/** Absolute path of the plugin's LLM-application pack. */
export function llmRulesPath(): string {
  return join(pluginPacksDir(), LLM_RULES_FILE);
}

/** Where the Docker fallback mounts the plugin's pack directory, read-only. */
export const CONTAINER_PACKS_ROOT = '/guardian-packs';

/**
 * The Semgrep the LLM pack was measured on. Older engines (1.86.0 through
 * 1.170.1, measured) do not resolve `import … from 'node:child_process'` in
 * taint mode, so the JS rule misses those sinks there.
 */
export const LLM_PACK_MEASURED_SEMGREP = '1.176.1';

/**
 * The note a run carries when the Semgrep that ran (the report's `version`)
 * is older than {@link LLM_PACK_MEASURED_SEMGREP}; null when it is not, or
 * when the version is unknown.
 */
export function llmPackVersionNote(version: string | undefined): string | null {
  if (version === undefined) return null;
  const parse = (v: string): number[] => v.split(/[.+-]/).slice(0, 3).map((p) => Number.parseInt(p, 10));
  const have = parse(version);
  const need = parse(LLM_PACK_MEASURED_SEMGREP);
  if (have.some((n) => Number.isNaN(n))) return null;
  for (let i = 0; i < 3; i += 1) {
    const a = have[i] ?? 0;
    const b = need[i] ?? 0;
    if (a !== b) {
      if (a > b) return null;
      return (
        `${LLM_RULES_FILE} was measured on Semgrep ${LLM_PACK_MEASURED_SEMGREP}; this is ${version}, which does not ` +
        "resolve `import … from 'node:child_process'` in taint mode — the pack's child_process coverage is reduced " +
        '(154 of 172 fixture findings on 1.86.0, 1.120.1 and 1.170.1; all 18 missing are node:child_process sinks)'
      );
    }
  }
  return null;
}

export interface SemgrepConfigPlan {
  /** `--config=…` for every rule source, and `--metrics=off` when local-only. */
  args: string[];
  /** Every rule pack, for the cache key: registry names and local file paths. */
  rulePacks: string[];
  /** The registry packs alone (`auto`, `p/csharp`) — empty when local-only. */
  registry: string[];
  /** The project's own in-tree configs alone (absolute paths) — the only
   *  local rules a container run can see through its project mount. */
  projectConfigs: string[];
  /** The plugin's own packs this plan runs (absolute paths): the LLM-application
   *  pack, when it is on disk. Last in `rulePacks`. */
  pluginPacks: string[];
  /** The plugin's pack directory on the host — what the Docker fallback mounts. */
  pluginPacksDir: string;
  /** The pack is not on disk (a damaged install): the run is partial, the gap in `notes`. */
  packMissing: boolean;
  /** The configs that make this a SAST scan — the registry, the project's and
   *  the registered ones; never the plugin's pack. "No rule loaded" is judged
   *  on these (`rulePacks` minus `pluginPacks`). */
  ruleConfigs: string[];
  /** Local rule files that were refused, and why — the user's rules silently not running —
   *  and any 2.0.x registration outside the project that is no longer applied. */
  notes: string[];
  /** `local_only` with no project or registered rules: there is nothing to run
   *  (the plugin's LLM pack alone is not a SAST ruleset — see the module comment). */
  nothingToRun: boolean;
}

export function planSemgrepConfigs(
  projectPath: string,
  plugin: PluginContext,
  localOnly: boolean,
): SemgrepConfigPlan {
  const inspection = inspectProjectSemgrepConfigs(projectPath);
  const custom = inspectCustomSemgrepConfigs(plugin, projectPath);
  const legacy = legacyRegistrationNote(legacyRegistrationsNotApplied(plugin, projectPath));
  const projectConfigs = inspection.usable.map((c) => c.path);
  const local = [...projectConfigs, ...custom.usable];
  const registry = localOnly ? [] : ['auto', ...(hasDotnetProject(projectPath) ? ['p/csharp'] : [])];
  // Never pass a --config that does not resolve: Semgrep aborts the WHOLE
  // scan when one fails to load. A damaged install without the pack says so.
  const llmPack = llmRulesPath();
  const pluginPacks = existsSync(llmPack) ? [llmPack] : [];
  const rulePacks = [...registry, ...local, ...pluginPacks];
  return {
    args: [...(localOnly ? ['--metrics=off'] : []), ...rulePacks.map((c) => `--config=${c}`)],
    rulePacks,
    registry,
    projectConfigs,
    pluginPacks,
    pluginPacksDir: pluginPacksDir(),
    packMissing: pluginPacks.length === 0,
    ruleConfigs: [...registry, ...local],
    notes: [
      ...inspection.unusable.map((u) => `${u.target} not loaded (${u.reason})`),
      ...custom.unusable.map((u) => `${u.path} not loaded (${u.reason})`),
      ...(legacy !== null ? [legacy] : []),
      ...(pluginPacks.length === 0 ? [`the plugin's LLM-application pack was not found at ${llmPack} — its rules did not run`] : []),
    ],
    nothingToRun: registry.length === 0 && local.length === 0,
  };
}

/** A `.csproj` / `.fsproj` at the project root — `scan_sast`'s own .NET signal. */
export function hasDotnetProject(projectPath: string): boolean {
  try {
    return readdirSync(projectPath).some((n) => n.endsWith('.csproj') || n.endsWith('.fsproj'));
  } catch {
    return false;
  }
}
