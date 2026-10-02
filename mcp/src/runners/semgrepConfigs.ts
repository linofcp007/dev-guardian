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
 * Last, the plugin's own packs: the Node/Express sink pack
 * (`configs/semgrep/web-js.yml`: SQL text built by interpolation in a SQL
 * driver, a request path reaching a file API, a request URL fetched) and the
 * LLM-application pack (`configs/semgrep/llm.yml`:
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
import { basename, join } from 'node:path';
import type { PluginContext } from '../context.js';
import {
  inspectCustomSemgrepConfigs,
  legacyRegistrationNote,
  legacyRegistrationsNotApplied,
} from '../platform/customRules.js';
import { inspectProjectSemgrepConfigs } from '../platform/projectSemgrepConfig.js';
import type { ToolRun } from '../types.js';
import { semgrepEngineOf } from './semgrepReport.js';
import { pluginPacksDir } from './semgrepRuleIds.js';

/** The plugin's LLM-application pack, by file name in `configs/semgrep/`. */
export const LLM_RULES_FILE = 'llm.yml';

/** The plugin's Node/Express sink pack (SQL by interpolation, path traversal, direct SSRF). */
export const WEBJS_RULES_FILE = 'web-js.yml';

/** The plugin's own packs every Semgrep run passes, in argv order. */
export const PLUGIN_PACK_FILES: readonly string[] = [LLM_RULES_FILE, WEBJS_RULES_FILE];

/** Absolute path of the plugin's LLM-application pack. */
export function llmRulesPath(): string {
  return join(pluginPacksDir(), LLM_RULES_FILE);
}

/** Absolute path of one of the plugin's own packs. */
export function pluginPackPath(file: string): string {
  return join(pluginPacksDir(), file);
}

/** Where the Docker fallback mounts the plugin's pack directory, read-only. */
export const CONTAINER_PACKS_ROOT = '/guardian-packs';

/**
 * The Semgrep the LLM pack was measured on. Older engines (1.86.0 through
 * 1.170.1, measured) do not resolve `import … from 'node:child_process'` in
 * taint mode, so the JS rule misses those sinks there ({@link semgrepEngineNote}).
 */
export const LLM_PACK_MEASURED_SEMGREP = '1.176.1';

/** Whether `version` is older than `than` (both `x.y.z`); false when either cannot be read. */
function olderThan(version: string, than: string): boolean {
  const parse = (v: string): number[] => v.split(/[.+-]/).slice(0, 3).map((p) => Number.parseInt(p, 10));
  const have = parse(version);
  const need = parse(than);
  if (have.some((n) => Number.isNaN(n)) || need.some((n) => Number.isNaN(n))) return false;
  for (let i = 0; i < 3; i += 1) {
    const a = have[i] ?? 0;
    const b = need[i] ?? 0;
    if (a !== b) return a < b;
  }
  return false;
}

/**
 * The one note a Semgrep run carries about the engine that ran it (its
 * report's `version`, `semgrepReport.ts#semgrepEngineOf`), or null when there
 * is nothing to say. Two things an older engine cannot do, said once, the
 * engine named once:
 *
 *   - report taint fixpoint timeouts (`time.fixpoint_timeouts`, absent
 *     before 1.170): a function its taint analysis gave up on is invisible,
 *     so a complete-looking run may not be — a note, not a partial;
 *   - with the plugin's LLM pack (`llmPack`), resolve `import … from
 *     'node:child_process'` in taint mode: older than
 *     {@link LLM_PACK_MEASURED_SEMGREP}, the pack's JS rule misses those sinks
 *     (160 of 184 fixture findings on 1.86.0, 1.120.1 and 1.170.1).
 */
export function semgrepEngineNote(
  engine: { version?: string; fixpointTimeoutsReported?: boolean },
  opts: { llmPack: boolean },
): string | null {
  const version = engine.version;
  if (version === undefined) return null;
  const fixpoint = engine.fixpointTimeoutsReported === false;
  const llm = opts.llmPack && olderThan(version, LLM_PACK_MEASURED_SEMGREP);
  const childProcess =
    "resolve `import … from 'node:child_process'` in taint mode — " +
    `${LLM_RULES_FILE} was measured on Semgrep ${LLM_PACK_MEASURED_SEMGREP}, and its child_process coverage is reduced ` +
    '(160 of 184 fixture findings on 1.86.0, 1.120.1 and 1.170.1; all 24 missing are node:child_process sinks)';
  const fixpointNote = 'does not report taint fixpoint timeouts; incomplete taint analysis cannot be detected';
  if (fixpoint && llm) return `this Semgrep (${version}) ${fixpointNote}; nor does it ${childProcess}`;
  if (fixpoint) return `this Semgrep (${version}) ${fixpointNote}`;
  if (llm) return `this Semgrep (${version}) does not ${childProcess}`;
  return null;
}

/**
 * `run` with {@link semgrepEngineNote} for the engine that wrote `raw`
 * appended to its reason — on a run that scanned (`ok`, full or with a
 * narrower gap) only: a failed or skipped run's reason is about something
 * else. For callers that never run the LLM pack (bug_hunt, scan_wordpress).
 */
export function withSemgrepEngineNote(run: ToolRun, raw: unknown): ToolRun {
  if (run.status !== 'ok') return run;
  const note = semgrepEngineNote(semgrepEngineOf(raw), { llmPack: false });
  if (note === null) return run;
  return { ...run, reason: [run.reason, note].filter((s) => s !== undefined).join('; ') };
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
   *  and Node/Express sink packs, those on disk. Last in `rulePacks`. */
  pluginPacks: string[];
  /** The plugin's pack directory on the host — what the Docker fallback mounts. */
  pluginPacksDir: string;
  /** A pack is not on disk (a damaged install): the run is partial, the gap in `notes`. */
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

/**
 * `projectPath` is the project whose rule configuration runs (a worktree's
 * origin for create_fix_pr, the CI gate's `--rules-ref` copy); `scannedPath`
 * the tree Semgrep scans, which decides whether `p/csharp` joins the registry
 * ruleset — the same tree, unless the rules come from elsewhere.
 */
export function planSemgrepConfigs(
  projectPath: string,
  plugin: PluginContext,
  localOnly: boolean,
  scannedPath: string = projectPath,
): SemgrepConfigPlan {
  const inspection = inspectProjectSemgrepConfigs(projectPath);
  const custom = inspectCustomSemgrepConfigs(plugin, projectPath);
  const legacy = legacyRegistrationNote(legacyRegistrationsNotApplied(plugin, projectPath));
  const projectConfigs = inspection.usable.map((c) => c.path);
  const local = [...projectConfigs, ...custom.usable];
  const registry = localOnly ? [] : ['auto', ...(hasDotnetProject(scannedPath) ? ['p/csharp'] : [])];
  // Never pass a --config that does not resolve: Semgrep aborts the WHOLE
  // scan when one fails to load. A damaged install without the pack says so.
  const packPaths = PLUGIN_PACK_FILES.map(pluginPackPath);
  const pluginPacks = packPaths.filter((p) => existsSync(p));
  const missingPacks = packPaths.filter((p) => !pluginPacks.includes(p));
  const rulePacks = [...registry, ...local, ...pluginPacks];
  return {
    args: [...(localOnly ? ['--metrics=off'] : []), ...rulePacks.map((c) => `--config=${c}`)],
    rulePacks,
    registry,
    projectConfigs,
    pluginPacks,
    pluginPacksDir: pluginPacksDir(),
    packMissing: missingPacks.length > 0,
    ruleConfigs: [...registry, ...local],
    notes: [
      ...inspection.unusable.map((u) => `${u.target} not loaded (${u.reason})`),
      ...custom.unusable.map((u) => `${u.path} not loaded (${u.reason})`),
      ...(legacy !== null ? [legacy] : []),
      ...missingPacks.map((p) => `the plugin's pack ${basename(p)} was not found at ${p} — its rules did not run`),
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
