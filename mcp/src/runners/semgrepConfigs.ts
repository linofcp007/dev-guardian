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
 * driver, a request path reaching a file API, a request URL fetched), the
 * client-trust pack (`configs/semgrep/client-trust.yml`: a secret behind a
 * browser-exposed env prefix, the Supabase service-role key in browser code,
 * a payment webhook without signature verification), the
 * mobile pack (`configs/semgrep/mobile.yml`: the Android manifest, its
 * network security config and the iOS Info.plist, read as text — `generic`
 * rules limited to those files by `paths.include`), the WordPress pack
 * (`configs/semgrep/wordpress.yml`: an `esc_sql` value put outside quotes,
 * which the Psalm pass's WordPress stub counts as escaped) and the
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
import { pluginPacksDir, ruleIdsInFile } from './semgrepRuleIds.js';

/** The plugin's LLM-application pack, by file name in `configs/semgrep/`. */
export const LLM_RULES_FILE = 'llm.yml';

/** The plugin's Node/Express sink pack (SQL by interpolation, path traversal, direct SSRF). */
export const WEBJS_RULES_FILE = 'web-js.yml';

/** The plugin's client-trust pack (browser-exposed secrets, the Supabase service-role key in browser code, payment webhooks). */
export const CLIENT_TRUST_RULES_FILE = 'client-trust.yml';

/** The plugin's mobile configuration pack (Android manifest, network security config, iOS Info.plist). */
export const MOBILE_RULES_FILE = 'mobile.yml';

/** The plugin's WordPress pack (an `esc_sql` value outside quotes); scan_wordpress passes it too. */
export const WORDPRESS_RULES_FILE = 'wordpress.yml';

/** The plugin's own packs every Semgrep run passes, in argv order. */
export const PLUGIN_PACK_FILES: readonly string[] = [
  LLM_RULES_FILE,
  WEBJS_RULES_FILE,
  CLIENT_TRUST_RULES_FILE,
  MOBILE_RULES_FILE,
  WORDPRESS_RULES_FILE,
];

let packRuleIds: ReadonlySet<string> | undefined;

/**
 * The rule ids the plugin's packs declare ({@link PLUGIN_PACK_FILES}), as
 * its findings are stored — the pack rule's own id (`localRuleIds.ts`).
 * Read once. A project-root rule carrying the same id is stored the same
 * way and is read as the pack's: in history that can only keep one of its
 * findings open, never close one (`history/runCompare.ts`); at the CI gate,
 * only a finding in a file whose content is unchanged since the baseline was
 * recorded is read against a pack-only record (`ci/taintIncomplete.ts`).
 */
export function pluginPackRuleIds(): ReadonlySet<string> {
  packRuleIds ??= new Set(PLUGIN_PACK_FILES.flatMap((file) => ruleIdsInFile(join(pluginPacksDir(), file))));
  return packRuleIds;
}

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
 * The one note a Semgrep run carries about the engine that ran it (its
 * report's `version`, `semgrepReport.ts#semgrepEngineOf`), or null when there
 * is nothing to say: an engine before 1.170 does not report taint fixpoint
 * timeouts (`time.fixpoint_timeouts`), so a function its taint analysis gave
 * up on is invisible and a complete-looking run may not be — a note, not a
 * partial.
 *
 * Until 3.9.3 it carried a second sentence when the plugin's LLM pack ran:
 * "older than 1.176.1, the JS rule misses the sinks of an `import … from
 * 'node:child_process'`". That was a difference between PLATFORMS read as one
 * between versions — the comparison had been Linux images of older releases
 * against a Windows install of 1.176.1, and the Linux build of 1.182.0 does
 * not resolve those imports either. The rule no longer depends on what the
 * engine resolves: it reads the import as written, and the pack gives the
 * same fixture findings on 1.86.0, 1.120.1, 1.170.1 and 1.182.0 on Linux and
 * on 1.182.0 on Windows (196 of them measured 2026-11-14; 215 on 2026-11-15,
 * with the spellings 3.11.0 added). Nothing is left for a version to say
 * about it.
 */
export function semgrepEngineNote(engine: { version?: string; fixpointTimeoutsReported?: boolean }): string | null {
  const version = engine.version;
  if (version === undefined || engine.fixpointTimeoutsReported !== false) return null;
  return `this Semgrep (${version}) does not report taint fixpoint timeouts; incomplete taint analysis cannot be detected`;
}

/**
 * `run` with {@link semgrepEngineNote} for the engine that wrote `raw`
 * appended to its reason — on a run that scanned (`ok`, full or with a
 * narrower gap) only: a failed or skipped run's reason is about something
 * else.
 */
export function withSemgrepEngineNote(run: ToolRun, raw: unknown): ToolRun {
  if (run.status !== 'ok') return run;
  const note = semgrepEngineNote(semgrepEngineOf(raw));
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
