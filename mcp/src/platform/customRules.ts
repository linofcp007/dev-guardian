/**
 * The reading side of `register_custom_rules`.
 *
 * ---- Why this file exists --------------------------------------------
 *
 * `register_custom_rules` discovers (or accepts) paths to a project's own
 * Semgrep YAML and persists them to `runtime_meta`. Its tool description told
 * callers "scan_sast / bug_hunt will then pick them up", and its success
 * payload told them "Re-run scan_sast / bug_hunt to apply the new rule set".
 *
 * Neither was true. `scan_sast` built `['--config=auto']` and nothing else;
 * `bug_hunt` built its own pack list. The persisted key was read by nothing in
 * the entire codebase — the only other mention of it anywhere was a test
 * asserting it had been *written*. So the write half was covered and the read
 * half had never been built, while the product surface claimed the feature
 * worked. A source comment did record the gap ("advisory until the next
 * maintenance pass ... listed in TODO_FOLLOWUPS below") but pointed at a
 * TODO_FOLLOWUPS block that does not exist anywhere in the repo.
 *
 * This module is that reading side.
 *
 * ---- Why the existence filter is not optional ------------------------
 *
 * Semgrep aborts the ENTIRE scan when any `--config` fails to resolve: exit 7,
 * `results: []`, `paths.scanned: []`. That is exactly the failure that took
 * `bug_hunt` down when the `p/bugs` registry pack was retired, and a local
 * path that no longer exists reproduces it without needing the network.
 *
 * Registration persists absolute paths, and a user who registers `.semgrep/`
 * and later deletes or renames it would otherwise poison every subsequent
 * scan — including scans that have nothing to do with custom rules. Dropping
 * the vanished entries keeps a stale registration from turning into a total
 * outage, matching what `resolveBugfixRules` does for the shipped packs.
 */

import { existsSync } from 'node:fs';
import type { PluginContext } from '../context.js';

/**
 * `runtime_meta` key written by `register_custom_rules`.
 *
 * Exported so the writer, the readers and their tests all name the same
 * string. It was previously a private constant in the writer, and a comment
 * in that same file called it `custom_semgrep_args` — a third spelling that
 * matched neither the code nor reality.
 */
export const CUSTOM_RULES_META_KEY = 'custom_semgrep_configs';

/**
 * Absolute paths to the project's registered Semgrep rule files/directories
 * that still exist on disk, or `[]` when nothing is registered.
 *
 * Never throws: a malformed or hand-edited `runtime_meta` row degrades to "no
 * custom rules" rather than breaking every scan in the project.
 */
export function resolveCustomSemgrepConfigs(ctx: PluginContext): string[] {
  let raw: unknown;
  try {
    raw = ctx.storage.runtimeMeta.getJson<unknown>(CUSTOM_RULES_META_KEY);
  } catch {
    return [];
  }
  if (!Array.isArray(raw)) return [];
  return raw.filter((p): p is string => typeof p === 'string' && p.length > 0 && existsSync(p));
}
