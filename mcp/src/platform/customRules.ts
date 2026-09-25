/**
 * The reading side of `register_custom_rules`, and the rule-file check both
 * sides use.
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
 * asserting it had been *written*. This module is that reading side.
 *
 * ---- Per project, and validated (Task 11, 2026-09-25 review) ----------
 *
 *   - **Registration is keyed by canonical project** (`customRulesMetaKey`).
 *     It used to be one global key, so project A's rules ran on every scan of
 *     project B served by the same database. The old key is still read — a
 *     2.0.x database keeps working — but only for entries INSIDE the project
 *     being scanned: it cannot say which project registered an entry outside
 *     one, and guessing is how A's rules reached B.
 *   - **Every file is validated as a Semgrep rules file** before it is handed
 *     to Semgrep, at registration and again at every read: a non-empty
 *     `rules:` list whose every rule has `id`, `message`, `languages`, a
 *     pattern key and a `severity` Semgrep accepts (without one: exit 7,
 *     0 files scanned). Auto-discovery used to register `rules/` whatever it held;
 *     a directory of Prometheus alerts made every later `scan_sast` exit 7
 *     with 0 files scanned, and `rules: []` gave exit 0 with 0 files scanned.
 *     A registered directory is expanded into its valid rule files here, so a
 *     broken file added to it later costs that file, never the scan.
 *
 * ---- Why the existence filter is not optional ------------------------
 *
 * Semgrep aborts the ENTIRE scan when any `--config` fails to resolve: exit 7,
 * `results: []`, `paths.scanned: []`. Registration persists absolute paths,
 * and a user who registers `.semgrep/` and later deletes it would otherwise
 * poison every subsequent scan. Vanished entries are dropped.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { isAbsolute, join, relative, sep } from 'node:path';
import { parse as parseYaml } from 'yaml';
import type { PluginContext } from '../context.js';

/**
 * The 2.0.x GLOBAL `runtime_meta` key. Still read (see the module comment),
 * never written. Per-project registrations live under
 * {@link customRulesMetaKey}.
 */
export const CUSTOM_RULES_META_KEY = 'custom_semgrep_configs';

/** The `runtime_meta` key holding one canonical project's registration. */
export function customRulesMetaKey(projectPath: string): string {
  return `${CUSTOM_RULES_META_KEY}:${projectPath}`;
}

export type RulesFileVerdict = { ok: true; rules: number } | { ok: false; reason: string };

/** Keys that make a rule match something; one of them must be present. */
const PATTERN_KEYS: readonly string[] = [
  'pattern',
  'patterns',
  'pattern-either',
  'pattern-regex',
  'pattern-sources',
  'match',
  'taint',
  'join',
];

/**
 * Whether Semgrep can load `path` as a rules file without aborting or
 * silently scanning nothing. Structural, not `semgrep --validate` (a second
 * process per file): a pattern that does not compile still costs one rule,
 * which the scan's own `errors[]` reports.
 */
export function validateSemgrepRulesFile(path: string): RulesFileVerdict {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    return { ok: false, reason: 'unreadable' };
  }
  let doc: unknown;
  try {
    doc = parseYaml(text);
  } catch {
    return { ok: false, reason: 'not valid YAML' };
  }
  if (!isRecord(doc)) return { ok: false, reason: 'no `rules:` list' };
  const rules = doc['rules'];
  if (!Array.isArray(rules)) return { ok: false, reason: 'no `rules:` list' };
  if (rules.length === 0) return { ok: false, reason: 'empty `rules:` list' };
  for (let i = 0; i < rules.length; i++) {
    const rule: unknown = rules[i];
    if (!isRecord(rule)) return { ok: false, reason: `rule #${i + 1} is not a mapping` };
    const id = rule['id'];
    if (typeof id !== 'string' || id.length === 0) return { ok: false, reason: `rule #${i + 1} has no \`id\`` };
    const message = rule['message'];
    if (typeof message !== 'string' || message.length === 0) {
      return { ok: false, reason: `rule '${id}' has no \`message\`` };
    }
    const languages = rule['languages'];
    if (!Array.isArray(languages) || languages.length === 0) {
      return { ok: false, reason: `rule '${id}' has no \`languages\`` };
    }
    if (!PATTERN_KEYS.some((k) => rule[k] !== undefined)) {
      return { ok: false, reason: `rule '${id}' has no pattern key` };
    }
    const severity = rule['severity'];
    if (severity === undefined || severity === null) return { ok: false, reason: `rule '${id}' has no \`severity\`` };
    if (typeof severity !== 'string' || !SEMGREP_SEVERITIES.includes(severity)) {
      return {
        ok: false,
        reason:
          `rule '${id}' has severity '${String(severity)}', which Semgrep rejects ` +
          `(expected one of ${SEMGREP_SEVERITIES.join(', ')})`,
      };
    }
  }
  return { ok: true, rules: rules.length };
}

/**
 * The `severity` values Semgrep's rule schema accepts — measured on 1.176.1,
 * each on its own rule: these load, while a missing severity or a lower-case
 * spelling (`warning`) is an `InvalidRuleSchemaError`, exit 7, 0 files
 * scanned. `EXPERIMENT` and `INVENTORY` load but report no findings.
 */
const SEMGREP_SEVERITIES: readonly string[] = [
  'INFO',
  'WARNING',
  'ERROR',
  'LOW',
  'MEDIUM',
  'HIGH',
  'CRITICAL',
  'EXPERIMENT',
  'INVENTORY',
];

/** `.yml` / `.yaml` files under `dir`, recursively, sorted; `.git` and
 *  `node_modules` are never entered. */
export function yamlFilesUnder(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string, depth: number): void => {
    if (depth > 8) return;
    let names: string[];
    try {
      names = readdirSync(d).sort();
    } catch {
      return;
    }
    for (const name of names) {
      if (name === '.git' || name === 'node_modules') continue;
      const abs = join(d, name);
      let isDir: boolean;
      try {
        isDir = statSync(abs).isDirectory();
      } catch {
        continue;
      }
      if (isDir) walk(abs, depth + 1);
      else if (/\.ya?ml$/i.test(name)) out.push(abs);
    }
  };
  walk(dir, 0);
  return out;
}

export interface CustomRulesInspection {
  /** Rule files safe to pass to Semgrep, one `--config` each. */
  usable: string[];
  /** Registered files (or files inside a registered directory) that would
   *  break or empty the scan, and why — reported, never passed on. */
  unusable: Array<{ path: string; reason: string }>;
}

/** This project's registered entries — its own key, plus the legacy global
 *  key's entries that lie inside it. Never throws. */
export function registeredEntries(ctx: PluginContext, projectPath: string): string[] {
  const own = readList(ctx, customRulesMetaKey(projectPath));
  const legacy = readList(ctx, CUSTOM_RULES_META_KEY).filter((p) => isInside(projectPath, p));
  return [...new Set([...own, ...legacy])];
}

/**
 * Every rule file this project's registration resolves to right now: files
 * as registered, directories expanded to their YAML files, each re-validated;
 * vanished paths dropped silently (the user removed them), invalid files
 * reported in `unusable`.
 */
export function inspectCustomSemgrepConfigs(ctx: PluginContext, projectPath: string): CustomRulesInspection {
  const usable: string[] = [];
  const unusable: Array<{ path: string; reason: string }> = [];
  const seen = new Set<string>();
  for (const entry of registeredEntries(ctx, projectPath)) {
    let isDir: boolean;
    try {
      isDir = statSync(entry).isDirectory();
    } catch {
      continue; // vanished — see the module comment
    }
    for (const file of isDir ? yamlFilesUnder(entry) : [entry]) {
      if (seen.has(file)) continue;
      seen.add(file);
      const verdict = validateSemgrepRulesFile(file);
      if (verdict.ok) usable.push(file);
      else unusable.push({ path: file, reason: verdict.reason });
    }
  }
  return { usable, unusable };
}

/**
 * Entries of the 2.0.x GLOBAL registration that lie outside `projectPath`
 * and so are no longer applied to it — 2.0.x ran them on every project.
 * Only paths that still exist: a vanished one would not have run anyway.
 */
export function legacyRegistrationsNotApplied(ctx: PluginContext, projectPath: string): string[] {
  return readList(ctx, CUSTOM_RULES_META_KEY).filter((p) => !isInside(projectPath, p) && pathExists(p));
}

/** The user-facing account of {@link legacyRegistrationsNotApplied}, or null. */
export function legacyRegistrationNote(paths: readonly string[]): string | null {
  if (paths.length === 0) return null;
  return (
    `custom Semgrep rules registered before registrations became per-project (dev-guardian 2.0.x) are no ` +
    `longer applied here because they lie outside this project: ${paths.join(', ')}. Re-register the ` +
    `ones this project needs with register_custom_rules (paths: [...]); register_custom_rules ` +
    'clear=true removes the old registration and this notice.'
  );
}

function pathExists(p: string): boolean {
  try {
    statSync(p);
    return true;
  } catch {
    return false;
  }
}

/** The usable half of {@link inspectCustomSemgrepConfigs}. */
export function resolveCustomSemgrepConfigs(ctx: PluginContext, projectPath: string): string[] {
  return inspectCustomSemgrepConfigs(ctx, projectPath).usable;
}

function readList(ctx: PluginContext, key: string): string[] {
  let raw: unknown;
  try {
    raw = ctx.storage.runtimeMeta.getJson<unknown>(key);
  } catch {
    return [];
  }
  if (!Array.isArray(raw)) return [];
  return raw.filter((p): p is string => typeof p === 'string' && p.length > 0);
}

/** `path` lies inside `root` (or is it). Case-insensitive on Windows. */
export function isInside(root: string, path: string): boolean {
  const norm = (p: string): string => (process.platform === 'win32' ? p.toLowerCase() : p);
  const rel = relative(norm(root), norm(path));
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
