/**
 * Which Semgrep rules a fix pass applies: ONLY the rules that produced the
 * group's targets (Task 11 item 4, 2026-09-25 review).
 *
 * The fix used to be `semgrep --config auto --autofix`: EVERY autofix of the
 * whole registry ruleset, applied across the whole tree — rewriting code no
 * target named, with rules no scan of this project had even run — and, since
 * `--config auto` cannot run with metrics off, it reported usage to Semgrep
 * Inc. on every dry run.
 *
 * Now each target rule is resolved to where it came from:
 *
 *   - a rule in one of the LOCAL rule files the originating scan loaded (the
 *     project's `.semgrep.yml`, its registered rules, `bug_hunt`'s shipped
 *     bugfix packs) is applied from a filtered copy of that file holding only
 *     the target rules — one copy per source file, each in its own directory,
 *     so two packs defining the same id never collide;
 *   - any other rule is a registry rule, applied as `r/<rule-id>` — allowed
 *     only when the originating scan itself used the registry (a `local_only`
 *     scan's target that is not in a local file cannot be resolved, and the
 *     group fails to apply rather than guess).
 *
 * The pass always runs with `--metrics=off`: nothing here uses
 * `--config auto`, and Semgrep accepts `r/<id>` with metrics off (measured on
 * 1.176.1). It runs on the targets' files only.
 *
 * **How a check_id is matched to a local rule.** Semgrep names a rule loaded
 * from a file by the dotted path of that file's DIRECTORY plus the rule id,
 * with characters outside `[A-Za-z0-9._-]` dropped — measured:
 * `C:\Users\ADMINI~1\…\my rules.d\sub\r.yml`'s `my-eval` reports as
 * `C.Users.ADMINI1.….myrules.d.sub.my-eval`. A target matches a rule when its
 * id is the rule id, or ends with `.<id>` after a prefix whose last segment
 * is that directory's name (normalised the same way) — which keeps a
 * registry rule such as `javascript.lang.security.audit.eval-detected` from
 * matching a local rule that happens to be called `eval-detected`.
 */

import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import { yamlFilesUnder } from '../platform/customRules.js';

/** One origin's targets, with the rule sources its scan loaded. */
export interface SemgrepFixSource {
  targets: ReadonlyArray<{ rule_id: string; file_path: string }>;
  /** Local rule files/directories the originating scan passed as --config. */
  localConfigs: readonly string[];
  /** Whether the originating scan loaded registry rules at all. */
  registryAllowed: boolean;
}

export interface SemgrepFixPlan {
  /** `--config` values, in order: filtered local copies, then `r/<rule-id>`. */
  configs: string[];
  /** The same, readable: `<id, id> from <file>` / `r/<rule-id>`. For the PR body. */
  configLabels: string[];
  /** Target files, relative to the project root, POSIX, sorted. */
  files: string[];
  /** A temp directory holding the filtered copies and the pass's reports. */
  dir: string;
}

export type SemgrepFixPlanResult = { ok: true; plan: SemgrepFixPlan } | { ok: false; reason: string };

/** Does Semgrep's check_id `checkId` name rule `id` of the file `ruleFile`? */
export function checkIdMatches(checkId: string, ruleFile: string, id: string): boolean {
  if (checkId === id) return true;
  if (!checkId.endsWith(`.${id}`)) return false;
  const prefix = checkId.slice(0, checkId.length - id.length - 1);
  const tail = basename(dirname(ruleFile)).replace(/[^A-Za-z0-9._-]/g, '');
  return tail.length > 0 && (prefix === tail || prefix.endsWith(`.${tail}`));
}

interface LocalRule {
  file: string;
  id: string;
  rule: Record<string, unknown>;
}

export function planSemgrepFix(sources: readonly SemgrepFixSource[], tmpRoot = tmpdir()): SemgrepFixPlanResult {
  const byFile = new Map<string, Map<string, Record<string, unknown>>>();
  const registry = new Set<string>();
  const files = new Set<string>();
  const unresolved: string[] = [];

  for (const source of sources) {
    const rules = loadLocalRules(source.localConfigs);
    for (const target of source.targets) {
      if (target.file_path.length === 0) {
        return { ok: false, reason: `the finding for rule '${target.rule_id}' names no file` };
      }
      files.add(target.file_path.replace(/\\/g, '/'));
      const matches = rules.filter((r) => checkIdMatches(target.rule_id, r.file, r.id));
      if (matches.length > 0) {
        for (const m of matches) {
          const picked = byFile.get(m.file) ?? new Map<string, Record<string, unknown>>();
          picked.set(m.id, m.rule);
          byFile.set(m.file, picked);
        }
      } else if (source.registryAllowed) {
        registry.add(target.rule_id);
      } else {
        unresolved.push(target.rule_id);
      }
    }
  }
  if (unresolved.length > 0) {
    return {
      ok: false,
      reason:
        `rule(s) ${[...new Set(unresolved)].join(', ')} are in no local rule file the originating scan ` +
        'loaded, and that scan did not use the Semgrep registry — refusing to guess where the fix comes from',
    };
  }

  const dir = mkdtempSync(join(tmpRoot, 'guardian-fixpr-sg-'));
  const configs: string[] = [];
  const configLabels: string[] = [];
  let n = 0;
  for (const [file, picked] of byFile) {
    const sub = join(dir, `rules-${String(n++).padStart(3, '0')}`);
    mkdirSync(sub);
    const copy = join(sub, basename(file));
    writeFileSync(copy, stringifyYaml({ rules: [...picked.values()] }), 'utf8');
    configs.push(copy);
    configLabels.push(`${[...picked.keys()].join(', ')} from ${basename(file)}`);
  }
  for (const id of [...registry].sort()) {
    configs.push(`r/${id}`);
    configLabels.push(`r/${id}`);
  }
  return { ok: true, plan: { configs, configLabels, files: [...files].sort(), dir } };
}

/** Removes the plan's temp directory. Best effort; safe to call twice. */
export function disposeSemgrepFixPlan(plan: SemgrepFixPlan): void {
  try {
    rmSync(plan.dir, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 });
  } catch {
    /* best effort — a temp directory the OS will reclaim */
  }
}

/** Every rule (with an id) in the given files/directories. Unreadable files are skipped. */
function loadLocalRules(configs: readonly string[]): LocalRule[] {
  const out: LocalRule[] = [];
  for (const config of configs) {
    let isDir: boolean;
    try {
      isDir = statSync(config).isDirectory();
    } catch {
      continue;
    }
    for (const file of isDir ? yamlFilesUnder(config) : [config]) {
      let doc: unknown;
      try {
        doc = parseYaml(readFileSync(file, 'utf8'));
      } catch {
        continue;
      }
      const rules = typeof doc === 'object' && doc !== null ? (doc as Record<string, unknown>)['rules'] : undefined;
      if (!Array.isArray(rules)) continue;
      for (const rule of rules) {
        if (typeof rule !== 'object' || rule === null) continue;
        const id = (rule as Record<string, unknown>)['id'];
        if (typeof id === 'string' && id.length > 0) out.push({ file, id, rule: rule as Record<string, unknown> });
      }
    }
  }
  return out;
}
