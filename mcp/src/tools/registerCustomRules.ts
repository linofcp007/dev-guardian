/**
 * `register_custom_rules` — discover the project's own Semgrep rules and
 * persist them, so `scan_sast` and `bug_hunt` run them alongside their own
 * packs.
 *
 * Auto-discovery looks at `.semgrep/`, `semgrep/`, `rules/`. Explicit `paths`
 * may be files, directories or globs (`rules/**\/*.yml`), relative to the
 * project.
 *
 * ---- What changed in Task 11 (2026-09-25 review) ----------------------
 *
 *   - **Globs are expanded.** They used to be stored literally, and the
 *     reader's existence check dropped them — while this tool answered `ok`.
 *     A pattern now registers the files it matches, and one that matches
 *     nothing is `rejected` with that reason.
 *   - **Registration is per canonical project** (`customRulesMetaKey`), not
 *     global: project A's rules used to run on project B.
 *   - **Every file is validated as a Semgrep rules file**
 *     (`validateSemgrepRulesFile`). Auto-discovery registered `rules/`
 *     whatever it held; Prometheus alerts there made every later `scan_sast`
 *     exit 7 with 0 files scanned, and `rules: []` scanned nothing with exit
 *     0. A directory is registered when it holds at least one valid rules
 *     file; its invalid files are `rejected`, and the reader
 *     (`../platform/customRules.ts`) skips them on every scan.
 *   - **Nothing valid means nothing written.** A call that registers nothing
 *     leaves the previous registration exactly as it was, and says so.
 *
 * The reading side (`resolveCustomSemgrepConfigs`) did not exist at all
 * until 2026-08-18 — see its module comment.
 */

import { existsSync, statSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';
import { z } from 'zod';
import type { PluginContext } from '../context.js';
import {
  CUSTOM_RULES_META_KEY,
  customRulesMetaKey,
  validateSemgrepRulesFile,
  yamlFilesUnder,
} from '../platform/customRules.js';
import { expandGlob, hasGlobMagic } from '../platform/glob.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import type { DomainError, ToolResult } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

const inputSchema = {
  project_path: ProjectPath,
  paths: z
    .array(z.string())
    .optional()
    .describe(
      'Files, directories or globs (e.g. rules/**/*.yml), relative to the project. When omitted, ' +
        'auto-discovers .semgrep/, semgrep/ and rules/.',
    ),
  clear: z
    .boolean()
    .optional()
    .describe("When true, remove this project's registered custom rules — and the 2.0.x global registration, for every project — and exit."),
};

const tool: ToolModule = {
  name: 'register_custom_rules',
  title: 'Register custom Semgrep rules',
  description:
    'Discover or accept paths/globs to Semgrep YAML rules and persist them for THIS project ' +
    '(registrations are per project). scan_sast and bug_hunt then run them as extra --config packs. ' +
    'Every file is checked to be a Semgrep rules file (non-empty rules:, each rule with id, message, ' +
    'languages, severity and a pattern) — anything else is returned in `rejected` with a reason and never ' +
    'registered, so a stray YAML (e.g. Prometheus alerts in rules/) cannot break later scans. A ' +
    'registered path that later disappears or stops validating is skipped rather than failing the ' +
    'scan. Pass clear=true to remove the registration.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

interface Rejected {
  path: string;
  reason: string;
}

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as { project_path?: string; paths?: string[]; clear?: boolean };
  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    return failDomain('not_a_git_repo', (e as Error).message);
  }

  if (inp.clear) {
    ctx.storage.runtimeMeta.delete(customRulesMetaKey(projectPath));
    // The 2.0.x registration was global, and clear removed it: it still
    // does, which also ends the notice scans give about it.
    ctx.storage.runtimeMeta.delete(CUSTOM_RULES_META_KEY);
    return { ok: true, cleared: true };
  }

  const explicit = inp.paths !== undefined && inp.paths.length > 0;
  const { registered, rejected } = explicit
    ? collectExplicit(projectPath, inp.paths ?? [])
    : collectDiscovered(projectPath);

  if (registered.length === 0) {
    return {
      ok: true,
      registered: [],
      rejected,
      note: explicit
        ? 'Nothing registered: no path named a valid Semgrep rules file. The previous registration is unchanged.'
        : 'No .semgrep/, semgrep/ or rules/ directory with a valid Semgrep rules file found. ' +
          'The previous registration is unchanged.',
    };
  }

  ctx.storage.runtimeMeta.setJson(customRulesMetaKey(projectPath), registered);
  return {
    ok: true,
    registered,
    rejected,
    note:
      rejected.length > 0
        ? `Registered ${registered.length} path(s); ${rejected.length} rejected (see \`rejected\`). ` +
          'Re-run scan_sast / bug_hunt to apply the new rule set.'
        : 'Re-run scan_sast / bug_hunt to apply the new rule set.',
  };
}

/** A directory counts when at least one YAML file in it validates; each
 *  invalid one is reported. A file counts when it validates. */
function consider(path: string, registered: string[], rejected: Rejected[]): void {
  let isDir: boolean;
  try {
    isDir = statSync(path).isDirectory();
  } catch {
    rejected.push({ path, reason: 'does not exist' });
    return;
  }
  if (!isDir) {
    const verdict = validateSemgrepRulesFile(path);
    if (verdict.ok) registered.push(path);
    else rejected.push({ path, reason: verdict.reason });
    return;
  }
  const files = yamlFilesUnder(path);
  let valid = 0;
  for (const file of files) {
    const verdict = validateSemgrepRulesFile(file);
    if (verdict.ok) valid += 1;
    else rejected.push({ path: file, reason: verdict.reason });
  }
  if (valid > 0) registered.push(path);
  else if (files.length === 0) rejected.push({ path, reason: 'holds no .yml/.yaml file' });
}

function collectExplicit(projectPath: string, paths: readonly string[]): { registered: string[]; rejected: Rejected[] } {
  const registered: string[] = [];
  const rejected: Rejected[] = [];
  for (const raw of paths) {
    if (hasGlobMagic(raw)) {
      if (isAbsolute(raw)) {
        rejected.push({ path: raw, reason: 'a glob must be relative to the project' });
        continue;
      }
      const matches = expandGlob(projectPath, raw).filter((p) => {
        try {
          return statSync(p).isFile();
        } catch {
          return false;
        }
      });
      if (matches.length === 0) {
        rejected.push({ path: raw, reason: 'matched no file' });
        continue;
      }
      for (const match of matches) consider(match, registered, rejected);
      continue;
    }
    consider(resolve(projectPath, raw), registered, rejected);
  }
  return { registered: [...new Set(registered)], rejected };
}

function collectDiscovered(projectPath: string): { registered: string[]; rejected: Rejected[] } {
  const registered: string[] = [];
  const rejected: Rejected[] = [];
  for (const dir of ['.semgrep', 'semgrep', 'rules']) {
    const abs = join(projectPath, dir);
    if (!existsSync(abs)) continue;
    consider(abs, registered, rejected);
  }
  return { registered, rejected };
}

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
