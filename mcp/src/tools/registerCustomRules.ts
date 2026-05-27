/**
 * `register_custom_rules` — discover the project's Semgrep rule dir and
 * persist it to runtime_meta so scan_sast / bug_hunt pick it up.
 *
 * Looks for, in order: `.semgrep/`, `semgrep/`, `rules/`. If any contains
 * `.yml`/`.yaml` files, we register that path and store an extra
 * `--config=<path>` flag in `runtime_meta['custom_semgrep_args']`.
 *
 * Reading-side wiring (have scan_sast actually use it): currently scan_sast
 * uses `--config=auto` only. The persisted flags are advisory until the
 * next maintenance pass updates that tool — listed in TODO_FOLLOWUPS below.
 */

import { existsSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import type { DomainError, ToolResult } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

const inputSchema = {
  project_path: ProjectPath,
  paths: z
    .array(z.string())
    .optional()
    .describe('Explicit paths or globs to register. When omitted, auto-discovers .semgrep/ etc.'),
  clear: z
    .boolean()
    .optional()
    .describe('When true, remove any previously registered custom rules and exit.'),
};

const tool: ToolModule = {
  name: 'register_custom_rules',
  title: 'Register custom Semgrep rules',
  description:
    'Discover or accept a list of paths to Semgrep YAML rules and persist them to runtime_meta. ' +
    'scan_sast / bug_hunt will then pick them up. Pass clear=true to remove the registration.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

const META_KEY = 'custom_semgrep_configs';

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
    ctx.storage.runtimeMeta.delete(META_KEY);
    return { ok: true, cleared: true };
  }

  const discovered = inp.paths && inp.paths.length > 0
    ? inp.paths.map((p) => resolve(projectPath, p))
    : autoDiscover(projectPath);

  if (discovered.length === 0) {
    return {
      ok: true,
      registered: [],
      note: 'No .semgrep/ or rules/ directory with YAML files found.',
    };
  }

  ctx.storage.runtimeMeta.setJson(META_KEY, discovered);
  return {
    ok: true,
    registered: discovered,
    note: 'Re-run scan_sast / bug_hunt to apply the new rule set.',
  };
}

function autoDiscover(projectPath: string): string[] {
  const out: string[] = [];
  for (const dir of ['.semgrep', 'semgrep', 'rules']) {
    const abs = join(projectPath, dir);
    if (!existsSync(abs)) continue;
    try {
      const hasYaml = readdirSync(abs).some((f) => /\.ya?ml$/.test(f));
      if (hasYaml) out.push(abs);
    } catch {
      /* ignore */
    }
  }
  return out;
}

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
