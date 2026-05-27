/**
 * `detect_stack` — runs `scripts/detect/detect-stack.sh` and persists the
 * parsed JSON to the `stack_snapshots` table.
 *
 * Standalone (no factory): the output is structured stack metadata, not
 * Findings. Other tools (`init_project`, `observability_setup`,
 * `deps_update_plan`, `scan_iac`) read the latest snapshot to drive
 * stack-aware behaviour.
 */

import { join } from 'node:path';
import type { PluginContext } from '../context.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { runShellScript } from '../runners/shellRunner.js';
import { ProjectPath } from '../schemas.js';
import type {
  DomainError,
  StackSnapshot,
  ToolResult,
} from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

const SCRIPT_REL_PATH = ['detect', 'detect-stack.sh'];

const tool: ToolModule = {
  name: 'detect_stack',
  title: 'Detect project stack',
  description:
    'Run scripts/detect/detect-stack.sh against the project and return the parsed stack info ' +
    '(languages, package managers, frameworks, existing tools, IaC, CI). The snapshot is also ' +
    'persisted to .guardian/guardian.db for stack-aware downstream tools.',
  inputSchema: { project_path: ProjectPath },
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as { project_path?: string };
  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    return failDomain('not_a_git_repo', (e as Error).message);
  }

  if (ctx.shell === null) {
    return failDomain(
      'no_bash_shell',
      'No usable bash shell found. Install Git Bash or WSL, then restart.',
    );
  }

  const scriptPath = join(ctx.scriptsDir, ...SCRIPT_REL_PATH);
  const result = await runShellScript({
    shell: ctx.shell,
    scriptPath,
    args: [projectPath],
    cwd: projectPath,
  });

  if (result.outcome !== 'completed') {
    return failDomain(
      'scanner_failed',
      `detect-stack.sh exited with outcome=${result.outcome}, code=${result.exitCode ?? '?'}: ${
        result.stderr.split(/\r?\n/)[0] ?? ''
      }`,
    );
  }

  let parsed: StackSnapshot;
  try {
    parsed = JSON.parse(result.stdout) as StackSnapshot;
  } catch (e) {
    return failDomain(
      'scanner_failed',
      `detect-stack.sh output was not valid JSON: ${(e as Error).message}`,
    );
  }

  const persisted = ctx.storage.stack.insert({ project_path: projectPath, snapshot: parsed });

  return {
    ok: true,
    snapshot: parsed as unknown as Record<string, unknown>,
    captured_at: persisted.captured_at,
    snapshot_id: persisted.id,
  };
}

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
