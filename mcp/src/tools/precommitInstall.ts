/**
 * `precommit_install` — register the project's `.pre-commit-config.yaml`
 * with the local pre-commit framework via `pre-commit install`.
 *
 * Idempotent. Assumes `init_project` (or the user) has already created
 * `.pre-commit-config.yaml`. Returns the hook stages that installed
 * (`stages_installed`) and those that did not (`stages_failed`).
 */

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { PluginContext } from '../context.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { runProcess } from '../runners/processRunner.js';
import { ProjectPath } from '../schemas.js';
import type { DomainError, ToolResult } from '../types.js';
import { scannerAvailable } from './scanHelpers.js';
import { registerToolModule, type ToolModule } from './index.js';

const tool: ToolModule = {
  name: 'precommit_install',
  title: 'Install pre-commit hooks',
  description:
    'Run `pre-commit install` in the project to wire its .pre-commit-config.yaml into git hooks. ' +
    'Requires pre-commit on PATH (install via install_toolchain).',
  inputSchema: { project_path: ProjectPath },
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  _ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as { project_path?: string };
  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    return failDomain('not_a_git_repo', (e as Error).message);
  }

  if (!existsSync(join(projectPath, '.pre-commit-config.yaml'))) {
    return failDomain(
      'scanner_failed',
      'No .pre-commit-config.yaml in project. Run init_project first.',
    );
  }
  if (!existsSync(join(projectPath, '.git'))) {
    return failDomain('not_a_git_repo', 'pre-commit needs a git repo to install hooks into.');
  }

  const bin = await scannerAvailable('pre-commit');
  if (!bin) {
    return failDomain(
      'missing_scanner',
      'pre-commit is not installed. Run install_toolchain with tools=["pre-commit"].',
    );
  }

  const result = await runProcess({
    command: 'pre-commit',
    args: ['install'],
    cwd: projectPath,
    timeoutMs: 60_000,
  });
  if (result.outcome !== 'completed') {
    return failDomain(
      'scanner_failed',
      `pre-commit install failed: ${result.stderr.split(/\r?\n/)[0] ?? '(no stderr)'}`,
    );
  }

  // Also install the commit-msg / pre-push hooks. Best effort — a failure
  // does not fail the call — but reported per stage: this used to list all
  // three as installed whatever these two returned, and a hook that did not
  // install is one that silently never runs.
  const stagesInstalled = ['pre-commit'];
  const stagesFailed: Array<{ stage: string; error: string }> = [];
  for (const stage of ['commit-msg', 'pre-push']) {
    const r = await runProcess({
      command: 'pre-commit',
      args: ['install', '--hook-type', stage],
      cwd: projectPath,
      timeoutMs: 30_000,
    });
    if (r.outcome === 'completed') {
      stagesInstalled.push(stage);
    } else {
      const firstLine = (r.stderr || r.stdout).split(/\r?\n/).find((l) => l.trim().length > 0);
      stagesFailed.push({ stage, error: firstLine?.trim() ?? r.outcome });
    }
  }

  return {
    ok: true,
    project_path: projectPath,
    stages_installed: stagesInstalled,
    stages_failed: stagesFailed,
    ...(stagesFailed.length > 0
      ? {
          warnings: stagesFailed.map(
            (f) => `the ${f.stage} hook was NOT installed and will not run: ${f.error}`,
          ),
        }
      : {}),
    stdout: result.stdout.split(/\r?\n/).slice(0, 20).join('\n'),
  };
}

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
