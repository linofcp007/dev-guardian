/**
 * `install_host_context` — copy a host-specific rules file into the user's
 * project root so non-Claude AI assistants (Cursor, Windsurf, Copilot, Cline,
 * Codex CLI) know about the dev-guardian MCP tools.
 *
 * Templates live in `<plugin>/host-rules/`. We read the template at runtime
 * and write it to the matching path inside the user's project. Idempotent:
 * if the destination already exists, the call returns `already_exists: true`
 * unless `force` is set.
 *
 * The "context" here is a markdown file that the host's AI reads when the
 * user opens the project. It maps natural-language intents to the right
 * MCP tools, lists the resources, and warns against anti-patterns.
 */

import {
  copyFileSync,
  existsSync,
  mkdirSync,
  statSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import type { DomainError, ToolResult } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

type HostName = 'cursor' | 'windsurf' | 'copilot' | 'cline' | 'codex' | 'all';

interface HostSpec {
  template_file: string;        // file name under host-rules/
  target_path: string;          // path within the user's project
  description: string;          // human-readable host label
}

const HOST_SPECS: Record<Exclude<HostName, 'all'>, HostSpec> = {
  cursor: {
    template_file: 'cursor.mdc',
    target_path: '.cursor/rules/dev-guardian.mdc',
    description: 'Cursor — .cursor/rules/dev-guardian.mdc',
  },
  windsurf: {
    template_file: 'windsurfrules',
    target_path: '.windsurfrules',
    description: 'Windsurf — .windsurfrules (root)',
  },
  copilot: {
    template_file: 'copilot-instructions.md',
    target_path: '.github/copilot-instructions.md',
    description: 'GitHub Copilot — .github/copilot-instructions.md',
  },
  cline: {
    template_file: 'clinerules',
    target_path: '.clinerules',
    description: 'Cline (VS Code) — .clinerules (root)',
  },
  codex: {
    template_file: 'AGENTS.md',
    target_path: 'AGENTS.md',
    description: 'OpenAI Codex CLI — AGENTS.md (root)',
  },
};

const inputSchema = {
  project_path: ProjectPath,
  host: z
    .enum(['cursor', 'windsurf', 'copilot', 'cline', 'codex', 'all'])
    .describe('Which host to install context for. Use "all" to install every template.'),
  force: z
    .boolean()
    .optional()
    .describe('Overwrite the destination file if it already exists. Default: false.'),
  apply: z
    .boolean()
    .optional()
    .describe('When false, return only the planned actions without writing. Default: true.'),
};

interface HostInstallResult {
  host: string;
  template_file: string;
  source_path: string;
  target_path: string;
  status: 'written' | 'already_exists' | 'would_write' | 'template_missing' | 'failed';
  bytes?: number;
  reason?: string;
}

const tool: ToolModule = {
  name: 'install_host_context',
  title: 'Install dev-guardian context for non-Claude AIs',
  description:
    'Copy the host-specific rules file (Cursor / Windsurf / Copilot / Cline / Codex) from the ' +
    'dev-guardian plugin into the target project so the host\'s AI knows when to call the MCP ' +
    'tools. Idempotent: existing destinations are preserved unless force=true. Use host="all" to ' +
    'install every template (handy for monorepos with mixed dev tooling).',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as {
    project_path?: string;
    host: HostName;
    force?: boolean;
    apply?: boolean;
  };

  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    return failDomain('not_a_git_repo', (e as Error).message);
  }

  const apply = inp.apply ?? true;
  const force = inp.force === true;
  const hostsDir = resolveHostRulesDir(ctx.scriptsDir);
  if (!existsSync(hostsDir)) {
    return failDomain(
      'scanner_failed',
      `host-rules templates not found at ${hostsDir}. Re-install the plugin or build it.`,
    );
  }

  const requestedHosts: Array<Exclude<HostName, 'all'>> =
    inp.host === 'all'
      ? (Object.keys(HOST_SPECS) as Array<Exclude<HostName, 'all'>>)
      : [inp.host];

  const results: HostInstallResult[] = [];
  for (const host of requestedHosts) {
    results.push(installOne({ host, hostsDir, projectPath, apply, force }));
  }

  return {
    ok: true,
    applied: apply,
    project_path: projectPath,
    results,
    next_steps:
      'Restart the target AI host so it re-reads the rules file. Then ask "what dev-guardian tools ' +
      'do you have?" — the host should list the MCP tools and use the new rules to pick the right one.',
  };
}

interface InstallOneArgs {
  host: Exclude<HostName, 'all'>;
  hostsDir: string;
  projectPath: string;
  apply: boolean;
  force: boolean;
}

function installOne(args: InstallOneArgs): HostInstallResult {
  const spec = HOST_SPECS[args.host];
  const src = join(args.hostsDir, spec.template_file);
  const dst = join(args.projectPath, spec.target_path);

  const base: HostInstallResult = {
    host: args.host,
    template_file: spec.template_file,
    source_path: src,
    target_path: dst,
    status: 'would_write',
  };

  if (!existsSync(src)) {
    return { ...base, status: 'template_missing', reason: `${src} missing` };
  }

  if (existsSync(dst) && !args.force) {
    return { ...base, status: 'already_exists', reason: 'force=false; not overwriting' };
  }

  if (!args.apply) {
    try {
      const size = statSync(src).size;
      return { ...base, status: 'would_write', bytes: size };
    } catch {
      return { ...base, status: 'would_write' };
    }
  }

  try {
    mkdirSync(dirname(dst), { recursive: true });
    copyFileSync(src, dst);
    const size = statSync(dst).size;
    return { ...base, status: 'written', bytes: size };
  } catch (e) {
    return { ...base, status: 'failed', reason: (e as Error).message };
  }
}

function resolveHostRulesDir(scriptsDir: string): string {
  // scriptsDir = <plugin>/scripts/. host-rules sits next to scripts/.
  return resolve(scriptsDir, '..', 'host-rules');
}

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
