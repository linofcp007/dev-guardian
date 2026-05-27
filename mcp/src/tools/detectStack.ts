/**
 * `detect_stack` — runs `scripts/detect/detect-stack.sh` and persists the
 * parsed JSON to the `stack_snapshots` table.
 *
 * Standalone (no factory): the output is structured stack metadata, not
 * Findings. Other tools (`init_project`, `observability_setup`,
 * `deps_update_plan`, `scan_iac`) read the latest snapshot to drive
 * stack-aware behaviour.
 */

import { existsSync, readdirSync } from 'node:fs';
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

  // .NET / C# / F# enrichment — kept in TS so we don't mutate the shared
  // shell script (forbidden by US-12 AC-1 in the original spec).
  enrichDotnet(parsed, projectPath);

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

/**
 * Augment the parsed snapshot with .NET-family signals. Idempotent: calling
 * twice yields the same arrays (we de-duplicate).
 */
function enrichDotnet(snap: StackSnapshot, projectPath: string): void {
  const addOnce = <T>(arr: T[] | undefined, value: T): T[] => {
    if (!arr) return [value];
    return arr.includes(value) ? arr : [...arr, value];
  };

  const hasFile = (rel: string): boolean => existsSync(join(projectPath, rel));
  const anyMatching = (rel: string, suffix: string): boolean => {
    try {
      const target = rel === '' ? projectPath : join(projectPath, rel);
      if (!existsSync(target)) return false;
      return readdirSync(target).some((name) => name.endsWith(suffix));
    } catch {
      return false;
    }
  };

  const hasCsproj = anyMatching('', '.csproj') || anyDeepMatching(projectPath, '.csproj', 3);
  const hasFsproj = anyMatching('', '.fsproj') || anyDeepMatching(projectPath, '.fsproj', 3);
  const hasSln = anyMatching('', '.sln');
  const hasGlobalJson = hasFile('global.json');
  const hasCentralPkgMgmt = hasFile('Directory.Packages.props');
  const hasAspNet =
    hasFile('appsettings.json') ||
    hasFile('Program.cs') ||
    anyDeepMatching(projectPath, 'appsettings.json', 2);

  if (hasCsproj || hasSln || hasGlobalJson || hasCentralPkgMgmt) {
    snap.languages = addOnce(snap.languages, 'csharp');
    snap.package_managers = addOnce(snap.package_managers, 'dotnet');
  }
  if (hasFsproj) {
    snap.languages = addOnce(snap.languages, 'fsharp');
    snap.package_managers = addOnce(snap.package_managers, 'dotnet');
  }
  if (hasCentralPkgMgmt) {
    snap.frameworks = addOnce(snap.frameworks, 'central-package-management');
  }
  if (hasAspNet && (hasCsproj || hasFsproj)) {
    snap.frameworks = addOnce(snap.frameworks, 'aspnetcore');
  }
}

function anyDeepMatching(root: string, suffix: string, maxDepth: number): boolean {
  // Bounded depth-first search for files matching the suffix. Cheap: we
  // stop at the first match. Skips heavy directories.
  const SKIP = new Set([
    'bin',
    'obj',
    'node_modules',
    '.git',
    '.guardian',
    'dist',
    'build',
    'packages',
  ]);
  function walk(dir: string, depth: number): boolean {
    if (depth > maxDepth) return false;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return false;
    }
    for (const name of entries) {
      if (SKIP.has(name) || name.startsWith('.')) continue;
      const abs = join(dir, name);
      if (name.endsWith(suffix)) return true;
      try {
        // Cheap stat → directory descent. We use existsSync on a dirent
        // path; for an unreadable entry we just continue.
        if (readdirSync(abs).length >= 0 && walk(abs, depth + 1)) return true;
      } catch {
        /* not a directory or unreadable */
      }
    }
    return false;
  }
  return walk(root, 0);
}
