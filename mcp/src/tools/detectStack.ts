/**
 * `detect_stack` — detects the project's stack in-process (see
 * `runners/stackDetect.ts`) and persists the result to the `stack_snapshots`
 * table.
 *
 * Used to shell out to `scripts/detect/detect-stack.sh`, which meant a host
 * with no bash/WSL got `no_bash_shell` for a tool that never actually needs
 * one. It also read manifests at the project root only (a repo whose
 * manifest lives a directory down — this repo's own `mcp/package.json` — got
 * `languages: []`) and detected PHP only through `composer.json` (a typical
 * WordPress site/theme/plugin ships none). All three are fixed in
 * `stackDetect.ts`; this file is now just the tool wrapper: detect, enrich
 * with .NET signals, persist, respond.
 *
 * Standalone (no factory): the output is structured stack metadata, not
 * Findings. Other tools (`init_project`, `observability_setup`,
 * `deps_update_plan`, `scan_iac`) read the latest snapshot to drive
 * stack-aware behaviour.
 */

import { existsSync } from 'node:fs';
import { listProjectDir } from '../platform/projectFs.js';
import { join } from 'node:path';
import type { PluginContext } from '../context.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { detectStack } from '../runners/stackDetect.js';
import { ProjectPath } from '../schemas.js';
import type {
  DomainError,
  StackSnapshot,
  ToolResult,
} from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

const tool: ToolModule = {
  name: 'detect_stack',
  title: 'Detect project stack',
  description:
    'Detect the project stack in-process (no shell involved): languages, package managers, ' +
    'frameworks, existing tools, IaC (has_iac), CI. Nested manifests are read up to 3 directories ' +
    'deep (excluding node_modules/vendor/.git/dist/build); each is also reported individually in ' +
    '`projects`, keyed by its path. PHP and WordPress (incl. WooCommerce, Kadence) are detected even ' +
    'with no composer.json: by *.php files, wp-config.php, wp-content/, or a theme/plugin header. ' +
    'The snapshot is also persisted to .guardian/guardian.db for stack-aware downstream tools.',
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

  const parsed: StackSnapshot = detectStack(projectPath);

  // .NET / C# / F# enrichment — kept separate from stackDetect.ts's manifest
  // walk, which only recognizes the manifest names in MANIFEST_FILES; .NET's
  // *.csproj/*.fsproj/*.sln naming does not fit that list (a name reused
  // between projects), so it keeps its own bounded walk here.
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
    const target = rel === '' ? projectPath : join(projectPath, rel);
    return listProjectDir(projectPath, target).some(({ name }) => name.endsWith(suffix));
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
  // `platform/projectFs.ts`: names only, and a directory link is never
  // descended — the walk used to list whatever a link pointed at, in or out
  // of the project.
  function walk(dir: string, depth: number): boolean {
    if (depth > maxDepth) return false;
    for (const { name, kind } of listProjectDir(root, dir)) {
      if (SKIP.has(name) || name.startsWith('.')) continue;
      if (name.endsWith(suffix)) return true;
      if (kind === 'directory' && walk(join(dir, name), depth + 1)) return true;
    }
    return false;
  }
  return walk(root, 0);
}
