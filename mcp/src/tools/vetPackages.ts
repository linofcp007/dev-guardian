/**
 * `vet_packages` — vet dependencies BEFORE installing them.
 *
 * The same engine the PreToolUse install-command hook runs (`pkgvet/vet.ts`),
 * exposed as a tool with a larger network budget (10 s instead of 3 s) and
 * the full per-check breakdown. See `pkgvet/vet.ts` for what each check
 * means and why `unknown` is never folded into `ok`.
 */

import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { parsePackageSpec } from '../pkgvet/parseCommand.js';
import type { PackageSpec, PkgEcosystem, SkippedSpec } from '../pkgvet/types.js';
import { TOOL_BUDGET_MS, vetPackages, worstVerdict } from '../pkgvet/vet.js';
import { ProjectPath } from '../schemas.js';
import type { ToolResult } from '../types.js';
import type { ToolCallMeta } from './index.js';
import { defineTool, registerToolModule, type ToolInput } from './index.js';
import { toolProjectPath } from './projectArg.js';

const ECOSYSTEM_ALIASES: Record<string, PkgEcosystem> = {
  npm: 'npm',
  pnpm: 'npm',
  yarn: 'npm',
  bun: 'npm',
  pypi: 'pypi',
  pip: 'pypi',
  python: 'pypi',
  uv: 'pypi',
  poetry: 'pypi',
  packagist: 'packagist',
  composer: 'packagist',
  php: 'packagist',
  nuget: 'nuget',
  dotnet: 'nuget',
};

const inputSchema = {
  ecosystem: z
    .enum(Object.keys(ECOSYSTEM_ALIASES) as [string, ...string[]])
    .describe('npm (also pnpm/yarn/bun), pypi (pip/uv/poetry), packagist (composer) or nuget (dotnet).'),
  packages: z
    .array(z.string().min(1).max(214))
    .min(1)
    .max(50)
    .describe('Package specs: "name" or "name@version".'),
  project_path: ProjectPath.describe(
    "The project whose registry configuration applies. Default: the server's working directory.",
  ),
};

const tool = defineTool({
  name: 'vet_packages',
  title: 'Vet packages before installing',
  description:
    'Check packages before installing them, against the registry and OSV: the name exists (unpublished: ' +
    'likely hallucinated), the version is not malicious, known vulnerabilities, publish age (under 72 h ' +
    'warns), npm install scripts, typosquatting. Verdict per package: block, warn, unknown or ok — ' +
    'unknown means a check could not run, never ok. Accepts name or name@version. Read-only.',
  inputSchema,
  handler: async (input, ctx, callMeta) => handler(input, ctx, callMeta),
});

registerToolModule(tool);

async function handler(
  inp: ToolInput<typeof inputSchema>,
  _ctx: PluginContext,
  callMeta?: ToolCallMeta,
): Promise<ToolResult<Record<string, unknown>>> {
  const ecosystem = ECOSYSTEM_ALIASES[inp.ecosystem];
  if (ecosystem === undefined) {
    return { ok: false, error: { code: 'unsupported_target', message: `unsupported ecosystem '${inp.ecosystem}'` } };
  }
  // The project's registry configuration (`.npmrc`, `nuget.config`) is read
  // from here: held to every tool's `project_path` rule (`toolProjectPath`),
  // never resolved on its own — a UNC path, `//host/…`, `\\?\UNC\…` or a link
  // to a share made Windows authenticate to a host the caller chose (review
  // 11, finding 8). Without one, the server's working directory, as before.
  let projectDir = process.cwd();
  if (inp.project_path !== undefined && inp.project_path !== '') {
    const resolved = toolProjectPath(inp.project_path);
    if (typeof resolved !== 'string') return resolved;
    projectDir = resolved;
  }

  const specs: PackageSpec[] = [];
  const skipped: SkippedSpec[] = [];
  for (const raw of inp.packages) {
    const parsed = parsePackageSpec(ecosystem, raw);
    if ('name' in parsed) specs.push(parsed);
    else skipped.push(parsed);
  }

  const offline = process.env['GUARDIAN_OFFLINE'] === '1';
  const results = await vetPackages(specs, {
    budgetMs: TOOL_BUDGET_MS,
    offline,
    registry: { projectDir },
    ...(callMeta?.signal !== undefined ? { signal: callMeta.signal } : {}),
  });

  const summary = { block: 0, warn: 0, unknown: 0, ok: 0 };
  for (const r of results) summary[r.verdict] += 1;
  return {
    ok: true,
    ecosystem,
    // Nothing vetted (every spec skipped) is not a clean bill of health.
    verdict: results.length === 0 ? 'unknown' : worstVerdict(results),
    summary,
    packages: results,
    skipped,
    network: offline ? 'disabled (GUARDIAN_OFFLINE=1)' : `online, ${TOOL_BUDGET_MS / 1000} s budget`,
  };
}
