/**
 * `vet_packages` — vet dependencies BEFORE installing them.
 *
 * The same engine the PreToolUse install-command hook runs (`pkgvet/vet.ts`),
 * exposed as a tool with a larger network budget (10 s instead of 3 s) and
 * the full per-check breakdown. See `pkgvet/vet.ts` for what each check
 * means and why `unknown` is never folded into `ok`.
 */

import { existsSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { parsePackageSpec } from '../pkgvet/parseCommand.js';
import type { PackageSpec, PkgEcosystem, SkippedSpec } from '../pkgvet/types.js';
import { TOOL_BUDGET_MS, vetPackages, worstVerdict } from '../pkgvet/vet.js';
import { ProjectPath } from '../schemas.js';
import type { ToolResult } from '../types.js';
import type { ToolCallMeta } from './index.js';
import { registerToolModule, type ToolModule } from './index.js';

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

const tool: ToolModule = {
  name: 'vet_packages',
  title: 'Vet packages before installing',
  description:
    'Vet dependencies BEFORE installing them. Per package, against the public registry and OSV: ' +
    'does the name exist (a name nobody published is likely hallucinated), is the version that would ' +
    'install flagged malicious (OSV MAL- advisory, or npm security placeholder), known vulnerabilities, ' +
    'publish age (< 72 h warns: fresh releases are how npm/PyPI worms spread), npm install scripts, ' +
    'and typosquat suspicion against a committed popular-packages list. Verdict per package and overall: ' +
    'block | warn | unknown | ok. `unknown` means a check could not run (offline, timeout, HTTP error, ' +
    'rate limit, GUARDIAN_OFFLINE=1) — never read it as ok. A name missing from the public registry is ' +
    '`unknown`, not block, when a custom registry is configured for it (.npmrc, pip.conf / PIP_INDEX_URL, ' +
    'pyproject/uv index, composer repositories, nuget.config), when an npmjs auth token is configured ' +
    '(scoped names), or when it is a local workspace package. Accepts "name" or "name@version" (also ' +
    'name==1.2, vendor/pkg:^2). Read-only; 10 s network budget. The PreToolUse hook runs the same checks ' +
    'on npm/pnpm/yarn/bun/pip/uv/poetry/composer/dotnet install commands; it denies a missing name only ' +
    'when the whole command is one plain install statement with allowlisted flags (otherwise it warns), ' +
    'and warns on known vulnerabilities only for an exact version pin.',
  inputSchema: {
    ecosystem: z
      .enum(Object.keys(ECOSYSTEM_ALIASES) as [string, ...string[]])
      .describe('npm (also pnpm/yarn/bun), pypi (pip/uv/poetry), packagist (composer) or nuget (dotnet).'),
    packages: z
      .array(z.string().min(1).max(214))
      .min(1)
      .max(50)
      .describe('Package specs: "name" or "name@version" (a range or tag is resolved to the version it installs).'),
    project_path: ProjectPath.describe(
      'Project whose registry configuration (.npmrc, pyproject.toml, composer.json, nuget.config) applies. Defaults to the current directory.',
    ),
  },
  handler: async (input, ctx, callMeta) => handler(input, ctx, callMeta),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  _ctx: PluginContext,
  callMeta?: ToolCallMeta,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as { ecosystem: string; packages: string[]; project_path?: string };
  const ecosystem = ECOSYSTEM_ALIASES[inp.ecosystem];
  if (ecosystem === undefined) {
    return { ok: false, error: { code: 'unsupported_target', message: `unsupported ecosystem '${inp.ecosystem}'` } };
  }
  let projectDir = process.cwd();
  if (inp.project_path !== undefined && inp.project_path !== '') {
    projectDir = resolve(inp.project_path);
    if (!existsSync(projectDir) || !statSync(projectDir).isDirectory()) {
      return { ok: false, error: { code: 'target_not_found', message: `project_path is not a directory: ${projectDir}` } };
    }
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
