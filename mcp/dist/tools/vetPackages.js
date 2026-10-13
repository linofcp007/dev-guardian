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
import { parsePackageSpec } from '../pkgvet/parseCommand.js';
import { TOOL_BUDGET_MS, vetPackages, worstVerdict } from '../pkgvet/vet.js';
import { ProjectPath } from '../schemas.js';
import { registerToolModule } from './index.js';
const ECOSYSTEM_ALIASES = {
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
const tool = {
    name: 'vet_packages',
    title: 'Vet packages before installing',
    description: 'Check packages before installing them, against the registry and OSV: the name exists (unpublished: ' +
        'likely hallucinated), the version is not malicious, known vulnerabilities, publish age (under 72 h ' +
        'warns), npm install scripts, typosquatting. Verdict per package: block, warn, unknown or ok — ' +
        'unknown means a check could not run, never ok. Accepts name or name@version. Read-only.',
    inputSchema: {
        ecosystem: z
            .enum(Object.keys(ECOSYSTEM_ALIASES))
            .describe('npm (also pnpm/yarn/bun), pypi (pip/uv/poetry), packagist (composer) or nuget (dotnet).'),
        packages: z
            .array(z.string().min(1).max(214))
            .min(1)
            .max(50)
            .describe('Package specs: "name" or "name@version".'),
        project_path: ProjectPath.describe("The project whose registry configuration applies. Default: the server's working directory."),
    },
    handler: async (input, ctx, callMeta) => handler(input, ctx, callMeta),
};
registerToolModule(tool);
async function handler(input, _ctx, callMeta) {
    const inp = input;
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
    const specs = [];
    const skipped = [];
    for (const raw of inp.packages) {
        const parsed = parsePackageSpec(ecosystem, raw);
        if ('name' in parsed)
            specs.push(parsed);
        else
            skipped.push(parsed);
    }
    const offline = process.env['GUARDIAN_OFFLINE'] === '1';
    const results = await vetPackages(specs, {
        budgetMs: TOOL_BUDGET_MS,
        offline,
        registry: { projectDir },
        ...(callMeta?.signal !== undefined ? { signal: callMeta.signal } : {}),
    });
    const summary = { block: 0, warn: 0, unknown: 0, ok: 0 };
    for (const r of results)
        summary[r.verdict] += 1;
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
//# sourceMappingURL=vetPackages.js.map