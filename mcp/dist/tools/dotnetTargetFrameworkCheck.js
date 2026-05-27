/**
 * `dotnet_target_framework_check` — parse every *.csproj / *.fsproj
 * `<TargetFramework>` and flag versions that are EOL (or close to it).
 *
 * Pure XML grep; does not need the .NET SDK installed.
 *
 * EOL reference (as of mid-2026):
 *   net5.0    — EOL May 2022 (long gone)
 *   netcoreapp3.1 — EOL Dec 2022
 *   net6.0    — EOL Nov 2024
 *   net7.0    — EOL May 2024 (STS)
 *   net8.0    — LTS, supported until Nov 2026
 *   net9.0    — STS, supported until May 2026
 *   net10.0   — LTS, supported until Nov 2028
 *   .NET Framework 4.5/4.6 — EOL (Microsoft only supports 4.6.2+)
 *   .NET Framework 4.7-4.8 — supported (security-only) but legacy
 */
import { randomUUID } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import { registerToolModule } from './index.js';
const SUPPORT = {
    'net10.0': { tfm: 'net10.0', status: 'lts-current', hint: 'LTS until Nov 2028.' },
    'net9.0': { tfm: 'net9.0', status: 'sts-current', hint: 'STS until May 2026.' },
    'net8.0': { tfm: 'net8.0', status: 'lts-current', hint: 'LTS until Nov 2026.' },
    'net7.0': { tfm: 'net7.0', status: 'eol', hint: 'STS — EOL May 2024. Move to net8.0.' },
    'net6.0': { tfm: 'net6.0', status: 'eol', hint: 'LTS — EOL Nov 2024. Move to net8.0.' },
    'net5.0': { tfm: 'net5.0', status: 'eol', hint: 'EOL May 2022. Move to net8.0.' },
    'netcoreapp3.1': { tfm: 'netcoreapp3.1', status: 'eol', hint: 'EOL Dec 2022. Move to net8.0.' },
    'netcoreapp3.0': { tfm: 'netcoreapp3.0', status: 'eol', hint: 'EOL Mar 2020. Move to net8.0.' },
    'netcoreapp2.1': { tfm: 'netcoreapp2.1', status: 'eol', hint: 'EOL Aug 2021. Move to net8.0.' },
    'net48': { tfm: 'net48', status: 'legacy', hint: '.NET Framework — supported, but no new features. Consider net8.0 for new code.' },
    'net472': { tfm: 'net472', status: 'legacy', hint: '.NET Framework 4.7.2 — supported, legacy.' },
    'net462': { tfm: 'net462', status: 'legacy', hint: '.NET Framework 4.6.2 — supported, legacy.' },
    'net461': { tfm: 'net461', status: 'eol', hint: '.NET Framework 4.6.1 — out of support April 2022.' },
    'net46': { tfm: 'net46', status: 'eol', hint: '.NET Framework 4.6 — out of support April 2022.' },
    'net45': { tfm: 'net45', status: 'eol', hint: '.NET Framework 4.5 — out of support.' },
};
const inputSchema = { project_path: ProjectPath };
const tool = {
    name: 'dotnet_target_framework_check',
    title: '.NET target framework EOL check',
    description: 'Parse every *.csproj / *.fsproj `<TargetFramework>` and report support status (LTS, STS, EOL, legacy ' +
        'Framework) plus a hint for each. Pure XML grep — no .NET SDK required.',
    inputSchema,
    handler: async (input, ctx) => handler(input, ctx),
};
registerToolModule(tool);
async function handler(input, ctx) {
    const inp = input;
    let projectPath;
    try {
        projectPath = resolveProjectPath(inp.project_path).path;
    }
    catch (e) {
        return failDomain('not_a_git_repo', e.message);
    }
    const projects = collectCsprojFiles(projectPath, 6);
    const rows = [];
    for (const file of projects) {
        let xml;
        try {
            xml = readFileSync(file, 'utf8');
        }
        catch {
            continue;
        }
        const tfms = extractTfms(xml);
        if (tfms.length === 0)
            continue;
        const statuses = tfms.map((tfm) => SUPPORT[tfm] ?? unknownStatus(tfm));
        rows.push({
            file: relative(projectPath, file).replace(/\\/g, '/'),
            target_frameworks: tfms,
            statuses,
        });
    }
    const eol = rows.flatMap((r) => r.statuses).filter((s) => s.status === 'eol');
    const legacy = rows.flatMap((r) => r.statuses).filter((s) => s.status === 'legacy');
    const scanId = randomUUID();
    ctx.storage.scans.insert({
        scan_id: scanId,
        scan_type: 'dotnet_target_framework',
        project_path: projectPath,
        tree_hash: '',
    });
    ctx.storage.scans.finalize({
        scan_id: scanId,
        status: 'completed',
        tools_run: [{ name: 'dotnet_target_framework_check', status: 'ok' }],
        missing_tools: [],
        meta: {
            project_count: rows.length,
            eol_count: eol.length,
            legacy_count: legacy.length,
            projects: rows,
        },
    });
    return {
        ok: true,
        scan_id: scanId,
        project_count: rows.length,
        eol_count: eol.length,
        legacy_count: legacy.length,
        projects: rows,
        hint: eol.length > 0
            ? `Migrate EOL framework(s) — they receive no security patches. Suggested target: net8.0 LTS.`
            : 'All target frameworks are in active support.',
    };
}
function extractTfms(xml) {
    // `<TargetFramework>net8.0</TargetFramework>` (single)
    // `<TargetFrameworks>net6.0;net8.0</TargetFrameworks>` (multi)
    const out = [];
    const singleMatches = xml.match(/<TargetFramework>([^<]+)<\/TargetFramework>/gi) ?? [];
    for (const m of singleMatches) {
        const inner = /<TargetFramework>([^<]+)<\/TargetFramework>/i.exec(m);
        if (inner && inner[1])
            out.push(inner[1].trim());
    }
    const multiMatches = xml.match(/<TargetFrameworks>([^<]+)<\/TargetFrameworks>/gi) ?? [];
    for (const m of multiMatches) {
        const inner = /<TargetFrameworks>([^<]+)<\/TargetFrameworks>/i.exec(m);
        if (inner && inner[1]) {
            for (const tfm of inner[1].split(';')) {
                if (tfm.trim().length > 0)
                    out.push(tfm.trim());
            }
        }
    }
    return out;
}
function unknownStatus(tfm) {
    return {
        tfm,
        status: 'unknown',
        hint: `Unknown target framework moniker. Verify support at https://learn.microsoft.com/dotnet/standard/frameworks`,
    };
}
const SKIP_DIRS = new Set(['bin', 'obj', 'node_modules', '.git', '.guardian', 'packages', '.vs']);
function collectCsprojFiles(root, maxDepth) {
    const out = [];
    function walk(dir, depth) {
        if (depth > maxDepth)
            return;
        let entries;
        try {
            entries = readdirSync(dir);
        }
        catch {
            return;
        }
        for (const name of entries) {
            if (SKIP_DIRS.has(name))
                continue;
            const abs = join(dir, name);
            try {
                const s = statSync(abs);
                if (s.isDirectory())
                    walk(abs, depth + 1);
                else if (name.endsWith('.csproj') || name.endsWith('.fsproj'))
                    out.push(abs);
            }
            catch {
                /* skip */
            }
        }
    }
    walk(root, 0);
    return out;
}
function failDomain(code, message) {
    return { ok: false, error: { code, message } };
}
//# sourceMappingURL=dotnetTargetFrameworkCheck.js.map