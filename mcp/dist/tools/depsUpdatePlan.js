/**
 * `deps_update_plan` — proposes an ordered dependency-upgrade plan.
 *
 * Unlike scan tools, this does NOT produce Findings — its output is an
 * ordered list of `UpgradeStep` entries. Wiring it through the
 * scan-tool factory would force-fit it into a ScanResult shape; we use
 * `registerToolModule` directly instead.
 *
 * Strategy:
 *   1. Detect the stack via `latest stack_snapshots` (or `package.json` /
 *      `pyproject.toml` / etc. as a fallback).
 *   2. Run the stack-native "outdated" command:
 *        npm   → `npm outdated --json`
 *        pip   → `pip list --outdated --format=json`
 *        composer → `composer outdated --format=json`
 *      (Other stacks return an empty plan with `note=unsupported`.)
 *   3. Classify each entry as patch / minor / major (by semver diff).
 *   4. Mark entries as `security` when an active CVE exists for the package
 *      (sourced from the `cves` table — last deps scan wins).
 *   5. Order the result by `prefer` (default: security, then patch, then
 *      minor, then major).
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { execa } from 'execa';
import { z } from 'zod';
import { ProjectPath } from '../schemas.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { registerToolModule } from './index.js';
const inputSchema = {
    project_path: ProjectPath,
    prefer: z
        .enum(['security', 'patch', 'minor', 'major'])
        .optional()
        .describe('Sort entries so this classification appears first. Default: security.'),
};
const tool = {
    name: 'deps_update_plan',
    title: 'Dependency upgrade plan',
    description: 'Produce an ordered upgrade plan from the project. Runs npm outdated / pip list --outdated / ' +
        'composer outdated, classifies each entry as security / patch / minor / major (security is ' +
        'inferred from the cves table), and returns a sortable list of upgrade_command strings.',
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
    const cvePackages = listActiveCvePackages(ctx);
    const ecosystems = detectEcosystems(projectPath);
    const stepsByEcosystem = await Promise.all(ecosystems.map(async (eco) => {
        switch (eco) {
            case 'npm':
                return runNpmOutdated(projectPath, cvePackages);
            case 'pip':
                return runPipOutdated(projectPath, cvePackages);
            case 'composer':
                return runComposerOutdated(projectPath, cvePackages);
            case 'cargo':
                return runCargoOutdated(projectPath, cvePackages);
            case 'go':
                return runGoOutdated(projectPath, cvePackages);
            case 'rubygems':
                return runBundlerOutdated(projectPath, cvePackages);
            case 'dotnet':
                return runDotnetOutdated(projectPath, cvePackages);
            default:
                return [];
        }
    }));
    const flat = stepsByEcosystem.flat();
    const ordered = orderPlan(flat, inp.prefer ?? 'security');
    const summary = summarize(ordered);
    return {
        ok: true,
        plan: ordered,
        summary,
        stack_detected: ecosystems,
        unsupported_ecosystems_present: detectUnsupportedEcosystems(projectPath),
    };
}
// ---------------------------------------------------------------------- detection
function detectEcosystems(projectPath) {
    const out = [];
    if (existsSync(join(projectPath, 'package.json')))
        out.push('npm');
    if (existsSync(join(projectPath, 'pyproject.toml')) ||
        existsSync(join(projectPath, 'requirements.txt')) ||
        existsSync(join(projectPath, 'setup.py')))
        out.push('pip');
    if (existsSync(join(projectPath, 'composer.json')))
        out.push('composer');
    if (existsSync(join(projectPath, 'Cargo.toml')))
        out.push('cargo');
    if (existsSync(join(projectPath, 'go.mod')))
        out.push('go');
    if (existsSync(join(projectPath, 'Gemfile')))
        out.push('rubygems');
    if (anyCsproj(projectPath))
        out.push('dotnet');
    return out;
}
function anyCsproj(projectPath) {
    try {
        return require('node:fs').readdirSync(projectPath).some((n) => n.endsWith('.csproj') || n.endsWith('.sln'));
    }
    catch {
        return false;
    }
}
function detectUnsupportedEcosystems(projectPath) {
    // Maven / Gradle: parsing `mvn versions:display-dependency-updates` or
    // `gradle dependencyUpdates` output is non-trivial — listed as unsupported
    // pending demand.
    const out = [];
    if (existsSync(join(projectPath, 'pom.xml')))
        out.push('maven');
    if (existsSync(join(projectPath, 'build.gradle')) ||
        existsSync(join(projectPath, 'build.gradle.kts')))
        out.push('gradle');
    return out;
}
function listActiveCvePackages(ctx) {
    // Use the latest completed deps-flavoured scan as the source of CVE truth.
    const latest = ctx.storage.scans.getLatest();
    if (!latest)
        return new Set();
    const cves = ctx.storage.cves.listActive(latest.scan_id);
    return new Set(cves.map((c) => c.package_name.toLowerCase()));
}
// ---------------------------------------------------------------------- runners
async function runNpmOutdated(projectPath, cvePackages) {
    const result = await execa('npm', ['outdated', '--json'], {
        cwd: projectPath,
        reject: false,
        timeout: 60_000,
    });
    // `npm outdated` exits 1 when anything is outdated — that is OK.
    if (result.stdout.trim().length === 0)
        return [];
    let parsed;
    try {
        parsed = JSON.parse(result.stdout);
    }
    catch {
        return [];
    }
    if (!parsed || typeof parsed !== 'object')
        return [];
    const out = [];
    for (const [pkg, raw] of Object.entries(parsed)) {
        if (!raw || typeof raw !== 'object')
            continue;
        const row = raw;
        const installed = typeof row['current'] === 'string' ? row['current'] : '';
        const latest = typeof row['latest'] === 'string' ? row['latest'] : '';
        if (!installed || !latest || installed === latest)
            continue;
        out.push(buildStep({
            package_name: pkg,
            installed_version: installed,
            latest_version: latest,
            ecosystem: 'npm',
            cvePackages,
            upgrade_command: `npm install ${pkg}@${latest}`,
        }));
    }
    return out;
}
async function runPipOutdated(projectPath, cvePackages) {
    const result = await execa('pip', ['list', '--outdated', '--format=json'], {
        cwd: projectPath,
        reject: false,
        timeout: 60_000,
    });
    if (result.exitCode !== 0 || result.stdout.trim().length === 0)
        return [];
    let parsed;
    try {
        parsed = JSON.parse(result.stdout);
    }
    catch {
        return [];
    }
    if (!Array.isArray(parsed))
        return [];
    const out = [];
    for (const row of parsed) {
        const name = row && typeof row === 'object' && 'name' in row && typeof row['name'] === 'string'
            ? row['name']
            : '';
        const version = row && typeof row === 'object' && 'version' in row && typeof row['version'] === 'string'
            ? row['version']
            : '';
        const latest = row && typeof row === 'object' && 'latest_version' in row && typeof row['latest_version'] === 'string'
            ? row['latest_version']
            : '';
        if (!name || !version || !latest || version === latest)
            continue;
        out.push(buildStep({
            package_name: name,
            installed_version: version,
            latest_version: latest,
            ecosystem: 'pip',
            cvePackages,
            upgrade_command: `pip install -U ${name}==${latest}`,
        }));
    }
    return out;
}
async function runComposerOutdated(projectPath, cvePackages) {
    const result = await execa('composer', ['outdated', '--format=json'], {
        cwd: projectPath,
        reject: false,
        timeout: 90_000,
    });
    if (result.exitCode !== 0 || result.stdout.trim().length === 0)
        return [];
    let parsed;
    try {
        parsed = JSON.parse(result.stdout);
    }
    catch {
        return [];
    }
    const installed = parsed?.installed;
    if (!Array.isArray(installed))
        return [];
    const out = [];
    for (const row of installed) {
        const name = row && typeof row === 'object' && 'name' in row && typeof row['name'] === 'string'
            ? row['name']
            : '';
        const version = row && typeof row === 'object' && 'version' in row && typeof row['version'] === 'string'
            ? row['version']
            : '';
        const latest = row && typeof row === 'object' && 'latest' in row && typeof row['latest'] === 'string'
            ? row['latest']
            : '';
        if (!name || !version || !latest || version === latest)
            continue;
        out.push(buildStep({
            package_name: name,
            installed_version: version,
            latest_version: latest,
            ecosystem: 'composer',
            cvePackages,
            upgrade_command: `composer require ${name}:^${latest}`,
        }));
    }
    return out;
}
async function runCargoOutdated(projectPath, cvePackages) {
    // Requires `cargo install cargo-outdated`.
    const result = await execa('cargo', ['outdated', '--format', 'json'], {
        cwd: projectPath,
        reject: false,
        timeout: 90_000,
    });
    if (result.exitCode !== 0 || result.stdout.trim().length === 0)
        return [];
    let parsed;
    try {
        parsed = JSON.parse(result.stdout);
    }
    catch {
        return [];
    }
    const dependencies = parsed?.dependencies;
    if (!Array.isArray(dependencies))
        return [];
    const out = [];
    for (const row of dependencies) {
        if (!row || typeof row !== 'object')
            continue;
        const r = row;
        const name = typeof r['name'] === 'string' ? r['name'] : '';
        const project = typeof r['project'] === 'string' ? r['project'] : '';
        const latest = typeof r['latest'] === 'string' ? r['latest'] : '';
        if (!name || !project || !latest || project === latest)
            continue;
        out.push(buildStep({
            package_name: name,
            installed_version: project,
            latest_version: latest,
            ecosystem: 'cargo',
            cvePackages,
            upgrade_command: `cargo update -p ${name} --precise ${latest}`,
        }));
    }
    return out;
}
async function runGoOutdated(projectPath, cvePackages) {
    // `go list -m -u -json all` emits one JSON object per line.
    const result = await execa('go', ['list', '-m', '-u', '-json', 'all'], {
        cwd: projectPath,
        reject: false,
        timeout: 90_000,
    });
    if (result.exitCode !== 0)
        return [];
    const out = [];
    // Go emits a stream of JSON objects, not a JSON array. Concatenate and
    // split by `}\n{` boundaries.
    const lines = result.stdout.split(/(?<=\})\s*(?=\{)/);
    for (const chunk of lines) {
        let mod;
        try {
            mod = JSON.parse(chunk);
        }
        catch {
            continue;
        }
        if (!mod)
            continue;
        if (!mod.Update || !mod.Path || !mod.Version)
            continue;
        const name = mod.Path;
        const installed = mod.Version;
        const latest = mod.Update.Version ?? '';
        if (!latest || installed === latest)
            continue;
        out.push(buildStep({
            package_name: name,
            installed_version: installed,
            latest_version: latest,
            ecosystem: 'go',
            cvePackages,
            upgrade_command: `go get ${name}@${latest}`,
        }));
    }
    return out;
}
async function runBundlerOutdated(projectPath, cvePackages) {
    // `bundle outdated --parseable` emits machine-friendly lines:
    // gem-name (newest 1.2.3, installed 1.2.0)
    const result = await execa('bundle', ['outdated', '--parseable'], {
        cwd: projectPath,
        reject: false,
        timeout: 90_000,
    });
    // `bundle outdated` exits non-zero when anything is outdated.
    const text = result.stdout || '';
    if (text.trim().length === 0)
        return [];
    const out = [];
    for (const line of text.split(/\r?\n/)) {
        const m = /^(\S+) \(newest ([^,]+), installed ([^,)]+)/.exec(line);
        if (!m)
            continue;
        const name = m[1] ?? '';
        const latest = m[2] ?? '';
        const installed = m[3] ?? '';
        if (!name || !installed || !latest || installed === latest)
            continue;
        out.push(buildStep({
            package_name: name,
            installed_version: installed,
            latest_version: latest,
            ecosystem: 'rubygems',
            cvePackages,
            upgrade_command: `bundle update ${name}`,
        }));
    }
    return out;
}
async function runDotnetOutdated(projectPath, cvePackages) {
    // Restore first (`dotnet list package --outdated` requires resolved
    // packages). If restore fails (e.g. private feed not configured), skip
    // the whole dotnet branch rather than failing the whole call.
    const restore = await execa('dotnet', ['restore', '--nologo', '--verbosity', 'quiet'], {
        cwd: projectPath,
        reject: false,
        timeout: 5 * 60_000,
    });
    if (restore.exitCode !== 0)
        return [];
    // `--format json` is available on .NET 8+; on older SDKs we fall back to
    // parsing the human-readable text output (less precise but functional).
    const r = await execa('dotnet', ['list', 'package', '--outdated', '--format', 'json'], { cwd: projectPath, reject: false, timeout: 90_000 });
    if (r.exitCode === 0 && r.stdout.trim().startsWith('{')) {
        return parseDotnetJson(r.stdout, cvePackages);
    }
    // Fallback to text parsing.
    const fallback = await execa('dotnet', ['list', 'package', '--outdated'], { cwd: projectPath, reject: false, timeout: 90_000 });
    if (fallback.exitCode !== 0 || fallback.stdout.trim().length === 0)
        return [];
    return parseDotnetText(fallback.stdout, cvePackages);
}
function parseDotnetJson(raw, cvePackages) {
    let parsed;
    try {
        parsed = JSON.parse(raw);
    }
    catch {
        return [];
    }
    const projects = parsed
        ?.projects;
    if (!Array.isArray(projects))
        return [];
    const out = [];
    for (const proj of projects) {
        for (const fw of proj.frameworks ?? []) {
            for (const pkg of fw.topLevelPackages ?? []) {
                if (!pkg || typeof pkg !== 'object')
                    continue;
                const p = pkg;
                const name = typeof p['id'] === 'string' ? p['id'] : '';
                const installed = typeof p['resolvedVersion'] === 'string' ? p['resolvedVersion'] : '';
                const latest = typeof p['latestVersion'] === 'string' ? p['latestVersion'] : '';
                if (!name || !installed || !latest || installed === latest)
                    continue;
                out.push(buildStep({
                    package_name: name,
                    installed_version: installed,
                    latest_version: latest,
                    ecosystem: 'dotnet',
                    cvePackages,
                    upgrade_command: `dotnet add package ${name} --version ${latest}`,
                }));
            }
        }
    }
    return out;
}
function parseDotnetText(text, cvePackages) {
    // Lines look like:
    //   > Microsoft.AspNetCore.App   2.1.0    2.1.0    3.1.0
    // (package, requested, resolved, latest). We skip header lines.
    const out = [];
    for (const lineRaw of text.split(/\r?\n/)) {
        const line = lineRaw.trim();
        if (!line.startsWith('>'))
            continue;
        const parts = line.replace(/^>\s*/, '').split(/\s+/);
        if (parts.length < 4)
            continue;
        const [name, _requested, resolved, latest] = parts;
        if (!name || !resolved || !latest || resolved === latest)
            continue;
        out.push(buildStep({
            package_name: name,
            installed_version: resolved,
            latest_version: latest,
            ecosystem: 'dotnet',
            cvePackages,
            upgrade_command: `dotnet add package ${name} --version ${latest}`,
        }));
    }
    return out;
}
function buildStep(input) {
    const semverKind = semverDiffKind(input.installed_version, input.latest_version);
    const hasCve = input.cvePackages.has(input.package_name.toLowerCase());
    const classification = hasCve ? 'security' : (semverKind ?? 'major');
    const step = {
        package_name: input.package_name,
        installed_version: input.installed_version,
        latest_version: input.latest_version,
        ecosystem: input.ecosystem,
        classification,
        upgrade_command: input.upgrade_command,
    };
    if (hasCve)
        step.reason = 'Active CVE on installed version';
    return step;
}
function semverDiffKind(installed, latest) {
    const a = /^v?(\d+)\.(\d+)\.(\d+)/.exec(installed);
    const b = /^v?(\d+)\.(\d+)\.(\d+)/.exec(latest);
    if (!a || !b)
        return null;
    if (a[1] !== b[1])
        return 'major';
    if (a[2] !== b[2])
        return 'minor';
    if (a[3] !== b[3])
        return 'patch';
    return null;
}
// ---------------------------------------------------------------------- ordering
function orderPlan(plan, prefer) {
    const order = {
        security: 0,
        patch: 1,
        minor: 2,
        major: 3,
    };
    // Move `prefer` to rank 0 if it isn't security already.
    if (prefer !== 'security')
        order[prefer] = -1;
    return [...plan].sort((a, b) => order[a.classification] - order[b.classification] ||
        a.package_name.localeCompare(b.package_name));
}
function summarize(plan) {
    const by_classification = {
        security: 0,
        patch: 0,
        minor: 0,
        major: 0,
    };
    for (const s of plan)
        by_classification[s.classification] += 1;
    return {
        total: plan.length,
        by_classification,
        has_security_updates: by_classification.security > 0,
    };
}
// ---------------------------------------------------------------------- domain error
function failDomain(code, message) {
    return { ok: false, error: { code, message } };
}
//# sourceMappingURL=depsUpdatePlan.js.map