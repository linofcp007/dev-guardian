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
 *   2. Per ecosystem:
 *        npm      → `npm outdated --json`, upgraded to the CVE's minimum
 *                    fixed version rather than "latest" when one is active,
 *                    every `npm install` carrying `--ignore-scripts`, and a
 *                    vulnerable TRANSITIVE package getting an `overrides`
 *                    step (`npm pkg set overrides.<pkg>=<version>`) instead;
 *        pip      → NEVER runs pip/pip-audit against the host interpreter.
 *                    Reads this project's own `requirements*.txt` exact pins
 *                    (`pkg==version`) and PEP 621 `pyproject.toml`
 *                    dependencies, and proposes a step only for a pin with
 *                    an active CVE and a known fixed version — see
 *                    `runPipPlan`'s own doc comment for why `upgrade_command`
 *                    is not a real, executable command here;
 *        composer / cargo / go / rubygems / dotnet → each stack's own
 *                    "outdated" command (unchanged).
 *      (Other stacks return an empty plan with `unsupported_ecosystems_present`.)
 *   3. Classify each entry as patch / minor / major (by semver diff).
 *   4. Mark entries as `security` when an active CVE exists for the package —
 *      sourced from the latest `deps` / `deps_audit` / `security_full` scan
 *      of THIS SAME PROJECT (`CVE_SOURCE_SCAN_TYPES`, `../types.js`), never
 *      an unscoped "whatever scan is latest in the whole database" lookup.
 *   5. Order the result by `prefer` (default: security, then patch, then
 *      minor, then major).
 */
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { execa } from 'execa';
import { z } from 'zod';
import { ProjectPath } from '../schemas.js';
import { CVE_SOURCE_SCAN_TYPES } from '../types.js';
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
    description: 'Produce an ordered upgrade plan from the project. npm/composer/cargo/go/rubygems/dotnet use ' +
        'each stack\'s own "outdated" command; pip reads this project\'s own requirements*.txt / ' +
        'pyproject.toml pins and never touches the host Python. Classifies each entry as security ' +
        '(minimum CVE-fixed version, from the same project\'s latest deps scan) / patch / minor / ' +
        'major, and returns a sortable, structured plan (package_name, ecosystem, installed_version, ' +
        'latest_version, cve_ids, upgrade_command).',
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
    const cves = listActiveCves(ctx, projectPath);
    const ecosystems = detectEcosystems(projectPath);
    const stepsByEcosystem = await Promise.all(ecosystems.map(async (eco) => {
        switch (eco) {
            case 'npm':
                return runNpmOutdated(projectPath, cves);
            case 'pip':
                return runPipPlan(projectPath, cves);
            case 'composer':
                return runComposerOutdated(projectPath, cves);
            case 'cargo':
                return runCargoOutdated(projectPath, cves);
            case 'go':
                return runGoOutdated(projectPath, cves);
            case 'rubygems':
                return runBundlerOutdated(projectPath, cves);
            case 'dotnet':
                return runDotnetOutdated(projectPath, cves);
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
        return readdirSync(projectPath).some((n) => n.endsWith('.csproj') || n.endsWith('.sln'));
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
/**
 * Active CVEs, keyed by lowercased package name, sourced from the latest
 * `deps` / `deps_audit` / `security_full` scan of THIS project —
 * `CVE_SOURCE_SCAN_TYPES` (`../types.js`), the same set Task 6 established
 * as "the same project's deps history". Previously this read
 * `ctx.storage.scans.getLatest()`, the UNSCOPED "any project, any scan
 * type" row — a `sast`-only scan of a different project could win here and
 * silently zero out every CVE, the same class of bug documented in
 * `scansRepo.ts`'s own module comment for `getLatest`/`listHistory`.
 */
function listActiveCves(ctx, projectPath) {
    const history = ctx.storage.scans.listHistoryForProject(projectPath, 50);
    const latest = history.find((s) => CVE_SOURCE_SCAN_TYPES.includes(s.scan_type) && s.status === 'completed');
    const out = new Map();
    if (!latest)
        return out;
    for (const cve of ctx.storage.cves.listActive(latest.scan_id)) {
        const key = cve.package_name.toLowerCase();
        // Trivy's own `FixedVersion` is free text and routinely NOT a single
        // installable version: multi-branch lists ("4.17.12, 5.0.0") and open
        // ranges (">=4.17.11") both appear on real scans (lodash's own CVE
        // history has both). Only an exact `X.Y.Z`-shaped string is usable as
        // an `npm install pkg@<version>` target; anything else is treated the
        // same as "no fix reported" for THIS cve — the id is still recorded
        // (cve_ids), only the version math ignores it. This is what keeps a
        // package with several active CVEs, some clean and one messy, from
        // silently ending up with the messy string as its computed minimum.
        const candidate = isCleanVersion(cve.fixed_version) ? cve.fixed_version : undefined;
        const existing = out.get(key);
        if (existing) {
            existing.cveIds.push(cve.cve_id);
            // The MINIMUM version that clears every active CVE is the MAXIMUM of
            // each individual CVE's own minimum fix — installing anything less
            // than the highest one leaves that CVE's own fix unmet.
            if (candidate !== undefined &&
                (existing.fixedVersion === undefined || compareVersionStrings(candidate, existing.fixedVersion) > 0)) {
                existing.fixedVersion = candidate;
            }
        }
        else {
            out.set(key, { cveIds: [cve.cve_id], fixedVersion: candidate });
        }
    }
    return out;
}
/** `1.2.3`, `1.2`, or `1` — optionally `v`-prefixed — and nothing else. The
 *  only shape of `cves.fixed_version` this module trusts as an installable
 *  target; see `listActiveCves`'s own comment for what real scanner output
 *  otherwise looks like. */
function isCleanVersion(v) {
    return v !== undefined && /^v?\d+(\.\d+)*$/i.test(v.trim());
}
/**
 * Best-effort numeric-segment comparison (`1.2.3` vs `1.10.0`), used only to
 * pick the HIGHER of two already-known fixed versions for the same package
 * when it carries more than one active CVE. Falls back to string comparison
 * for anything that does not parse as dotted numbers — never throws.
 */
function compareVersionStrings(a, b) {
    const pa = a.replace(/^v/i, '').split('.').map((n) => parseInt(n, 10));
    const pb = b.replace(/^v/i, '').split('.').map((n) => parseInt(n, 10));
    if (pa.some(Number.isNaN) || pb.some(Number.isNaN))
        return a.localeCompare(b);
    for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
        const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
        if (diff !== 0)
            return diff;
    }
    return 0;
}
// ---------------------------------------------------------------------- runners
/**
 * npm branch (item 4):
 *   - a package with an active CVE upgrades to the MINIMUM fixed version
 *     (`cves.fixed_version`) rather than `npm outdated`'s own `latest` —
 *     the smallest change that actually resolves the CVE, not whatever is
 *     newest today;
 *   - every `npm install` this plan emits carries `--ignore-scripts` — a
 *     dependency's install/postinstall script must never run just because
 *     this tool proposed a version bump;
 *   - a TRANSITIVE package (not named in this project's own `package.json`
 *     `dependencies`/`devDependencies`/`optionalDependencies`/
 *     `peerDependencies` — see `readNpmDirectDependencies`'s own comment for
 *     why NOT `npm outdated --json`'s `dependent` field) with an active CVE
 *     gets an `overrides` step instead of an `npm install` —
 *     `npm install <transitive>@<version>` does not reliably pin a nested
 *     dependency's resolved version the way `package.json`'s own
 *     `overrides` field does, and `npm pkg set` edits the manifest without
 *     touching `node_modules` or running any script.
 */
async function runNpmOutdated(projectPath, cves) {
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
    const directDeps = readNpmDirectDependencies(projectPath);
    const out = [];
    for (const [pkg, raw] of Object.entries(parsed)) {
        if (!raw || typeof raw !== 'object')
            continue;
        const row = raw;
        const installed = typeof row['current'] === 'string' ? row['current'] : '';
        const npmLatest = typeof row['latest'] === 'string' ? row['latest'] : '';
        if (!installed)
            continue;
        const cve = cves.get(pkg.toLowerCase());
        // Minimum fixed version wins over npm's own "latest" when fixing a CVE.
        const latest = (cve?.fixedVersion && cve.fixedVersion) || npmLatest;
        if (!latest || installed === latest)
            continue;
        // Defaults to `false` (a real `npm install`) whenever `directDeps` is
        // empty from a package.json read failure — never to `overrides`, which
        // this module comment's own reproduction shows can silently leave a
        // vulnerable package completely unfixed when the directness guess is
        // wrong. `npm install pkg@version` at least attempts a real fix either
        // way; `overrides` alone (no accompanying install) never does.
        const isTransitive = cve !== undefined && directDeps.size > 0 && !directDeps.has(pkg);
        out.push(isTransitive
            ? buildOverrideStep({
                package_name: pkg,
                installed_version: installed,
                latest_version: latest,
                cve,
            })
            : buildStep({
                package_name: pkg,
                installed_version: installed,
                latest_version: latest,
                ecosystem: 'npm',
                cves,
                upgrade_command: `npm install ${pkg}@${latest} --ignore-scripts`,
            }));
    }
    return out;
}
/**
 * The package NAMES this project's own `package.json` declares directly
 * (`dependencies` + `devDependencies` + `optionalDependencies` +
 * `peerDependencies`) — used to tell a direct dependency apart from a
 * transitive one.
 *
 * **Not** `npm outdated --json`'s own `dependent` field: measured directly
 * against a real npm install, `dependent` for a TOP-LEVEL package is not
 * this project's `package.json` `name` at all — it read the enclosing
 * DIRECTORY's basename instead (`"npmoutdated"` for a project whose
 * `package.json` declared `"name": "x"`). Comparing that against
 * `package.json`'s own `name` field made every direct dependency look
 * transitive: the vulnerable package then got an `overrides` step
 * (`npm pkg set`, which only edits `package.json`) instead of a real
 * `npm install`, so `node_modules`/`package-lock.json` never actually
 * changed and the re-scan still found the same CVE — reproduced against a
 * genuine Trivy scan of a genuine `npm install`, not simulated.
 */
function readNpmDirectDependencies(projectPath) {
    const out = new Set();
    try {
        const raw = readFileSync(join(projectPath, 'package.json'), 'utf8');
        const pkg = JSON.parse(raw);
        for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
            const deps = pkg[field];
            if (deps && typeof deps === 'object') {
                for (const name of Object.keys(deps))
                    out.add(name);
            }
        }
    }
    catch {
        /* unreadable/unparseable — returns empty, and the call site treats an
         * empty set as "cannot tell", defaulting to a real npm install rather
         * than guessing transitive (see runNpmOutdated's own comment on why). */
    }
    return out;
}
function buildOverrideStep(input) {
    return {
        package_name: input.package_name,
        installed_version: input.installed_version,
        latest_version: input.latest_version,
        ecosystem: 'npm',
        classification: 'security',
        reason: `Active CVE (${input.cve.cveIds.join(', ')}) on a transitive dependency — pinned via npm overrides`,
        cve_ids: input.cve.cveIds,
        // `npm pkg set` only rewrites package.json — no node_modules install, no
        // script of any kind runs, which is why this step does not also need
        // --ignore-scripts.
        upgrade_command: `npm pkg set overrides.${input.package_name}=${input.latest_version}`,
    };
}
/**
 * pip branch (item 4). Previously this ran `pip list --outdated` /
 * (nominally) `pip install -U` — both against whatever Python interpreter
 * happens to be on the MCP host's own PATH, which is never this project's
 * environment and, for `pip install -U`, would upgrade the HOST's global
 * site-packages. Neither the host's installed-package list nor a live
 * registry query is used any more: this reads the project's OWN
 * `requirements*.txt` pins (`pkg==version`, the only specifier exact enough
 * to know an "installed" version without inspecting an environment) and
 * proposes a step only for a pin with an active CVE and a known
 * `cves.fixed_version` — the same "plan by editing pins in the target tree"
 * shape a `pyproject.toml`-only project gets from `runDotnetOutdated`'s
 * siblings for their own ecosystems.
 *
 * `upgrade_command` is deliberately NOT a real `pip`/`sed` invocation: there
 * is no cross-platform, shell-free, whitespace-only-tokenised command that
 * edits one line of a text file (`fixpr/apply.ts`'s own `toArgv` requires
 * exactly that — see its module comment). It names the file and the pin
 * change in a fixed, parseable shape instead; a literal attempt to execute
 * it fails closed (unknown binary) rather than touching anything. Task 11
 * matches on the structured fields (`package_name`, `ecosystem`,
 * `installed_version`, `latest_version`, `cve_ids`) to perform the actual
 * edit, not on this string.
 */
async function runPipPlan(projectPath, cves) {
    const out = [];
    for (const file of findPipRequirementsFiles(projectPath)) {
        for (const pin of parsePinnedRequirements(file.content)) {
            const step = buildPipSecurityStep({ file: file.relPath, pin, cves });
            if (step)
                out.push(step);
        }
    }
    for (const pin of parsePyprojectPins(projectPath)) {
        const step = buildPipSecurityStep({ file: 'pyproject.toml', pin, cves });
        if (step)
            out.push(step);
    }
    return out;
}
function buildPipSecurityStep(opts) {
    const cve = opts.cves.get(opts.pin.name.toLowerCase());
    if (!cve || !cve.fixedVersion || cve.fixedVersion === opts.pin.version)
        return null;
    return {
        package_name: opts.pin.name,
        installed_version: opts.pin.version,
        latest_version: cve.fixedVersion,
        ecosystem: 'pip',
        classification: 'security',
        reason: `Active CVE (${cve.cveIds.join(', ')}) on the pinned version`,
        cve_ids: cve.cveIds,
        upgrade_command: `pip-pin ${opts.file} ${opts.pin.name}==${cve.fixedVersion}`,
    };
}
/** `requirements*.txt` at the project root, plus one level into a
 *  `requirements/` directory — same shallow scope `deps_audit.ts`'s own
 *  pip-audit wiring uses (not shared code: that module belongs to a
 *  different tool). */
function findPipRequirementsFiles(projectPath) {
    const out = [];
    const tryRead = (relPath) => {
        try {
            out.push({ relPath, content: readFileSync(join(projectPath, relPath), 'utf8') });
        }
        catch {
            /* unreadable — skip */
        }
    };
    let rootEntries = [];
    try {
        rootEntries = readdirSync(projectPath);
    }
    catch {
        return out;
    }
    for (const name of rootEntries) {
        if (/^requirements.*\.txt$/i.test(name))
            tryRead(name);
    }
    const reqDir = join(projectPath, 'requirements');
    if (existsSync(reqDir)) {
        try {
            for (const name of readdirSync(reqDir)) {
                if (name.toLowerCase().endsWith('.txt'))
                    tryRead(join('requirements', name));
            }
        }
        catch {
            /* best-effort */
        }
    }
    return out;
}
/** Lines of the exact shape `pkg==1.2.3` (optionally with inline
 *  whitespace/comment) — the only pip requirement specifier precise enough
 *  to name a single "installed" version without inspecting an environment.
 *  A range (`>=`, `~=`, `<`) or an unpinned name is left alone: there is no
 *  single version to compare a CVE's fixed version against. */
function parsePinnedRequirements(content) {
    const out = [];
    for (const lineRaw of content.split(/\r?\n/)) {
        const line = lineRaw.split('#')[0]?.trim() ?? '';
        if (!line || line.startsWith('-'))
            continue; // -r other.txt, --index-url, etc.
        const m = /^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._-]+)$/.exec(line);
        if (!m)
            continue;
        const name = m[1];
        const version = m[2];
        if (name && version)
            out.push({ name, version });
    }
    return out;
}
/**
 * PEP 621 `[project] dependencies = ["pkg==1.2.3", …]` exact pins only — a
 * regex scan over the raw text, the same simplicity
 * `licenseCompatibility.ts#detectProjectLicense` already uses for this same
 * file rather than adding a TOML parser dependency for one array. Poetry's
 * own `[tool.poetry.dependencies]` table (`pkg = "1.2.3"`) is a different,
 * non-PEP-621 shape and is out of scope here.
 */
function parsePyprojectPins(projectPath) {
    const out = [];
    let raw;
    try {
        raw = readFileSync(join(projectPath, 'pyproject.toml'), 'utf8');
    }
    catch {
        return out;
    }
    const block = /dependencies\s*=\s*\[([^\]]*)\]/i.exec(raw);
    if (!block || !block[1])
        return out;
    const entryPattern = /["']([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._-]+)["']/g;
    let m;
    while ((m = entryPattern.exec(block[1])) !== null) {
        const name = m[1];
        const version = m[2];
        if (name && version)
            out.push({ name, version });
    }
    return out;
}
async function runComposerOutdated(projectPath, cves) {
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
            cves,
            upgrade_command: `composer require ${name}:^${latest}`,
        }));
    }
    return out;
}
async function runCargoOutdated(projectPath, cves) {
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
            cves,
            upgrade_command: `cargo update -p ${name} --precise ${latest}`,
        }));
    }
    return out;
}
async function runGoOutdated(projectPath, cves) {
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
            cves,
            upgrade_command: `go get ${name}@${latest}`,
        }));
    }
    return out;
}
async function runBundlerOutdated(projectPath, cves) {
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
            cves,
            upgrade_command: `bundle update ${name}`,
        }));
    }
    return out;
}
async function runDotnetOutdated(projectPath, cves) {
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
        return parseDotnetJson(r.stdout, cves);
    }
    // Fallback to text parsing.
    const fallback = await execa('dotnet', ['list', 'package', '--outdated'], { cwd: projectPath, reject: false, timeout: 90_000 });
    if (fallback.exitCode !== 0 || fallback.stdout.trim().length === 0)
        return [];
    return parseDotnetText(fallback.stdout, cves);
}
function parseDotnetJson(raw, cves) {
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
                    cves,
                    upgrade_command: `dotnet add package ${name} --version ${latest}`,
                }));
            }
        }
    }
    return out;
}
function parseDotnetText(text, cves) {
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
            cves,
            upgrade_command: `dotnet add package ${name} --version ${latest}`,
        }));
    }
    return out;
}
function buildStep(input) {
    const semverKind = semverDiffKind(input.installed_version, input.latest_version);
    const cve = input.cves.get(input.package_name.toLowerCase());
    const classification = cve ? 'security' : (semverKind ?? 'major');
    const step = {
        package_name: input.package_name,
        installed_version: input.installed_version,
        latest_version: input.latest_version,
        ecosystem: input.ecosystem,
        classification,
        upgrade_command: input.upgrade_command,
    };
    if (cve) {
        step.reason = `Active CVE (${cve.cveIds.join(', ')}) on installed version`;
        step.cve_ids = cve.cveIds;
    }
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