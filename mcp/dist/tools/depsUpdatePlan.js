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
 *        npm      → `npm outdated --json` for direct-dependency current/
 *                    latest, PLUS a sweep of the whole CVE map for anything
 *                    that listing never surfaces — `npm outdated --json`
 *                    has listed only DIRECT dependencies since npm 7, so a
 *                    transitive package never appears in it at all. Every
 *                    CVE-driven target is the smallest version STRICTLY
 *                    ABOVE what is currently installed
 *                    (`../deps/versionCompare.js#minCleanVersionAbove`, or
 *                    its `...Loose` counterpart for a PRE-RELEASE install —
 *                    fix round 3, item N2: `2.0.0-beta.1` is genuinely
 *                    below a clean `2.0.1` fix, which the strict clean-
 *                    version check alone cannot see) — never a scanner's
 *                    raw "fixed_version" taken on faith, which can be an
 *                    older release branch's own backport, simply stale
 *                    (`already_fixed` — never relabels a resolved CVE
 *                    `security` on the strength of an ordinary npm-latest
 *                    bump; only ever claimed for a CLEAN installed version,
 *                    never a pre-release), or belonging to some OTHER
 *                    ecosystem the CVE table's own lack of an ecosystem
 *                    column cannot rule out (the CVE-map sweep only claims
 *                    a package `package-lock.json` / `node_modules` —
 *                    including pnpm's own flat `.pnpm` store, fix round 3 —
 *                    actually resolves, case-insensitively, keyed by the
 *                    LOCKFILE's own spelling of the name). Every
 *                    `npm install` carries `--ignore-scripts`; a transitive
 *                    CVE'd package gets an `npm pkg set
 *                    overrides[<pkg>]=<version>` step (bracket notation — a
 *                    dotted package name would otherwise become a nested
 *                    key; deliberately UNQUOTED — `create_fix_pr` runs this
 *                    without a shell, and fix round 2's own quoting
 *                    corrupted `package.json` there; a shell-quoted,
 *                    paste-safe copy is in `shell_command` instead) with a
 *                    `follow_up_command` of `npm install --ignore-scripts`
 *                    to re-resolve the lockfile. A direct dependency `npm
 *                    outdated` never lists (already at latest, or npm could
 *                    not reach the registry) is judged against the version
 *                    `package-lock.json` / `node_modules` actually holds:
 *                    `already_fixed`, a real minimum-fix install step, or
 *                    `unplanned` — never silently skipped. A project managed
 *                    by pnpm or yarn gets NO npm command at all: every CVE'd
 *                    package is `unplanned` with that manager's own manual
 *                    fix (`pnpm.overrides` / `resolutions`), and the manager
 *                    is named in `unsupported_ecosystems_present`;
 *        pip      → NEVER runs pip/pip-audit against the host interpreter.
 *                    Reads this project's own `requirements*.txt` pins
 *                    (including pip-compile hash-continuation lines,
 *                    extras and environment markers) and PEP 621
 *                    `[project] dependencies` — scoped to that ONE TOML
 *                    table (fix round 3: a `[tool.uv] dev-dependencies`
 *                    array earlier in the same file used to win an
 *                    unscoped substring search outright), extras and range
 *                    specs included (a depth-counting array parser, not a
 *                    `[^\]]*` regex that stopped at an extras marker's own
 *                    `]`), environment markers stripped before matching on
 *                    either path — and proposes a step only for an exact
 *                    pin with an active CVE and a fix version above the pin
 *                    — see `runPipPlan`'s own doc comment for why
 *                    `upgrade_command` is not a real, executable command
 *                    here, and why the target file is also exposed as a
 *                    structured `file` field. Pip has NO CVE-map sweep of
 *                    its own (fix round 3: the earlier one mislabelled
 *                    non-pip packages, e.g. a composer or Go one, `'pip'`
 *                    purely because npm did not resolve them) — a
 *                    genuinely transitive pip dependency with no manifest
 *                    mention now surfaces through the catch-all below;
 *        composer / cargo / go / rubygems / dotnet → each stack's own
 *                    "outdated" command. dotnet runs one explicit
 *                    `dotnet restore <target> --locked-mode` per root
 *                    solution/project FIRST (a stale-but-present `obj/`
 *                    otherwise makes `dotnet list --no-restore` report the
 *                    OLD resolution), planned by `../deps/dotnetRestore.ts`
 *                    so it never creates or rewrites a lock file — see
 *                    `runDotnetOutdated`.
 *      (Other stacks return an empty plan with `unsupported_ecosystems_present`.)
 *      **A runner that could not do its job** — its command missing or
 *      failing, a .NET restore refused (`NU1004`) or unable to reach its
 *      feed (`NU1301`) — is reported in `runner_failures` (ecosystem, code,
 *      reason, target), so an empty plan for that ecosystem never reads as
 *      "nothing to upgrade".
 *      **Every package with an active CVE that did NOT become a step is
 *      reported in `unplanned`** (package, ecosystem, cve_ids, reason) —
 *      never silently dropped: a non-exact pip specifier, a CVE whose only
 *      reported fix is a downgrade or already resolved, a transitive
 *      package with no recorded installed version to compare against, a
 *      pnpm/yarn project. As a final catch-all (`appendCatchAllUnplanned`),
 *      any CVE key still unclaimed after every runner has had a turn is
 *      reported with the reason that actually applies: declared in a
 *      manifest whose runner failed, declared in a manifest whose runner
 *      does not plan it, or declared nowhere in the project.
 *   3. Classify each entry as patch / minor / major (by semver diff).
 *   4. Mark entries as `security` when an active CVE exists for the package —
 *      sourced from the latest `deps` / `deps_audit` / `security_full` scan
 *      of THIS SAME PROJECT (`CVE_SOURCE_SCAN_TYPES`, `../types.js`), never
 *      an unscoped "whatever scan is latest in the whole database" lookup.
 *      Only the npm and pip branches target the MINIMUM fixed version; the
 *      composer/cargo/go/rubygems/dotnet steps keep their "outdated"
 *      command's latest version, and the tool description says so.
 *   5. Order the result by `prefer` (default: security, then patch, then
 *      minor, then major).
 */
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { execa } from 'execa';
import { z } from 'zod';
import { classifyRestoreFailure, findDotnetTargets, lockFileCandidates, planDotnetRestore, projectsForTarget, readPackageReferences, removeCreatedLockFiles, } from '../deps/dotnetRestore.js';
import { compareVersions, compareVersionsLoose, isCleanVersion, isLooseVersion, minCleanVersionAbove, minCleanVersionAboveLoose, } from '../deps/versionCompare.js';
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
        'each stack\'s own "outdated" command; for .NET that is preceded by `dotnet restore ' +
        '--locked-mode`, which EXECUTES the project\'s own MSBuild and contacts its NuGet feeds (it ' +
        'never creates or rewrites a packages.lock.json). pip reads this project\'s own ' +
        'requirements*.txt / pyproject.toml pins and never touches the host Python. pnpm and yarn ' +
        'projects get no npm commands — their CVEs are listed with the pnpm.overrides / resolutions ' +
        'fix to apply by hand (workspace members included). Classifies each entry as security (an ' +
        'active CVE in the same project\'s latest deps scan — npm/pip target the MINIMUM fixed version, ' +
        'other stacks the latest available) / patch / minor / major, and returns a sortable, structured ' +
        'plan (package_name, ecosystem, installed_version, latest_version, cve_ids, upgrade_command), ' +
        '`unplanned` (every CVE that got no step, with why) and `runner_failures` (every ecosystem ' +
        'command that failed, with its code — e.g. NU1004 lock out of sync vs NU1301 feed unreachable).',
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
    const plansByEcosystem = await Promise.all(ecosystems.map(async (eco) => {
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
                return { steps: [], unplanned: [] };
        }
    }));
    const flat = plansByEcosystem.flatMap((p) => p.steps);
    const unplanned = plansByEcosystem.flatMap((p) => p.unplanned);
    const runnerFailures = plansByEcosystem.flatMap((p) => p.failures ?? []);
    appendCatchAllUnplanned({ projectPath, cves, steps: flat, unplanned, runnerFailures });
    const ordered = orderPlan(flat, inp.prefer ?? 'security');
    const summary = summarize(ordered);
    return {
        ok: true,
        plan: ordered,
        summary,
        unplanned,
        runner_failures: runnerFailures,
        stack_detected: ecosystems,
        unsupported_ecosystems_present: [
            ...detectUnsupportedEcosystems(projectPath),
            ...plansByEcosystem.flatMap((p) => p.unsupported ?? []),
        ],
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
    // The same target discovery `deps_audit` uses (a root solution, else every
    // project file) — a repo whose only .csproj lives under src/ has a .NET
    // stack too.
    if (findDotnetTargets(projectPath).length > 0)
        out.push('dotnet');
    return out;
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
 * The final safety net: every CVE key that, after every ecosystem runner has
 * had a turn, produced NEITHER a step NOR an `unplanned` entry is pushed to
 * `unplanned` here. The `cves` table has no ecosystem column, and each runner
 * only claims a package it has real evidence for (a manifest mention, an
 * "outdated" listing, a resolved lockfile entry), so without this a package
 * outside every runner's evidence would vanish from both lists.
 *
 * The evidence read here is every manifest AND every non-JS lockfile
 * (`readDependencyEvidence`): a package a lockfile resolves is attributed to
 * that lockfile's ecosystem even when no manifest names it — the transitive
 * `psr/log` in a `composer.lock` is composer's, not `unknown`. The reason
 * says which situation applies, because they call for different actions:
 *
 *   0. every version the evidence records is at or above the fix —
 *      `already_fixed`, exactly as the npm branch reports it;
 *   1. the runner for its ecosystem FAILED (a .NET restore refused with
 *      `NU1004`, a feed that could not be reached, a missing `composer`) —
 *      the reason names the failure;
 *   2. it is declared in a manifest whose runner ran fine but only plans what
 *      its own "outdated" command lists (composer, cargo, go, bundler, and
 *      .NET's top-level listing);
 *   3. only a lockfile resolves it (a transitive dependency of that stack),
 *      below the fix, and the runner did not list it;
 *   4. no manifest declares it, no lockfile read here resolves it, and no
 *      runner listed it — ecosystem `unknown`, naming any runner that failed.
 */
function appendCatchAllUnplanned(opts) {
    const { projectPath, cves, steps, unplanned, runnerFailures } = opts;
    const named = new Set([
        ...steps.map((s) => s.package_name.toLowerCase()),
        ...unplanned.map((u) => u.package_name.toLowerCase()),
    ]);
    let evidenceMap;
    for (const [pkgLower, cve] of cves) {
        if (named.has(pkgLower))
            continue;
        evidenceMap ??= readDependencyEvidence(projectPath);
        const evidence = evidenceMap.get(pkgLower);
        const fix = cve.fixedVersion ? ` (fixed in ${cve.fixedVersion})` : '';
        if (evidence) {
            const { ecosystem } = evidence;
            const versions = [...evidence.versions];
            const where = [evidence.declaredIn, evidence.lockFile].filter((f) => f !== undefined).join(' / ');
            if (versions.length > 0 && versions.every((v) => isAlreadyFixed(v, cve))) {
                unplanned.push(alreadyFixedEntry(cve.displayName, cve, `${versions.join(', ')} (${where})`, ecosystem));
                continue;
            }
            const at = versions.length > 0 ? ` at ${versions.join(', ')}` : '';
            const failed = runnerFailures.filter((f) => f.ecosystem === ecosystem);
            let reason;
            if (failed.length > 0) {
                reason =
                    `${evidence.declaredIn ? 'declared in' : 'resolved in'} ${where}${at}, but the ${ecosystem} runner ` +
                        `failed — ${failed.map(describeFailure).join('; ')} — so no upgrade could be planned${fix}`;
            }
            else if (evidence.declaredIn) {
                reason =
                    `declared in ${where}${at}, but the ${ecosystem} runner only plans what ` +
                        `${OUTDATED_COMMAND[ecosystem]} lists, and it did not list this package — no CVE-driven ` +
                        `step; upgrade it manually${fix}`;
            }
            else {
                reason =
                    `resolved in ${where}${at} as a transitive dependency (no manifest declares it), and ` +
                        `${OUTDATED_COMMAND[ecosystem]} did not list it — upgrade the package that requires it, or ` +
                        `constrain it directly${fix}`;
            }
            unplanned.push({ package_name: cve.displayName, ecosystem, cve_ids: cve.cveIds, reason });
            continue;
        }
        unplanned.push({
            package_name: cve.displayName,
            ecosystem: 'unknown',
            cve_ids: cve.cveIds,
            reason: `no manifest declares it and no runner listed it, and none of the lockfiles read here ` +
                `(${LOCKFILES_READ}) resolves it` +
                (runnerFailures.length > 0
                    ? ` — a runner that might have resolved it failed: ${runnerFailures.map(describeFailure).join('; ')}${fix}`
                    : ` — a dependency of a stack deps_update_plan cannot resolve, or a CVE row for a package no ` +
                        `longer present${fix}`),
        });
    }
}
/** Named in the `unknown` reason, so it never claims more than was read.
 *  The npm/pnpm/yarn locks are read by the npm runner itself, which claims
 *  every package they resolve. */
const LOCKFILES_READ = 'package-lock.json / pnpm-lock.yaml / yarn.lock, composer.lock, Cargo.lock, go.sum, Gemfile.lock, packages.lock.json';
function describeFailure(f) {
    return `${f.ecosystem}${f.target ? ` (${f.target})` : ''}: ${f.code} — ${f.reason}`;
}
const OUTDATED_COMMAND = {
    npm: '`npm outdated`',
    pip: 'an exact pin',
    composer: '`composer outdated`',
    cargo: '`cargo outdated`',
    go: '`go list -m -u`',
    rubygems: '`bundle outdated`',
    dotnet: '`dotnet list package --outdated` (top-level references only)',
    unknown: 'its own listing',
};
/**
 * Every package this project's manifests DECLARE or its non-JS lockfiles
 * RESOLVE, lowercased, with the ecosystem that owns it and every version
 * recorded — the evidence the catch-all needs for a package no runner
 * claimed. Read directly from the files, never from a runner's output (a
 * runner that failed has no output). The first ecosystem to claim a name
 * keeps it; a lockfile of the SAME ecosystem adds its versions.
 */
function readDependencyEvidence(projectPath) {
    const out = new Map();
    const entry = (name, ecosystem) => {
        const key = name.trim().toLowerCase();
        if (!key)
            return undefined;
        const existing = out.get(key);
        if (existing)
            return existing.ecosystem === ecosystem ? existing : undefined;
        const created = { ecosystem, versions: new Set() };
        out.set(key, created);
        return created;
    };
    const declare = (name, ecosystem, file, version) => {
        const e = entry(name, ecosystem);
        if (!e)
            return;
        e.declaredIn ??= file;
        if (version)
            e.versions.add(version);
    };
    const resolve = (name, ecosystem, file, version) => {
        const e = entry(name, ecosystem);
        if (!e)
            return;
        e.lockFile ??= file;
        if (version)
            e.versions.add(version);
    };
    const readJson = (file) => {
        try {
            const parsed = JSON.parse(readFileSync(join(projectPath, file), 'utf8'));
            return parsed && typeof parsed === 'object' ? parsed : undefined;
        }
        catch {
            return undefined;
        }
    };
    const readText = (file) => {
        try {
            return readFileSync(join(projectPath, file), 'utf8');
        }
        catch {
            return '';
        }
    };
    const declareKeys = (obj, ecosystem, file) => {
        if (obj && typeof obj === 'object')
            for (const k of Object.keys(obj))
                declare(k, ecosystem, file);
    };
    // ---- manifests
    const pkg = readJson('package.json');
    for (const f of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
        declareKeys(pkg?.[f], 'npm', 'package.json');
    }
    const composer = readJson('composer.json');
    declareKeys(composer?.['require'], 'composer', 'composer.json');
    declareKeys(composer?.['require-dev'], 'composer', 'composer.json');
    // Cargo.toml: keys of every *dependencies table, plus `[dependencies.<name>]` headers.
    let inDeps = false;
    for (const line of readText('Cargo.toml').split(/\r?\n/)) {
        const header = /^\s*\[([^\]]+)\]\s*(?:#.*)?$/.exec(line);
        if (header?.[1]) {
            const table = header[1].trim();
            const dotted = /(?:^|\.)(?:dev-|build-)?dependencies\.([A-Za-z0-9_-]+)$/.exec(table);
            if (dotted?.[1])
                declare(dotted[1], 'cargo', 'Cargo.toml');
            inDeps = /(?:^|\.)(?:dev-|build-)?dependencies$/.test(table);
            continue;
        }
        const key = inDeps ? /^\s*([A-Za-z0-9_-]+)\s*=/.exec(line) : null;
        if (key?.[1])
            declare(key[1], 'cargo', 'Cargo.toml');
    }
    // go.mod: `require path v1.2.3` and every line of a `require ( … )` block —
    // direct and `// indirect` alike. The version there IS the selected one.
    let inRequire = false;
    for (const line of readText('go.mod').split(/\r?\n/)) {
        const t = line.replace(/\/\/.*$/, '').trim();
        if (/^require\s*\($/.test(t))
            inRequire = true;
        else if (inRequire && t === ')')
            inRequire = false;
        else {
            const m = inRequire ? /^(\S+)\s+(v\S+)/.exec(t) : /^require\s+(\S+)\s+(v\S+)/.exec(t);
            if (m?.[1])
                declare(m[1], 'go', 'go.mod', m[2]);
        }
    }
    for (const m of readText('Gemfile').matchAll(/^\s*gem\s+['"]([^'"]+)['"]/gm)) {
        if (m[1])
            declare(m[1], 'rubygems', 'Gemfile');
    }
    const projects = findDotnetTargets(projectPath).flatMap((t) => projectsForTarget(t));
    for (const [name, file] of readPackageReferences(projects))
        declare(name, 'dotnet', relative(projectPath, file) || file);
    // ---- lockfiles
    const composerLock = readJson('composer.lock');
    for (const section of ['packages', 'packages-dev']) {
        const list = composerLock?.[section];
        if (!Array.isArray(list))
            continue;
        for (const p of list) {
            const rec = p && typeof p === 'object' ? p : undefined;
            const name = rec?.['name'];
            const version = rec?.['version'];
            if (typeof name === 'string')
                resolve(name, 'composer', 'composer.lock', typeof version === 'string' ? version : undefined);
        }
    }
    // Cargo.lock: `[[package]]` blocks of `name = "…"` / `version = "…"`.
    let cargoName;
    for (const line of readText('Cargo.lock').split(/\r?\n/)) {
        if (/^\s*\[\[package\]\]\s*$/.test(line))
            cargoName = undefined;
        const n = /^\s*name\s*=\s*"([^"]+)"/.exec(line);
        if (n?.[1])
            cargoName = n[1];
        const v = /^\s*version\s*=\s*"([^"]+)"/.exec(line);
        if (v?.[1] && cargoName !== undefined) {
            resolve(cargoName, 'cargo', 'Cargo.lock', v[1]);
            cargoName = undefined;
        }
    }
    // go.sum lists every version the module graph ever needed, not only the
    // selected one: it attributes a module go.mod does not name, and adds a
    // version only for such a module (go.mod's own version is the selected one).
    for (const line of readText('go.sum').split(/\r?\n/)) {
        const m = /^(\S+)\s+(v[^\s/]+)(\/go\.mod)?\s/.exec(line);
        if (!m?.[1])
            continue;
        const inGoMod = out.get(m[1].toLowerCase())?.declaredIn === 'go.mod';
        resolve(m[1], 'go', 'go.sum', inGoMod || m[3] ? undefined : m[2]);
    }
    // Gemfile.lock: `    name (version)` at four spaces under a `specs:` block
    // (six spaces are that gem's own dependency constraints).
    for (const m of readText('Gemfile.lock').matchAll(/^ {4}([^\s(]+) \(([^)]+)\)\s*$/gm)) {
        if (m[1])
            resolve(m[1], 'rubygems', 'Gemfile.lock', m[2]);
    }
    // NuGet packages.lock.json next to every project the solution lists:
    // `dependencies.<framework>.<package>.resolved`, direct and transitive.
    for (const project of projects) {
        for (const lock of lockFileCandidates(project)) {
            let parsed;
            try {
                parsed = JSON.parse(readFileSync(lock, 'utf8'));
            }
            catch {
                continue;
            }
            const frameworks = parsed?.dependencies;
            if (!frameworks || typeof frameworks !== 'object')
                continue;
            for (const deps of Object.values(frameworks)) {
                if (!deps || typeof deps !== 'object')
                    continue;
                for (const [name, info] of Object.entries(deps)) {
                    const resolved = info && typeof info === 'object' ? info['resolved'] : undefined;
                    resolve(name, 'dotnet', relative(projectPath, lock) || lock, typeof resolved === 'string' ? resolved : undefined);
                }
            }
        }
    }
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
        // history has both), and a CVE row can simply be STALE (recorded
        // against an older installed version than what a fresh ecosystem query
        // reports now). `minCleanVersionAbove` — never a raw `fixed_version`
        // read verbatim — is what keeps a package with several active CVEs,
        // some clean and one messy or stale, from silently ending up with a
        // downgrade as its computed minimum (fix round 1, CRITICAL item 1).
        const existing = out.get(key);
        const installedForThisCve = cve.installed_version;
        const candidate = minCleanVersionAbove(installedForThisCve, [cve.fixed_version]);
        if (existing) {
            existing.cveIds.push(cve.cve_id);
            if (existing.installedVersion === undefined)
                existing.installedVersion = installedForThisCve;
            // The MINIMUM version that clears every active CVE is the MAXIMUM of
            // each individual CVE's own minimum fix — installing anything less
            // than the highest one leaves that CVE's own fix unmet.
            if (candidate !== undefined &&
                (existing.fixedVersion === undefined || compareVersions(candidate, existing.fixedVersion) > 0)) {
                existing.fixedVersion = candidate;
            }
        }
        else {
            out.set(key, {
                cveIds: [cve.cve_id],
                fixedVersion: candidate,
                installedVersion: installedForThisCve,
                displayName: cve.package_name,
            });
        }
    }
    return out;
}
// ---------------------------------------------------------------------- runners
/**
 * npm branch (item 4, fix round 1 items 1 and 2):
 *   - a package with an active CVE upgrades to the MINIMUM fixed version
 *     (`cves.fixed_version`) rather than `npm outdated`'s own `latest` —
 *     the smallest change that actually resolves the CVE, not whatever is
 *     newest today — and NEVER a downgrade: `minCleanVersionAbove` compares
 *     against THIS run's own `npm outdated` "current" value, the freshest
 *     installed-version signal available, not just the (possibly stale)
 *     value the CVE row was recorded against;
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
 *     `overrides` field does. `npm pkg set` edits the manifest only, so
 *     every override step also carries a `follow_up_command`
 *     (`npm install --ignore-scripts`, no explicit package) to re-resolve
 *     the lockfile;
 *   - a CVE whose recorded fix is already at or below what is INSTALLED —
 *     read from `npm outdated`'s "current", or, for a package `npm outdated`
 *     does not list (it is already at latest, or npm could not reach the
 *     registry), from `package-lock.json` / `node_modules` — is reported
 *     `already_fixed`, never planned and never dropped;
 *   - a project managed by **pnpm or yarn** gets no npm command at all
 *     (`planForNonNpmManager`).
 *
 * **Driven from the CVE map, not from `npm outdated`'s own listing, for the
 * transitive case.** `npm outdated --json` has listed ONLY direct
 * dependencies since npm 7 — a transitive package never appears in it at
 * all, so a check that only classifies entries FROM that listing (`pkg in
 * parsed`) can never actually reach the transitive branch against a real
 * npm install; it only fired in a hand-built mock. Pass 1 below still reads
 * `npm outdated` for direct-dependency current/latest info; pass 2 sweeps
 * the WHOLE `cves` map for anything pass 1 did not already handle.
 */
async function runNpmOutdated(projectPath, cves) {
    const manager = detectNpmPackageManager(projectPath);
    if (manager.name !== 'npm')
        return planForNonNpmManager(projectPath, cves, manager);
    const result = await execa('npm', ['outdated', '--json'], {
        cwd: projectPath,
        reject: false,
        timeout: 60_000,
    });
    const steps = [];
    const unplanned = [];
    const failures = [];
    let outdatedObj = {};
    const stdout = typeof result.stdout === 'string' ? result.stdout : '';
    if (stdout.trim().length > 0) {
        try {
            const parsed = JSON.parse(stdout);
            if (parsed && typeof parsed === 'object') {
                const error = parsed['error'];
                // npm reports its own failures (registry unreachable, a broken
                // install) as `{ "error": { "code", "summary" } }` on stdout, with
                // the SAME exit code 1 it uses for "something is outdated".
                if (error && typeof error === 'object') {
                    const e = error;
                    failures.push({
                        ecosystem: 'npm',
                        code: typeof e['code'] === 'string' ? e['code'] : 'npm_error',
                        reason: `\`npm outdated\` failed: ${typeof e['summary'] === 'string' ? e['summary'] : 'see npm output'}`,
                    });
                }
                else {
                    outdatedObj = parsed;
                }
            }
        }
        catch {
            failures.push({ ecosystem: 'npm', code: 'unparseable_output', reason: '`npm outdated --json` printed something that is not JSON' });
        }
    }
    const exitFailure = describeExecFailure('npm outdated', result, [0, 1]);
    if (exitFailure && failures.length === 0)
        failures.push({ ecosystem: 'npm', ...exitFailure });
    const directDeps = readNpmDirectDependencies(projectPath);
    const handled = new Set(); // lowercased names pass 1 already decided
    // Pass 1: npm outdated's own entries — direct dependencies only, on a
    // real npm 7+ install (see this function's own doc comment).
    for (const [pkg, raw] of Object.entries(outdatedObj)) {
        if (!raw || typeof raw !== 'object')
            continue;
        const row = raw;
        const installed = typeof row['current'] === 'string' ? row['current'] : '';
        const npmLatest = typeof row['latest'] === 'string' ? row['latest'] : '';
        if (!installed)
            continue;
        const pkgLower = pkg.toLowerCase();
        handled.add(pkgLower);
        const cve = cves.get(pkgLower);
        // The CVE's own minimum fix, checked against THIS run's actual current
        // version — never the (possibly stale) version the CVE row itself was
        // recorded against. `minCleanVersionAboveLoose`, not the strict
        // `minCleanVersionAbove` (fix round 3, item N2): `installed` can be a
        // PRE-RELEASE (`2.0.0-beta.1`), which the strict clean-version regex
        // rejects outright. The candidate fix itself is still required to be a
        // clean, installable version either way.
        const safeCveVersion = cve ? minCleanVersionAboveLoose(installed, [cve.fixedVersion]) : undefined;
        // Only ever claimed when `installed` is a plain, unambiguous CLEAN
        // version (fix round 3, item N2) — see `isAlreadyFixed`.
        const staleCve = cve !== undefined && isAlreadyFixed(installed, cve);
        if (staleCve && cve)
            unplanned.push(alreadyFixedEntry(pkg, cve, installed));
        const safeNpmLatest = isCleanVersion(npmLatest) && compareVersions(npmLatest, installed) > 0 ? npmLatest : undefined;
        const latest = staleCve ? safeNpmLatest : (safeCveVersion ?? safeNpmLatest);
        if (cve && !staleCve && !latest) {
            unplanned.push({
                package_name: pkg,
                ecosystem: 'npm',
                cve_ids: cve.cveIds,
                reason: 'active CVE, but no safe upgrade target: the reported fix version is not above the ' +
                    'installed version, and npm reports no newer release either',
            });
            continue;
        }
        if (!latest || installed === latest)
            continue;
        if (!staleCve && cve !== undefined && directDeps.size > 0 && !directDeps.has(pkgLower)) {
            steps.push(buildOverrideStep({ package_name: pkg, installed_version: installed, latest_version: latest, cve }));
        }
        else {
            steps.push(buildStep({
                package_name: pkg,
                installed_version: installed,
                latest_version: latest,
                ecosystem: 'npm',
                // A stale CVE must not re-attach its (already resolved) ids via
                // buildStep's own lookup — an empty map forces the ordinary
                // semver classification instead of `security`.
                cves: staleCve ? new Map() : cves,
                upgrade_command: `npm install ${pkg}@${latest} --ignore-scripts`,
            }));
        }
    }
    // Pass 2: CVE'd packages `npm outdated` never lists at all — a TRANSITIVE
    // dependency (npm 7+ never lists one), or a DIRECT dependency npm's own
    // "outdated" check did not flag (already at latest, or npm itself failed).
    // Transitive packages are claimed ONLY when this install's own resolved
    // graph contains them (fix round 2, item 10: the `cves` table has no
    // ecosystem column — a pip `django` or composer `laravel/framework` must
    // never become an npm override step).
    const resolved = readNpmResolvedPackages(projectPath, 'npm');
    for (const [pkgLower, cve] of cves) {
        if (handled.has(pkgLower))
            continue;
        const info = resolved.get(pkgLower);
        if (directDeps.has(pkgLower)) {
            planDirectNotListed({ name: info?.name ?? cve.displayName, installed: info?.topLevel, cve, cves, steps, unplanned });
            continue;
        }
        if (info === undefined)
            continue; // not a package this npm install resolves at all — leave it to its own ecosystem
        const versions = [...info.versions];
        if (versions.length > 0 && versions.every((v) => isAlreadyFixed(v, cve))) {
            unplanned.push(alreadyFixedEntry(info.name, cve, versions.join(', ')));
            continue;
        }
        // The lowest resolved copy still below the fix is what the override has
        // to lift; the CVE row's own recorded version is the fallback when the
        // tree gives no version at all.
        const belowFix = versions
            .filter((v) => isLooseVersion(v) && cve.fixedVersion !== undefined && compareVersionsLoose(v, cve.fixedVersion) < 0)
            .sort(compareVersionsLoose);
        const installed = belowFix[0] ?? cve.installedVersion;
        const target = minCleanVersionAboveLoose(installed, [cve.fixedVersion]);
        if (!installed || !target) {
            // A package this npm graph DOES resolve, but with no recorded
            // installed_version on the CVE row at all — cannot even compute a
            // target, only report the gap when there IS an installed_version.
            if (installed) {
                unplanned.push({
                    package_name: info.name,
                    ecosystem: 'npm',
                    cve_ids: cve.cveIds,
                    reason: `active CVE on a transitive dependency, but no fix version above the installed version ${installed}`,
                });
            }
            continue;
        }
        // `info.name`, NOT `cve.displayName` (fix round 3): `overrides[<name>]`
        // must be keyed by the LOCKFILE's own spelling — a scanner's own casing
        // (`MiniMist`) creates an override for a name that does not exist.
        steps.push(buildOverrideStep({ package_name: info.name, installed_version: installed, latest_version: target, cve }));
    }
    return { steps, unplanned, failures };
}
/** The CVE row's own minimum fix is at or below `installed` — the package
 *  was already upgraded past it and the CVE record is stale. Claimed only
 *  for a CLEAN installed version (fix round 3, item N2): a pre-release, or
 *  anything that is not a version at all, never reads as "already fixed". */
function isAlreadyFixed(installed, cve) {
    return cve.fixedVersion !== undefined && isCleanVersion(installed) && compareVersions(cve.fixedVersion, installed) <= 0;
}
function alreadyFixedEntry(name, cve, installed, ecosystem = 'npm') {
    return {
        package_name: name,
        ecosystem,
        cve_ids: cve.cveIds,
        reason: `already_fixed: installed version ${installed} is already at or above the recorded fix ` +
            `${cve.fixedVersion ?? '(unknown)'} — the CVE record is stale.`,
    };
}
/**
 * A DIRECT dependency with an active CVE that `npm outdated` did not list —
 * usually because it is already at its latest release (then the CVE is
 * almost always stale), or because npm could not reach the registry. The
 * installed version comes from the tree itself (`package-lock.json`, else
 * `node_modules/<name>/package.json`): at or above the fix is
 * `already_fixed`; below it, the minimum fix becomes a real
 * `npm install <name>@<fix> --ignore-scripts` step; no installed version at
 * all is reported, never dropped.
 */
function planDirectNotListed(opts) {
    const { name, installed, cve, cves, steps, unplanned } = opts;
    if (installed === undefined) {
        unplanned.push({
            package_name: name,
            ecosystem: 'npm',
            cve_ids: cve.cveIds,
            reason: 'active CVE on a direct dependency that `npm outdated` did not report, and no installed ' +
                'version was found in package-lock.json or node_modules — install dependencies and re-run',
        });
        return;
    }
    if (isAlreadyFixed(installed, cve)) {
        unplanned.push(alreadyFixedEntry(name, cve, installed));
        return;
    }
    const target = minCleanVersionAboveLoose(installed, [cve.fixedVersion]);
    if (!target) {
        unplanned.push({
            package_name: name,
            ecosystem: 'npm',
            cve_ids: cve.cveIds,
            reason: `active CVE on a direct dependency, but no fix version above the installed ${installed} is known`,
        });
        return;
    }
    steps.push(buildStep({
        package_name: name,
        installed_version: installed,
        latest_version: target,
        ecosystem: 'npm',
        cves,
        upgrade_command: `npm install ${name}@${target} --ignore-scripts`,
    }));
}
/**
 * Which package manager owns this `package.json`. A lockfile in the project
 * decides first (`pnpm-lock.yaml`, `yarn.lock`, then `package-lock.json` /
 * `npm-shrinkwrap.json`). Without one, the project may be a WORKSPACE MEMBER
 * whose lock lives at the workspace root: each ancestor up to the repository
 * root (the nearest directory holding `.git`, else the filesystem root) is
 * checked for `pnpm-workspace.yaml` / `pnpm-lock.yaml` / `yarn.lock` — the
 * nearest one decides, and an ancestor `package-lock.json` /
 * `npm-shrinkwrap.json` stops the walk as npm. Only then the project's own
 * `packageManager` field, then a pnpm store in `node_modules/.pnpm`; npm
 * otherwise. (Fix round 5: a member of a pnpm or yarn workspace used to fall
 * through to npm and get `npm install … --ignore-scripts` steps.)
 */
/** A relative path as a reader types it, on every OS (`../../package.json`). */
function toPosix(p) {
    return p.split(sep).join('/');
}
function detectNpmPackageManager(projectPath) {
    const has = (dir, file) => existsSync(join(dir, file));
    const at = (dir, file) => {
        const rel = toPosix(relative(projectPath, join(dir, file)));
        return dir === projectPath ? file : `${rel}, the workspace root`;
    };
    for (let dir = projectPath;;) {
        if (has(dir, 'pnpm-lock.yaml'))
            return { name: 'pnpm', evidence: at(dir, 'pnpm-lock.yaml'), root: dir };
        if (has(dir, 'pnpm-workspace.yaml'))
            return { name: 'pnpm', evidence: at(dir, 'pnpm-workspace.yaml'), root: dir };
        if (has(dir, 'yarn.lock'))
            return { name: 'yarn', evidence: at(dir, 'yarn.lock'), root: dir };
        if (has(dir, 'package-lock.json') || has(dir, 'npm-shrinkwrap.json')) {
            return { name: 'npm', evidence: 'package-lock.json', root: projectPath };
        }
        if (has(dir, '.git'))
            break;
        const parent = dirname(dir);
        if (parent === dir)
            break;
        dir = parent;
    }
    try {
        const pkg = JSON.parse(readFileSync(join(projectPath, 'package.json'), 'utf8'));
        const pm = typeof pkg['packageManager'] === 'string' ? pkg['packageManager'] : '';
        const m = /^(pnpm|yarn)@/.exec(pm);
        if (m?.[1] === 'pnpm' || m?.[1] === 'yarn') {
            return { name: m[1], evidence: 'package.json "packageManager"', root: projectPath };
        }
    }
    catch {
        /* unreadable package.json — fall through */
    }
    if (existsSync(join(projectPath, 'node_modules', '.pnpm'))) {
        return { name: 'pnpm', evidence: 'node_modules/.pnpm', root: projectPath };
    }
    return { name: 'npm', evidence: 'default', root: projectPath };
}
/**
 * A pnpm or yarn project gets NO npm command. Measured with pnpm 10.33.2:
 * pnpm ignores npm's top-level `overrides` (the lock still resolved
 * `minimist@0.0.8` with `"overrides": {"minimist": "1.2.6"}` in place; with
 * `"pnpm": {"overrides": …}` it resolved `1.2.6`), and an `npm install` in
 * such a tree writes a `package-lock.json` and rebuilds `node_modules` while
 * `pnpm-lock.yaml` / `yarn.lock` — what CI installs from — stays vulnerable.
 * Every CVE'd package the tree declares or resolves is reported `unplanned`
 * with the manual fix spelled out for THAT package manager (`pnpm.overrides`
 * / yarn `resolutions`), or `already_fixed` when every resolved copy is past
 * the fix. Ordinary (non-CVE) upgrades are not listed at all; the manager is
 * named in `unsupported_ecosystems_present` so the omission is visible.
 */
function planForNonNpmManager(projectPath, cves, manager) {
    const directDeps = readNpmDirectDependencies(projectPath);
    const resolved = readNpmResolvedPackages(projectPath, manager.name, manager.root);
    // `pnpm.overrides` and `resolutions` are only honoured in the ROOT
    // package.json of a workspace, and the install runs there.
    const rootManifest = manager.root === projectPath
        ? 'package.json'
        : `the workspace root package.json (${toPosix(relative(projectPath, join(manager.root, 'package.json')))})`;
    const runAt = manager.root === projectPath ? '' : ' at the workspace root';
    const unplanned = [];
    for (const [pkgLower, cve] of cves) {
        const info = resolved.get(pkgLower);
        const direct = directDeps.has(pkgLower);
        if (info === undefined && !direct)
            continue; // not this tree's — the catch-all attributes it
        const name = info?.name ?? cve.displayName;
        const versions = info ? [...info.versions] : [];
        if (versions.length > 0 && versions.every((v) => isAlreadyFixed(v, cve))) {
            unplanned.push(alreadyFixedEntry(name, cve, versions.join(', ')));
            continue;
        }
        const target = cve.fixedVersion ?? '<a version that fixes ' + cve.cveIds.join(', ') + '>';
        const bump = direct ? `raise the "${name}" range in package.json to ${target}, or ` : '';
        const reason = manager.name === 'pnpm'
            ? `pnpm project (${manager.evidence}): no npm command is emitted — npm would write a ` +
                'package-lock.json and rebuild node_modules while pnpm-lock.yaml stays vulnerable, and pnpm ' +
                `ignores npm's top-level "overrides". Fix manually: ${bump}add "pnpm": { "overrides": ` +
                `{ "${name}": "${target}" } } to ${rootManifest}, then run pnpm install --ignore-scripts${runAt}.`
            : `yarn project (${manager.evidence}): no npm command is emitted — npm would write a ` +
                'package-lock.json while yarn.lock stays vulnerable, and yarn reads "resolutions", not ' +
                `npm's "overrides". Fix manually: ${bump}add "resolutions": { "${name}": "${target}" } to ` +
                `${rootManifest}, then run yarn install${runAt} (--ignore-scripts on Yarn 1, --mode=skip-build on Yarn 2+).`;
        unplanned.push({ package_name: name, ecosystem: 'npm', cve_ids: cve.cveIds, reason });
    }
    return { steps: [], unplanned, unsupported: [manager.name] };
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
    // Lowercased (fix round 2, item 10): a legacy package can have declared an
    // uppercase name in `package.json` before npm enforced lowercase package
    // names, and every comparison against this set must agree on case.
    const out = new Set();
    try {
        const raw = readFileSync(join(projectPath, 'package.json'), 'utf8');
        const pkg = JSON.parse(raw);
        for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
            const deps = pkg[field];
            if (deps && typeof deps === 'object') {
                for (const name of Object.keys(deps))
                    out.add(name.toLowerCase());
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
/**
 * Every package the JS dependency tree ACTUALLY resolves — direct or
 * transitive — keyed by lowercased name, read from the manager's own
 * lockfile (`package-lock.json` / `npm-shrinkwrap.json` v1-v3,
 * `pnpm-lock.yaml`, `yarn.lock`) and, when that yields nothing, from
 * `node_modules/` itself (including pnpm's flat `.pnpm` store).
 *
 * **Why this exists**: `cves` (`Map<string, CveInfo>`) has NO ecosystem
 * column — a `django` (pip) or `laravel/framework` (composer) CVE sits in
 * the same table as an npm one, and only a package this function resolves is
 * ever claimed for npm (fix round 2, item 10).
 */
function readNpmResolvedPackages(projectPath, manager, lockDir = projectPath) {
    const out = new Map();
    const add = (name, version, topLevel = false) => {
        const key = name.toLowerCase();
        let entry = out.get(key);
        if (!entry) {
            entry = { name, versions: new Set() };
            out.set(key, entry);
        }
        if (version) {
            entry.versions.add(version);
            if (topLevel && entry.topLevel === undefined)
                entry.topLevel = version;
        }
    };
    // The lockfile lives at `lockDir` — the workspace root for a member.
    const readText = (file) => {
        try {
            return readFileSync(join(lockDir, file), 'utf8');
        }
        catch {
            return undefined;
        }
    };
    if (manager === 'npm') {
        const raw = readText('package-lock.json') ?? readText('npm-shrinkwrap.json');
        if (raw !== undefined) {
            try {
                const lock = JSON.parse(raw);
                const packages = lock['packages'];
                if (packages && typeof packages === 'object') {
                    for (const [key, val] of Object.entries(packages)) {
                        const m = /node_modules\/(@[^/]+\/[^/]+|[^/]+)$/.exec(key);
                        if (!m?.[1])
                            continue;
                        const version = val && typeof val === 'object' ? val['version'] : undefined;
                        add(m[1], typeof version === 'string' ? version : undefined, key === `node_modules/${m[1]}`);
                    }
                }
                const deps = lock['dependencies'];
                if (deps && typeof deps === 'object')
                    collectLockV1Deps(deps, add, true);
            }
            catch {
                /* unparseable lockfile — node_modules below */
            }
        }
    }
    else if (manager === 'pnpm') {
        // v9 `  name@1.2.3:` / `  '@scope/name@1.2.3':`, v6 `  /name@1.2.3:`,
        // v5 `  /name/1.2.3:` — package keys at two-space indent; the version
        // stops before any `(peer@x)` suffix.
        for (const line of (readText('pnpm-lock.yaml') ?? '').split(/\r?\n/)) {
            const m = /^ {2}['"]?\/?((?:@[^/\s'"]+\/)?[^@/\s'"]+)[@/](\d[^:'"(\s]*)/.exec(line);
            if (m?.[1] && m[2])
                add(m[1], m[2]);
        }
    }
    else {
        // yarn.lock (v1 and Berry): a column-0 header listing one or more
        // `name@range` descriptors, then an indented `version "x"` / `version: x`.
        let pending = [];
        for (const line of (readText('yarn.lock') ?? '').split(/\r?\n/)) {
            if (/^[^\s#].*:$/.test(line)) {
                pending = line
                    .slice(0, -1)
                    .split(',')
                    .map((d) => d.trim().replace(/^"|"$/g, ''))
                    .map((d) => {
                    const at = d.indexOf('@', 1);
                    return at > 0 ? d.slice(0, at) : '';
                })
                    .filter((n) => n.length > 0 && !n.startsWith('__'));
                continue;
            }
            const v = /^\s+version:?\s+"?([^"\s]+)"?/.exec(line);
            if (v?.[1]) {
                for (const name of pending)
                    add(name, v[1]);
                pending = [];
            }
        }
    }
    if (out.size === 0) {
        for (const pkg of listNodeModulesPackages(join(projectPath, 'node_modules')))
            add(pkg.name, pkg.version, pkg.topLevel);
    }
    return out;
}
function collectLockV1Deps(deps, add, topLevel) {
    for (const [name, val] of Object.entries(deps)) {
        const rec = val && typeof val === 'object' ? val : undefined;
        const version = rec?.['version'];
        add(name, typeof version === 'string' ? version : undefined, topLevel);
        const nested = rec?.['dependencies'];
        if (nested && typeof nested === 'object')
            collectLockV1Deps(nested, add, false);
    }
}
/**
 * Every package `node_modules/` itself holds, with the version its own
 * `package.json` declares — the fallback when no lockfile says. Walks pnpm's
 * flat `.pnpm/<encoded>/node_modules/<realName>` store too (fix round 3):
 * pnpm's TOP-LEVEL `node_modules/<name>` entries are symlinks into `.pnpm/`,
 * which `Dirent.isDirectory()` does not follow; the store holds every
 * installed package — direct AND transitive — as a real directory.
 */
function listNodeModulesPackages(nodeModulesDir) {
    const out = [];
    const push = (dir, name, topLevel) => {
        let version;
        try {
            const pj = JSON.parse(readFileSync(join(dir, name, 'package.json'), 'utf8'));
            if (typeof pj['version'] === 'string')
                version = pj['version'];
        }
        catch {
            /* no readable package.json — name only */
        }
        out.push({ name, version, topLevel });
    };
    const collect = (dir, topLevel) => {
        let entries;
        try {
            entries = readdirSync(dir);
        }
        catch {
            return;
        }
        for (const name of entries) {
            if (name.startsWith('.'))
                continue;
            if (!safeIsDirectory(join(dir, name)))
                continue; // follows a pnpm top-level symlink too
            if (name.startsWith('@')) {
                let scoped = [];
                try {
                    scoped = readdirSync(join(dir, name));
                }
                catch {
                    continue;
                }
                for (const inner of scoped)
                    if (safeIsDirectory(join(dir, name, inner)))
                        push(dir, `${name}/${inner}`, topLevel);
                continue;
            }
            push(dir, name, topLevel);
        }
    };
    collect(nodeModulesDir, true);
    try {
        for (const storeEntry of readdirSync(join(nodeModulesDir, '.pnpm'))) {
            collect(join(nodeModulesDir, '.pnpm', storeEntry, 'node_modules'), false);
        }
    }
    catch {
        /* no .pnpm store */
    }
    return out;
}
/** `statSync`-based directory check that FOLLOWS symlinks (unlike
 *  `Dirent.isDirectory()`, which reflects the dirent itself) — needed for
 *  pnpm's own top-level `node_modules/<name>` entries, each a symlink into
 *  `.pnpm/`. */
function safeIsDirectory(p) {
    try {
        return statSync(p).isDirectory();
    }
    catch {
        return false;
    }
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
        // Bracket notation (`overrides[name]`), never `overrides.name`: `npm pkg
        // set` interprets a DOT in a dotted key path as a nested-object
        // separator, so a package name that itself contains a dot (a real one:
        // `socket.io-parser`) would silently become `{overrides: {socket:
        // {"io-parser": ...}}}` instead of the flat key the real package name
        // is. Used unconditionally, not only when a dot is detected.
        //
        // UNQUOTED (fix round 3, item N1): `create_fix_pr`'s `fixpr/apply.ts`
        // splits `upgrade_command` on whitespace and runs it WITHOUT a shell, so
        // a quoted token is literal characters `npm pkg set` receives as part of
        // the argument — quoting it wrote `"'overrides": {"minimist": "1.2.6'"}`
        // while still reporting `applied: true`. `shell_command` carries the
        // shell-quoted form instead, for a human pasting this into a terminal.
        upgrade_command: `npm pkg set overrides[${input.package_name}]=${input.latest_version}`,
        shell_command: `npm pkg set 'overrides[${input.package_name}]=${input.latest_version}'`,
        // `npm pkg set` only rewrites package.json — the lockfile/node_modules
        // do not reflect the override until a plain reinstall re-resolves them.
        follow_up_command: 'npm install --ignore-scripts',
    };
}
/** What an `execa(…, { reject: false })` result says about a runner that
 *  could not do its job: the command could not start at all (no exit code —
 *  not installed, not on PATH), or it exited with a code outside `okCodes`.
 *  `null` when the exit code is one the caller treats as success. */
function describeExecFailure(label, result, okCodes) {
    if (typeof result.exitCode === 'number') {
        if (okCodes.includes(result.exitCode))
            return null;
        const stderr = typeof result.stderr === 'string' ? result.stderr : '';
        const first = stderr.split(/\r?\n/).map((l) => l.trim()).find((l) => l.length > 0);
        return { code: `exit_${result.exitCode}`, reason: `${label} exited ${result.exitCode}${first ? `: ${first}` : ''}` };
    }
    const code = typeof result.code === 'string' ? result.code : 'not_runnable';
    const why = typeof result.shortMessage === 'string' ? result.shortMessage : code;
    return { code: code === 'ENOENT' ? 'not_installed' : code, reason: `${label} could not be run (${why})` };
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
 * proposes a step only for a pin with an active CVE and a known SAFE fixed
 * version (never a downgrade — `minCleanVersionAbove`, same guard as the
 * npm branch, fix round 1 item 1).
 *
 * `upgrade_command` is deliberately NOT a real `pip`/`sed` invocation: there
 * is no cross-platform, shell-free, whitespace-only-tokenised command that
 * edits one line of a text file (`fixpr/apply.ts`'s own `toArgv` requires
 * exactly that — see its module comment). It names the file and the pin
 * change in a fixed, human-readable shape instead; a literal attempt to
 * execute it fails closed (unknown binary) rather than touching anything.
 * The AUTHORITATIVE target file is the structured `file` field on the step
 * (fix round 1, item 9) — a path can contain spaces, which the
 * whitespace-tokenised `upgrade_command` string cannot represent. Task 11
 * matches on the structured fields (`package_name`, `ecosystem`, `file`,
 * `installed_version`, `latest_version`, `cve_ids`) to perform the actual
 * edit, not on this string.
 *
 * **Every requirement mention with an active CVE that could not become a
 * step is reported in `unplanned`** (fix round 1, item 7) — a non-exact
 * specifier (`>=`, `~=`, …: no single installed version to compare
 * against), an unpinned bare name, or an exact pin whose CVE has no safe
 * fix version above it — never silently dropped.
 */
async function runPipPlan(projectPath, cves) {
    const steps = [];
    const unplanned = [];
    const handled = new Set(); // lowercased names an actual manifest mentioned
    const considerMention = (file, mention) => {
        handled.add(mention.name.toLowerCase());
        const cve = cves.get(mention.name.toLowerCase());
        if (!cve)
            return; // no active CVE — nothing to plan or report
        if (mention.version === undefined) {
            unplanned.push({
                package_name: mention.name,
                ecosystem: 'pip',
                cve_ids: cve.cveIds,
                reason: mention.unplannableReason ?? 'could not determine a pinned version',
            });
            return;
        }
        const step = buildPipSecurityStep({ file, pin: { name: mention.name, version: mention.version }, cves });
        if (step) {
            steps.push(step);
        }
        else {
            unplanned.push({
                package_name: mention.name,
                ecosystem: 'pip',
                cve_ids: cve.cveIds,
                reason: `active CVE (${cve.cveIds.join(', ')}), but no fix version above the pinned ${mention.version} is known`,
            });
        }
    };
    for (const file of findPipRequirementsFiles(projectPath)) {
        for (const mention of parsePinnedRequirements(file.content))
            considerMention(file.relPath, mention);
    }
    for (const mention of parsePyprojectPins(projectPath))
        considerMention('pyproject.toml', mention);
    // Fix round 3, item #7: there is deliberately NO pass 2 here any more. The
    // fix round 2 shape swept the WHOLE `cves` map for anything npm's own
    // lockfile did not resolve and labelled every one of them `pip` ("likely
    // transitive") — but "not npm" does not mean "pip": the coordinator's own
    // probe showed a composer `laravel/framework` and a Go
    // `golang.org/x/net` both mislabelled `pip` by this exact sweep in a repo
    // that has pip present alongside them. `ecosystem: 'pip'` is now used ONLY
    // for a package this function's own parsing actually found a manifest
    // line for (`handled`, above) — every other CVE'd package, including a
    // genuinely transitive pip dependency this file never mentions by name,
    // falls through to `appendCatchAllUnplanned`'s generic `'unknown'` entry
    // in the top-level handler, which is the honest attribution: this
    // function has no evidence it is pip at all, only that it is not
    // something ELSE this project's runners could place either.
    return { steps, unplanned };
}
function buildPipSecurityStep(opts) {
    const cve = opts.cves.get(opts.pin.name.toLowerCase());
    if (!cve)
        return null;
    const target = minCleanVersionAbove(opts.pin.version, [cve.fixedVersion]);
    if (!target)
        return null;
    return {
        package_name: opts.pin.name,
        installed_version: opts.pin.version,
        latest_version: target,
        ecosystem: 'pip',
        classification: 'security',
        reason: `Active CVE (${cve.cveIds.join(', ')}) on the pinned version`,
        cve_ids: cve.cveIds,
        file: opts.file,
        upgrade_command: `pip-pin ${opts.file} ${opts.pin.name}==${target}`,
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
/**
 * Every package MENTION in a requirements file — exact `==` pins (returned
 * with `version` set, the only specifier precise enough to name a single
 * "installed" version without inspecting an environment) AND range/unpinned
 * mentions (returned with `unplannableReason` set instead, so an active CVE
 * on one is reported in `unplanned` rather than silently dropped — fix
 * round 1, item 7).
 *
 * Handles the shapes a real `requirements.txt` uses beyond a bare
 * `pkg==1.2.3`:
 *   - pip-compile's hash-pinned, line-continued form
 *     (`django==4.2.0 \` followed by `    --hash=sha256:...` lines) — a
 *     trailing backslash joins the logical line, and `--hash=...` tokens
 *     are stripped before parsing;
 *   - extras (`celery[redis]==5.3.0`) — the `[redis]` marker is stripped;
 *     the package identity for CVE matching is `celery`, not the bracketed
 *     form;
 *   - environment markers (`pkg==1.0.0; python_version >= "3.8"`) — the
 *     marker (after `;`) is dropped, the pin itself is still read.
 */
function parsePinnedRequirements(content) {
    const out = [];
    for (const rawLine of joinContinuedLines(content)) {
        let line = rawLine.split('#')[0]?.trim() ?? '';
        if (!line || line.startsWith('-'))
            continue; // -r other.txt, --index-url, etc.
        line = line.replace(/\s+--hash=\S+/g, '').trim(); // pip-compile hash annotations
        const semi = line.indexOf(';');
        if (semi >= 0)
            line = line.slice(0, semi).trim(); // environment marker
        if (!line)
            continue;
        const mention = parseOneRequirementSpec(line);
        if (mention)
            out.push(mention);
    }
    return out;
}
/**
 * Parses ONE already-isolated requirement specifier — no comments, no
 * `--hash=...` annotations, no line continuation: the caller (a
 * requirements-file line, or one element of a pyproject
 * `dependencies = [...]` array) already stripped those. Shared so both
 * shapes get the SAME extras/exact/range/bare handling rather than two
 * copies that can drift (fix round 2, item 7).
 *
 * The environment marker (everything from a top-level `;` onward,
 * `pkg==1.0.0; python_version >= "3.8"`) IS stripped here, internally (fix
 * round 3, "cheap" item) — `parsePinnedRequirements` already stripped it
 * before this function existed as a shared helper, but a pyproject array
 * element (`"urllib3==1.26.0; python_version >= '3.8'"`) went straight from
 * `parsePyprojectPins` to this function with no such preprocessing, so the
 * marker's trailing text made every one of the regexes below fail to match
 * at all — the whole mention silently vanished, not even reported
 * `unplanned`. Doing it here, once, means BOTH callers get it whether or
 * not they remembered to strip it themselves.
 *
 * Returns an exact `==` pin with `version` set, a non-exact specifier or
 * bare name with `unplannableReason` set (fix round 1, item 7 — never
 * silently dropped), or `null` when the text is not a package mention at
 * all (a VCS URL, a local path, `-e .`, …).
 */
function parseOneRequirementSpec(specRaw) {
    const semi = specRaw.indexOf(';');
    const spec = (semi >= 0 ? specRaw.slice(0, semi) : specRaw).trim();
    if (!spec)
        return null;
    // Extras: `celery[redis]==5.3.0` -> name `celery`, rest `==5.3.0`.
    const extras = /^([A-Za-z0-9._-]+)\[[^\]]*\](.*)$/.exec(spec);
    const target = extras ? `${extras[1]}${extras[2]}` : spec;
    const exact = /^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._-]+)$/.exec(target);
    if (exact) {
        const [, name, version] = exact;
        if (name && version)
            return { name, version };
        return null;
    }
    const range = /^([A-Za-z0-9._-]+)\s*(>=|<=|~=|!=|===|<|>)/.exec(target);
    if (range?.[1] && range[2]) {
        return {
            name: range[1],
            unplannableReason: `non-exact specifier (${range[2]}) — cannot determine a safe target without inspecting the installed environment`,
        };
    }
    const bare = /^[A-Za-z0-9._-]+$/.exec(target);
    if (bare) {
        return { name: target, unplannableReason: 'no version specifier — cannot determine an installed version' };
    }
    // Anything else (a VCS URL, a local path, `-e .`, …) is not a package
    // mention this module can reason about at all — silently skipped, same
    // as before.
    return null;
}
/** Joins a pip-compile-style backslash line continuation
 *  (`django==4.2.0 \` followed by `    --hash=sha256:...`) into one logical
 *  line, so `parsePinnedRequirements` sees the whole pin on one line. */
function joinContinuedLines(content) {
    const out = [];
    let buffer = '';
    for (const line of content.split(/\r?\n/)) {
        const continued = /\\\s*$/.test(line);
        buffer += continued ? line.replace(/\\\s*$/, ' ') : line;
        if (continued)
            continue;
        out.push(buffer);
        buffer = '';
    }
    if (buffer)
        out.push(buffer);
    return out;
}
/**
 * PEP 621 `[project] dependencies = ["pkg==1.2.3", "pkg[extra]>=1.0", …]` —
 * a regex scan, the same simplicity `licenseCompatibility.ts#detectProjectLicense`
 * already uses for this same file rather than adding a TOML parser
 * dependency for one array. Poetry's own `[tool.poetry.dependencies]` table
 * (`pkg = "1.2.3"`) is a different, non-PEP-621 shape and is out of scope
 * here.
 *
 * Scoped to the `[project]` TABLE specifically, not the whole file (fix
 * round 3, "cheap" item): `dependencies\s*=\s*\[` as a bare substring search
 * also matches INSIDE `dev-dependencies = [...]` — "dev-dependencies" ends
 * in "dependencies" — so a `[tool.uv] dev-dependencies = [...]` array
 * placed earlier in the file than `[project] dependencies = [...]` won the
 * old unscoped search outright, and the REAL PEP 621 dependency list was
 * never read at all. `extractProjectTableText` isolates the `[project]`
 * table's own text (from its header to the next `[section]` header or EOF)
 * first; `extractDependenciesArray` then searches only within that slice.
 *
 * Every element goes through `parseOneRequirementSpec` (fix round 2, item
 * 7): a range specifier (`django>=4.2`) and an extras pin
 * (`celery[redis]==5.3.0`) are now returned as proper `RequirementMention`s
 * — an exact pin with `version` set, or an unplannable one with a reason —
 * instead of the old exact-`==`-only regex silently dropping everything
 * else.
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
    const projectTable = extractProjectTableText(raw);
    if (projectTable === null)
        return out; // no [project] table at all — nothing PEP 621 defines to read
    const block = extractDependenciesArray(projectTable);
    if (block === null)
        return out;
    const entryPattern = /["']([^"']*)["']/g;
    let m;
    while ((m = entryPattern.exec(block)) !== null) {
        const mention = parseOneRequirementSpec(m[1] ?? '');
        if (mention)
            out.push(mention);
    }
    return out;
}
/** The raw text of the `[project]` TOML table only — from its own header
 *  line to the next top-level `[...]` header (any table, including
 *  `[project.urls]` — TOML does not nest a table's OWN content under a
 *  dotted child header) or EOF. `null` when no bare `[project]` header
 *  exists at all. Matches only a header that is EXACTLY `[project]` on its
 *  own line, optionally followed by a TOML comment (`[project] # main`) —
 *  `[tool.project]` or `[project.optional-dependencies]` do not count as the
 *  table itself. */
function extractProjectTableText(raw) {
    const header = /^[ \t]*\[project\][ \t]*(?:#[^\r\n]*)?$/m.exec(raw);
    if (!header)
        return null;
    const start = header.index + header[0].length;
    const rest = raw.slice(start);
    const nextHeader = /^[ \t]*\[/m.exec(rest);
    return nextHeader ? rest.slice(0, nextHeader.index) : rest;
}
/**
 * The raw text INSIDE `dependencies = [ ... ]`, depth-counting brackets
 * rather than matching up to the first `]` (fix round 2, item 7): the fix
 * round 1 regex `dependencies\s*=\s*\[([^\]]*)\]` stopped at the FIRST `]`
 * it saw, which an extras marker introduces well before the array's own
 * closing bracket — `["django>=4.2", "celery[redis]==5.3.0", "urllib3"]`
 * was truncated to `"django>=4.2", "celery[redis` (matching the
 * coordinator's own probe: `celery[redis]==5.3.0` and anything after it
 * silently vanished). Returns `null` when no `dependencies = [` is found,
 * or the array never closes (malformed TOML — nothing to parse either way).
 */
function extractDependenciesArray(raw) {
    const startMatch = /dependencies\s*=\s*\[/i.exec(raw);
    if (!startMatch)
        return null;
    const start = startMatch.index + startMatch[0].length;
    let depth = 1;
    let i = start;
    for (; i < raw.length && depth > 0; i += 1) {
        const ch = raw[i];
        if (ch === '[')
            depth += 1;
        else if (ch === ']')
            depth -= 1;
    }
    if (depth !== 0)
        return null; // never closed — malformed, bail out rather than guess
    return raw.slice(start, i - 1);
}
/** Parses a runner's stdout as JSON, or records why it could not — an empty
 *  or unparseable listing is a runner failure, never "nothing is outdated". */
function parseRunnerJson(ecosystem, label, stdout, failures) {
    const text = typeof stdout === 'string' ? stdout : '';
    if (text.trim().length === 0) {
        failures.push({ ecosystem, code: 'no_output', reason: `${label} printed nothing` });
        return undefined;
    }
    try {
        return JSON.parse(text);
    }
    catch {
        failures.push({ ecosystem, code: 'unparseable_output', reason: `${label} printed something that is not JSON` });
        return undefined;
    }
}
async function runComposerOutdated(projectPath, cves) {
    const result = await execa('composer', ['outdated', '--format=json'], {
        cwd: projectPath,
        reject: false,
        timeout: 90_000,
    });
    const failures = [];
    const exitFailure = describeExecFailure('composer outdated', result, [0]);
    if (exitFailure)
        return { steps: [], unplanned: [], failures: [{ ecosystem: 'composer', ...exitFailure }] };
    const parsed = parseRunnerJson('composer', 'composer outdated --format=json', result.stdout, failures);
    const installed = parsed?.installed;
    if (!Array.isArray(installed)) {
        if (failures.length === 0) {
            failures.push({ ecosystem: 'composer', code: 'unparseable_output', reason: 'composer outdated printed no "installed" list' });
        }
        return { steps: [], unplanned: [], failures };
    }
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
    return { steps: out, unplanned: [], failures };
}
async function runCargoOutdated(projectPath, cves) {
    // Requires `cargo install cargo-outdated`.
    const result = await execa('cargo', ['outdated', '--format', 'json'], {
        cwd: projectPath,
        reject: false,
        timeout: 90_000,
    });
    const failures = [];
    const exitFailure = describeExecFailure('cargo outdated (needs cargo-outdated)', result, [0]);
    if (exitFailure)
        return { steps: [], unplanned: [], failures: [{ ecosystem: 'cargo', ...exitFailure }] };
    const parsed = parseRunnerJson('cargo', 'cargo outdated --format json', result.stdout, failures);
    const dependencies = parsed?.dependencies;
    if (!Array.isArray(dependencies)) {
        if (failures.length === 0) {
            failures.push({ ecosystem: 'cargo', code: 'unparseable_output', reason: 'cargo outdated printed no "dependencies" list' });
        }
        return { steps: [], unplanned: [], failures };
    }
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
    return { steps: out, unplanned: [], failures };
}
async function runGoOutdated(projectPath, cves) {
    // `go list -m -u -json all` emits one JSON object per line.
    const result = await execa('go', ['list', '-m', '-u', '-json', 'all'], {
        cwd: projectPath,
        reject: false,
        timeout: 90_000,
    });
    const exitFailure = describeExecFailure('go list -m -u -json all', result, [0]);
    if (exitFailure)
        return { steps: [], unplanned: [], failures: [{ ecosystem: 'go', ...exitFailure }] };
    const out = [];
    // Go emits a stream of JSON objects, not a JSON array. Concatenate and
    // split by `}\n{` boundaries.
    const lines = (typeof result.stdout === 'string' ? result.stdout : '').split(/(?<=\})\s*(?=\{)/);
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
    return { steps: out, unplanned: [] };
}
async function runBundlerOutdated(projectPath, cves) {
    // `bundle outdated --parseable` emits machine-friendly lines:
    // gem-name (newest 1.2.3, installed 1.2.0)
    const result = await execa('bundle', ['outdated', '--parseable'], {
        cwd: projectPath,
        reject: false,
        timeout: 90_000,
    });
    // `bundle outdated` exits 1 when anything is outdated, so only a command
    // that could not run, or a non-zero exit with nothing parseable, is a
    // failure.
    const text = typeof result.stdout === 'string' ? result.stdout : '';
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
    const exitFailure = describeExecFailure('bundle outdated', result, out.length > 0 ? [0, 1] : [0]);
    return { steps: out, unplanned: [], ...(exitFailure ? { failures: [{ ecosystem: 'rubygems', ...exitFailure }] } : {}) };
}
/**
 * .NET: one `dotnet restore` + `dotnet list <target> package --outdated
 * --format json --no-restore` per target `findDotnetTargets` finds (a root
 * solution, else every project file) — the same targets and the same restore
 * plan `deps_audit` uses (`../deps/dotnetRestore.ts`, whose module comment
 * has the measured rules): `--locked-mode` on every restore, lock files found
 * from the solution/project list rather than a depth-limited walk, and a
 * restore that would create a lock file prevented or not run at all. A scan
 * must never modify the working tree.
 *
 * Restore ALWAYS runs first (fix round 3 — a stale-but-present `obj/` makes
 * `dotnet list --no-restore` report the OLD resolution with exit 0), and no
 * `requestedVersion` vs `resolvedVersion` comparison is made on the result:
 * after a fresh restore those legitimately differ for every floating (`2.*`),
 * range, two-part or not-on-the-feed reference, and one `Serilog 2.*` used to
 * empty the whole .NET plan.
 *
 * Every failed or refused target is a `runner_failures` entry carrying
 * NuGet's own code — `NU1004` (lock out of sync) reads differently from
 * `NU1101` (package not found) or `NU1301` (feed unreachable) — and the
 * catch-all names it for every CVE'd package declared in a `PackageReference`.
 */
async function runDotnetOutdated(projectPath, cves) {
    const steps = [];
    const failures = [];
    for (const target of findDotnetTargets(projectPath)) {
        const rel = relative(projectPath, target) || target;
        const plan = planDotnetRestore(projectPath, target);
        if (plan.blocked) {
            failures.push({ ecosystem: 'dotnet', target: rel, code: plan.blocked.code, reason: plan.blocked.reason });
            continue;
        }
        const restore = await execa('dotnet', plan.args, { cwd: projectPath, reject: false, timeout: 5 * 60_000 });
        const created = removeCreatedLockFiles(plan);
        if (created.length > 0) {
            failures.push({
                ecosystem: 'dotnet',
                target: rel,
                code: 'lock_file_would_be_created',
                reason: `restore created ${created.map((c) => relative(projectPath, c) || c).join(', ')} (a ` +
                    'RestorePackagesWithLockFile opt-in this plan could not see) — deleted again; target not planned',
            });
            continue;
        }
        if (restore.exitCode !== 0) {
            const execFailure = describeExecFailure('dotnet restore', restore, [0]);
            const failure = restore.exitCode === undefined && execFailure
                ? execFailure
                : classifyRestoreFailure(typeof restore.stdout === 'string' ? restore.stdout : '', typeof restore.stderr === 'string' ? restore.stderr : '');
            failures.push({ ecosystem: 'dotnet', target: rel, code: failure.code, reason: failure.reason });
            continue;
        }
        const r = await execa('dotnet', ['list', target, 'package', '--outdated', '--format', 'json', '--no-restore'], {
            cwd: projectPath,
            reject: false,
            timeout: 90_000,
        });
        const listed = typeof r.stdout === 'string' ? r.stdout : '';
        // `--format json` is available on .NET 8+; on older SDKs we fall back to
        // parsing the human-readable text output (less precise but functional).
        if (r.exitCode === 0 && listed.trim().startsWith('{')) {
            steps.push(...parseDotnetJson(listed, cves));
            continue;
        }
        const fallback = await execa('dotnet', ['list', target, 'package', '--outdated', '--no-restore'], {
            cwd: projectPath,
            reject: false,
            timeout: 90_000,
        });
        const text = typeof fallback.stdout === 'string' ? fallback.stdout : '';
        if (fallback.exitCode !== 0 || text.trim().length === 0) {
            failures.push({
                ecosystem: 'dotnet',
                target: rel,
                code: 'list_failed',
                reason: 'restored, but `dotnet list package --outdated` failed',
            });
            continue;
        }
        steps.push(...parseDotnetText(text, cves));
    }
    // A package referenced by several projects of one solution is listed once
    // per project; one step is enough.
    const seen = new Set();
    const unique = steps.filter((s) => {
        const key = `${s.package_name.toLowerCase()}@${s.installed_version}->${s.latest_version}`;
        if (seen.has(key))
            return false;
        seen.add(key);
        return true;
    });
    return { steps: unique, unplanned: [], failures };
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