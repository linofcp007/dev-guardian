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
 *                    (`../deps/versionCompare.js#minCleanVersionAbove`) —
 *                    never a scanner's raw "fixed_version" taken on faith,
 *                    which can be an older release branch's own backport or
 *                    simply stale. Every `npm install` carries
 *                    `--ignore-scripts`; a transitive CVE'd package gets an
 *                    `npm pkg set overrides[<pkg>]=<version>` step (bracket
 *                    notation — a dotted package name would otherwise
 *                    become a nested key) with a `follow_up_command` of
 *                    `npm install --ignore-scripts` to re-resolve the
 *                    lockfile;
 *        pip      → NEVER runs pip/pip-audit against the host interpreter.
 *                    Reads this project's own `requirements*.txt` pins
 *                    (including pip-compile hash-continuation lines,
 *                    extras and environment markers) and PEP 621
 *                    `pyproject.toml` dependencies, and proposes a step
 *                    only for an exact pin with an active CVE and a fix
 *                    version above the pin — see `runPipPlan`'s own doc
 *                    comment for why `upgrade_command` is not a real,
 *                    executable command here, and why the target file is
 *                    also exposed as a structured `file` field;
 *        composer / cargo / go / rubygems / dotnet → each stack's own
 *                    "outdated" command (dotnet restores only when a direct
 *                    `dotnet list` attempt fails, and with `--locked-mode`
 *                    when a `packages.lock.json` exists — a scan must never
 *                    modify the working tree).
 *      (Other stacks return an empty plan with `unsupported_ecosystems_present`.)
 *      **Every package with an active CVE that did NOT become a step is
 *      reported in `unplanned`** (package, ecosystem, cve_ids, reason) —
 *      never silently dropped: a non-exact pip specifier, a CVE whose only
 *      reported fix is a downgrade, a transitive npm package with no
 *      recorded installed version to compare against.
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
import { compareVersions, isCleanVersion, minCleanVersionAbove } from '../deps/versionCompare.js';
import { ProjectPath } from '../schemas.js';
import { CVE_SOURCE_SCAN_TYPES } from '../types.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { registerToolModule } from './index.js';
function noUnplanned(steps) {
    return { steps, unplanned: [] };
}
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
    const plansByEcosystem = await Promise.all(ecosystems.map(async (eco) => {
        switch (eco) {
            case 'npm':
                return runNpmOutdated(projectPath, cves);
            case 'pip':
                return runPipPlan(projectPath, cves);
            case 'composer':
                return noUnplanned(await runComposerOutdated(projectPath, cves));
            case 'cargo':
                return noUnplanned(await runCargoOutdated(projectPath, cves));
            case 'go':
                return noUnplanned(await runGoOutdated(projectPath, cves));
            case 'rubygems':
                return noUnplanned(await runBundlerOutdated(projectPath, cves));
            case 'dotnet':
                return noUnplanned(await runDotnetOutdated(projectPath, cves));
            default:
                return noUnplanned([]);
        }
    }));
    const flat = plansByEcosystem.flatMap((p) => p.steps);
    const unplanned = plansByEcosystem.flatMap((p) => p.unplanned);
    const ordered = orderPlan(flat, inp.prefer ?? 'security');
    const summary = summarize(ordered);
    return {
        ok: true,
        plan: ordered,
        summary,
        unplanned,
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
 *     the lockfile.
 *
 * **Driven from the CVE map, not from `npm outdated`'s own listing, for the
 * transitive case.** `npm outdated --json` has listed ONLY direct
 * dependencies since npm 7 — a transitive package never appears in it at
 * all, so a check that only classifies entries FROM that listing (`pkg in
 * parsed`) can never actually reach the transitive branch against a real
 * npm install; it only fired in a hand-built mock. Pass 1 below still reads
 * `npm outdated` for direct-dependency current/latest info; pass 2 sweeps
 * the WHOLE `cves` map for anything pass 1 did not already handle and that
 * is not a declared direct dependency, using the CVE row's own recorded
 * `installed_version` (the only "current version" signal available for a
 * package no ecosystem-native tool reports at all).
 */
async function runNpmOutdated(projectPath, cves) {
    const result = await execa('npm', ['outdated', '--json'], {
        cwd: projectPath,
        reject: false,
        timeout: 60_000,
    });
    const steps = [];
    const unplanned = [];
    let outdatedObj = {};
    if (result.stdout.trim().length > 0) {
        try {
            const parsed = JSON.parse(result.stdout);
            if (parsed && typeof parsed === 'object')
                outdatedObj = parsed;
        }
        catch {
            /* leave outdatedObj empty — pass 2 (CVE-map sweep) still runs */
        }
    }
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
        handled.add(pkg.toLowerCase());
        const cve = cves.get(pkg.toLowerCase());
        // The CVE's own minimum fix, checked against THIS run's actual current
        // version — never the (possibly stale) version the CVE row itself was
        // recorded against. Falls back to npm's own "latest" when the CVE has
        // no safe fix version, same as before a CVE ever entered the picture.
        const safeCveVersion = cve ? minCleanVersionAbove(installed, [cve.fixedVersion]) : undefined;
        const safeNpmLatest = isCleanVersion(npmLatest) && compareVersions(npmLatest, installed) > 0 ? npmLatest : undefined;
        const latest = safeCveVersion ?? safeNpmLatest;
        if (cve && !latest) {
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
        const isTransitive = cve !== undefined && directDeps.size > 0 && !directDeps.has(pkg);
        steps.push(isTransitive
            ? buildOverrideStep({ package_name: pkg, installed_version: installed, latest_version: latest, cve: cve })
            : buildStep({
                package_name: pkg,
                installed_version: installed,
                latest_version: latest,
                ecosystem: 'npm',
                cves,
                upgrade_command: `npm install ${pkg}@${latest} --ignore-scripts`,
            }));
    }
    // Pass 2: transitive CVE'd packages `npm outdated` never lists at all.
    // Driven entirely from the CVE map — see the module comment above.
    for (const [pkgLower, cve] of cves) {
        if (handled.has(pkgLower))
            continue;
        if (directDeps.has(pkgLower))
            continue; // a direct dep npm didn't flag as outdated — nothing to do
        const installed = cve.installedVersion;
        const target = minCleanVersionAbove(installed, [cve.fixedVersion]);
        if (!installed || !target) {
            // The `cves` table has no ecosystem column, so a package that never
            // showed up via `npm outdated` and has no recorded installed_version
            // either might not even BE an npm package — only report it as an npm
            // gap when there is at least an installed_version on record, i.e.
            // some scan already attributed it to this tree.
            if (installed) {
                unplanned.push({
                    package_name: cve.displayName,
                    ecosystem: 'npm',
                    cve_ids: cve.cveIds,
                    reason: `active CVE on a transitive dependency, but no fix version above the recorded installed version ${installed}`,
                });
            }
            continue;
        }
        steps.push(buildOverrideStep({ package_name: cve.displayName, installed_version: installed, latest_version: target, cve }));
    }
    return { steps, unplanned };
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
        // Bracket notation (`overrides[name]`), never `overrides.name`: `npm pkg
        // set` interprets a DOT in a dotted key path as a nested-object
        // separator, so a package name that itself contains a dot (a real one:
        // `socket.io-parser`) would silently become `{overrides: {socket:
        // {"io-parser": ...}}}` instead of the flat key the real package name
        // is. Bracket notation is npm's own documented way to set a literal key
        // regardless of what characters it contains, and works identically for
        // names without a dot too — so it is used unconditionally, not only
        // when a dot is detected.
        upgrade_command: `npm pkg set overrides[${input.package_name}]=${input.latest_version}`,
        // `npm pkg set` only rewrites package.json — the lockfile/node_modules
        // do not reflect the override until a plain reinstall re-resolves them.
        follow_up_command: 'npm install --ignore-scripts',
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
    const considerMention = (file, mention) => {
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
        // Extras: `celery[redis]==5.3.0` -> name `celery`, rest `==5.3.0`.
        const extras = /^([A-Za-z0-9._-]+)\[[^\]]*\](.*)$/.exec(line);
        const target = extras ? `${extras[1]}${extras[2]}` : line;
        const exact = /^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._-]+)$/.exec(target);
        if (exact) {
            const [, name, version] = exact;
            if (name && version)
                out.push({ name, version });
            continue;
        }
        const range = /^([A-Za-z0-9._-]+)\s*(>=|<=|~=|!=|===|<|>)/.exec(target);
        if (range?.[1] && range[2]) {
            out.push({
                name: range[1],
                unplannableReason: `non-exact specifier (${range[2]}) — cannot determine a safe target without inspecting the installed environment`,
            });
            continue;
        }
        const bare = /^[A-Za-z0-9._-]+$/.exec(target);
        if (bare) {
            out.push({ name: target, unplannableReason: 'no version specifier — cannot determine an installed version' });
        }
        // Anything else (a VCS URL, a local path, `-e .`, …) is not a package
        // mention this module can reason about at all — silently skipped, same
        // as before.
    }
    return out;
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
/**
 * Restore only when the tree genuinely was not restored already (fix round
 * 1, item 8: a scan must never modify tracked files). Previously this ran
 * `dotnet restore` unconditionally, every call — in an environment that
 * already restored (CI, a dev machine mid-session), that is wasted work at
 * best; at worst it rewrites a TRACKED `packages.lock.json` in place if the
 * dependency graph has drifted since the lock file was committed. `dotnet
 * list package --outdated` is tried directly first; a restore is attempted
 * only when that fails, and `--locked-mode` is added whenever a
 * `packages.lock.json` exists so an out-of-date lock FAILS the restore
 * instead of being silently rewritten.
 */
async function runDotnetOutdated(projectPath, cves) {
    let r = await execa('dotnet', ['list', 'package', '--outdated', '--format', 'json'], {
        cwd: projectPath,
        reject: false,
        timeout: 90_000,
    });
    if (r.exitCode !== 0) {
        const restoreArgs = ['restore', '--nologo', '--verbosity', 'quiet'];
        if (existsSync(join(projectPath, 'packages.lock.json')))
            restoreArgs.push('--locked-mode');
        const restore = await execa('dotnet', restoreArgs, { cwd: projectPath, reject: false, timeout: 5 * 60_000 });
        if (restore.exitCode !== 0)
            return []; // private feed not configured, lock out of date, etc. — skip the branch
        r = await execa('dotnet', ['list', 'package', '--outdated', '--format', 'json'], {
            cwd: projectPath,
            reject: false,
            timeout: 90_000,
        });
    }
    // `--format json` is available on .NET 8+; on older SDKs we fall back to
    // parsing the human-readable text output (less precise but functional).
    if (r.exitCode === 0 && r.stdout.trim().startsWith('{')) {
        return parseDotnetJson(r.stdout, cves);
    }
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