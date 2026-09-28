/**
 * Shared .NET restore planning for `deps_audit` (vulnerable-package listing)
 * and `deps_update_plan` (outdated-package listing). Both have to run
 * `dotnet restore` before `dotnet list ... --no-restore` can report anything
 * current, and both must do it WITHOUT creating or rewriting a tracked file.
 * The rules below were measured against SDK 10.0.401, not assumed:
 *
 *   - `--locked-mode` is passed on EVERY restore. On a project with a
 *     `packages.lock.json` it makes an out-of-sync lock fail the restore
 *     (`NU1004`) instead of rewriting it; on a project with no lock and no
 *     opt-in it is a no-op — restore succeeds, floating (`12.*`) and range
 *     (`[12.0.1,13.0)`) versions included.
 *   - `--locked-mode` does NOT stop a project that sets
 *     `RestorePackagesWithLockFile=true` but has no committed lock from
 *     CREATING `packages.lock.json`. `-p:RestorePackagesWithLockFile=false`
 *     does — but the same global property FAILS the restore (`NU1005`) on any
 *     project that does have a lock file. So it is passed only when no
 *     project the restore touches has a lock file; when some do and another
 *     opts in without one, the restore is not run at all and the target is
 *     reported as a gap (`lock_file_would_be_created`).
 *   - Lock files are found from the project LIST — the `.sln`/`.slnx`
 *     entries, or the `.csproj` itself, plus every `ProjectReference` they
 *     pull in (restore follows those too) — never from a depth-limited walk
 *     of the tree, which missed a solution's project five directories down
 *     and let a plain restore rewrite its lock. Both `packages.lock.json` and
 *     NuGet's project-specific `packages.<project>.lock.json` count.
 *   - After every restore, any lock-file path that did not exist before and
 *     does now is deleted again and the target reported as a gap — defence
 *     in depth for an opt-in this module's textual check could not see (an
 *     imported `.props` outside the project tree, a custom
 *     `NuGetLockFilePath`).
 *
 * `dotnet restore` evaluates and runs the project's own MSBuild — the same
 * trust boundary both tools' descriptions name.
 */
import { existsSync, readFileSync, readdirSync, unlinkSync } from 'node:fs';
import { basename, dirname, extname, isAbsolute, join, relative, resolve } from 'node:path';
const SKIP_DIRS = new Set(['bin', 'obj', 'node_modules', '.git', '.guardian', 'packages', '.vs']);
/** How deep the no-solution `.csproj` walk goes. Only decides which projects
 *  are scanned when there is no solution at the root; lock files are never
 *  found this way (see the module comment). */
const PROJECT_WALK_MAX_DEPTH = 8;
const PROJECT_EXTENSIONS = new Set(['.csproj', '.fsproj', '.vbproj']);
/**
 * What `dotnet restore` / `dotnet list` run against: the solution at the
 * project root when there is one (`.sln` preferred over `.slnx`; one call
 * covers every project it lists), otherwise every project file a bounded walk
 * finds.
 */
export function findDotnetTargets(projectPath) {
    let rootEntries;
    try {
        rootEntries = readdirSync(projectPath).sort();
    }
    catch {
        return [];
    }
    const sln = rootEntries.find((n) => n.toLowerCase().endsWith('.sln')) ??
        rootEntries.find((n) => n.toLowerCase().endsWith('.slnx'));
    if (sln)
        return [join(projectPath, sln)];
    return findProjectFiles(projectPath);
}
function findProjectFiles(projectPath) {
    const out = [];
    // `Dirent` types, not `statSync`: a symlinked directory is not followed
    // (no cycles), and the walk costs one syscall per directory, not per entry
    // — it runs for every `deps_update_plan` call, .NET project or not.
    const walk = (dir, depth) => {
        if (depth > PROJECT_WALK_MAX_DEPTH)
            return;
        let entries;
        try {
            entries = readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
        }
        catch {
            return;
        }
        for (const entry of entries) {
            if (SKIP_DIRS.has(entry.name))
                continue;
            const abs = join(dir, entry.name);
            if (entry.isDirectory())
                walk(abs, depth + 1);
            else if (entry.isFile() && PROJECT_EXTENSIONS.has(extname(entry.name).toLowerCase()))
                out.push(abs);
        }
    };
    walk(projectPath, 0);
    return out;
}
/** A path as written inside a `.sln`/`.slnx`/`.csproj` (usually with
 *  backslashes, relative to that file) as an absolute path on this OS. */
function resolveFromFile(file, written) {
    const normalised = written.trim().replace(/\\/g, '/');
    return isAbsolute(normalised) ? resolve(normalised) : resolve(dirname(file), normalised);
}
function readText(path) {
    try {
        return readFileSync(path, 'utf8');
    }
    catch {
        return '';
    }
}
/** Project files a solution lists — `.sln` `Project(...) = "Name", "path", …`
 *  lines (solution folders, whose "path" is not a project file, are skipped)
 *  or `.slnx` `<Project Path="…" />` elements. */
function solutionProjects(solution) {
    const text = readText(solution);
    const out = [];
    const add = (written) => {
        if (PROJECT_EXTENSIONS.has(extname(written.trim()).toLowerCase()))
            out.push(resolveFromFile(solution, written));
    };
    if (solution.toLowerCase().endsWith('.slnx')) {
        for (const m of text.matchAll(/<Project\b[^>]*\bPath\s*=\s*"([^"]+)"/gi))
            if (m[1])
                add(m[1]);
    }
    else {
        for (const m of text.matchAll(/^\s*Project\("[^"]*"\)\s*=\s*"[^"]*"\s*,\s*"([^"]+)"/gim))
            if (m[1])
                add(m[1]);
    }
    return out;
}
function projectReferences(project) {
    const text = readText(project);
    const out = [];
    for (const m of text.matchAll(/<ProjectReference\b[^>]*\bInclude\s*=\s*"([^"]+)"/gi)) {
        if (m[1])
            out.push(resolveFromFile(project, m[1]));
    }
    return out;
}
/**
 * Every project file a restore of `target` touches: the solution's own
 * entries (or the project itself), closed over `ProjectReference` — `dotnet
 * restore` follows project-to-project references, so a referenced project's
 * lock file is just as much at stake as the target's own.
 */
export function projectsForTarget(target) {
    const lower = target.toLowerCase();
    const start = lower.endsWith('.sln') || lower.endsWith('.slnx') ? solutionProjects(target) : [resolve(target)];
    const out = [];
    const seen = new Set();
    const queue = [...start];
    for (let next = queue.shift(); next !== undefined; next = queue.shift()) {
        // Windows paths are case-insensitive; a solution and a ProjectReference
        // can spell the same file differently.
        const key = process.platform === 'win32' ? next.toLowerCase() : next;
        if (seen.has(key))
            continue;
        seen.add(key);
        out.push(next);
        if (existsSync(next))
            queue.push(...projectReferences(next));
    }
    return out;
}
/** Where NuGet looks for a project's lock file: `packages.lock.json`, or the
 *  project-specific `packages.<project>.lock.json` (measured: NuGet reads it,
 *  and fails `NU1005`/`NU1004` on it exactly as on the default name). A space
 *  in the project name is also tried as `_`. */
export function lockFileCandidates(project) {
    const dir = dirname(project);
    const name = basename(project, extname(project));
    const names = new Set(['packages.lock.json', `packages.${name}.lock.json`, `packages.${name.replace(/ /g, '_')}.lock.json`]);
    return [...names].map((n) => join(dir, n));
}
/** True when the project, or any `Directory.Build.props` between it and the
 *  scanned root, opts into lock files — a restore would then CREATE one. A
 *  textual check: an opt-in it cannot see is caught after the fact by
 *  `removeCreatedLockFiles`. */
function optsIntoLockFile(project, root) {
    const optIn = /<RestorePackagesWithLockFile>\s*true\s*<\/RestorePackagesWithLockFile>/i;
    if (optIn.test(readText(project)))
        return true;
    const stop = resolve(root);
    for (let dir = dirname(resolve(project));; dir = dirname(dir)) {
        if (optIn.test(readText(join(dir, 'Directory.Build.props'))))
            return true;
        if (dir === stop || dirname(dir) === dir || relative(stop, dir).startsWith('..'))
            return false;
    }
}
export function planDotnetRestore(root, target) {
    const projects = projectsForTarget(target);
    const lockFiles = [];
    const absentLockCandidates = [];
    const withoutLock = [];
    for (const project of projects) {
        const candidates = lockFileCandidates(project);
        const present = candidates.filter((c) => existsSync(c));
        lockFiles.push(...present);
        absentLockCandidates.push(...candidates.filter((c) => !existsSync(c)));
        if (present.length === 0)
            withoutLock.push(project);
    }
    const args = ['restore', target, '--locked-mode', '--nologo', '--verbosity', 'quiet'];
    const plan = { target, projects, lockFiles, args, absentLockCandidates };
    if (lockFiles.length === 0) {
        // Nothing to protect, so nothing can fail NU1005 — and this is the one
        // switch that stops an opted-in project from creating a lock file.
        args.push('-p:RestorePackagesWithLockFile=false');
        return plan;
    }
    const wouldCreate = withoutLock.filter((p) => optsIntoLockFile(p, root));
    if (wouldCreate.length > 0) {
        const names = wouldCreate.map((p) => relative(root, p) || p).join(', ');
        plan.blocked = {
            code: 'lock_file_would_be_created',
            reason: `not restored: ${names} set RestorePackagesWithLockFile=true but has no committed ` +
                'packages.lock.json, and another project in the same restore does — restoring would create a ' +
                'new lock file in the working tree',
        };
    }
    return plan;
}
/** After a restore: deletes every lock file that did not exist before it ran
 *  and returns their paths — a scan must leave the tree as it found it. */
export function removeCreatedLockFiles(plan) {
    const created = [];
    for (const candidate of plan.absentLockCandidates) {
        if (!existsSync(candidate))
            continue;
        try {
            unlinkSync(candidate);
        }
        catch {
            /* reported either way — the caller turns it into a gap */
        }
        created.push(candidate);
    }
    return created;
}
const KIND_BY_CODE = {
    NU1004: 'lock_out_of_sync',
    NU1005: 'lock_out_of_sync',
    NU1403: 'lock_out_of_sync',
    NU1101: 'package_not_found',
    NU1102: 'package_not_found',
    NU1103: 'package_not_found',
    NU1301: 'feed_unreachable',
    NU1302: 'feed_unreachable',
};
/**
 * Why a restore failed. Error lines are preferred over the first line of
 * output: restore prints `warning NU1903` (a known-vulnerable package) ahead
 * of the real error on exactly the projects this tool exists to scan.
 */
export function classifyRestoreFailure(stdout, stderr) {
    const lines = `${stderr}\n${stdout}`.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length > 0);
    const errorLine = lines.find((l) => /\berror\s+[A-Z]+\d+\b/.test(l)) ?? lines.find((l) => /\berror\b/i.test(l));
    const firstLine = errorLine ?? lines[0] ?? '(no output)';
    const code = /\berror\s+([A-Z]+\d+)\b/.exec(firstLine)?.[1] ?? 'restore_failed';
    const kind = KIND_BY_CODE[code] ?? 'other';
    const lead = kind === 'lock_out_of_sync'
        ? 'packages.lock.json is out of sync with the project (restore runs in --locked-mode and never rewrites it)'
        : kind === 'package_not_found'
            ? 'a package or version could not be found on the configured feeds'
            : kind === 'feed_unreachable'
                ? 'a package feed could not be reached'
                : 'restore failed';
    // The MSBuild line carries the absolute project path twice (a leading
    // `C:\…\App.csproj :` and a trailing `[C:\…\App.csproj]`); the code and the
    // message are what a reader needs. Only the LAST bracket group is dropped —
    // NuGet's own version ranges (`[12.0.1, )`) sit inside the message.
    const stripped = firstLine.replace(/^.*?\berror\s+[A-Z]+\d+:\s*/, '').replace(/\s*\[[^[\]]*\]\s*$/, '');
    const message = stripped.length > 240 ? `${stripped.slice(0, 237)}...` : stripped;
    return { code, kind, reason: `${lead} (${code}: ${message})` };
}
/** `Include` names of every `PackageReference` in `projects`, lowercased,
 *  mapped to the project file that declares it. */
export function readPackageReferences(projects) {
    const out = new Map();
    for (const project of projects) {
        for (const m of readText(project).matchAll(/<PackageReference\b[^>]*\b(?:Include|Update)\s*=\s*"([^"]+)"/gi)) {
            const name = m[1]?.trim().toLowerCase();
            if (name && !out.has(name))
                out.set(name, project);
        }
    }
    return out;
}
//# sourceMappingURL=dotnetRestore.js.map