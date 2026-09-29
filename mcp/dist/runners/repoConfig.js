/**
 * A scanned repository's own configuration for the scanners it is scanned
 * with — one convention for every runner (round 4, item 3; round 5, item 2).
 *
 * A file a scanner reads from the project decides part of what the scan
 * reports. Where that is the project's call to make — its accepted risks,
 * its rule selection, its ignores — the file is honoured, and the run that
 * read it NAMES it: `tools_run[].honoured_config` lists the files, and the
 * run's reason says what they decide ("honoured the project's .bandit (its
 * skips and tests decide what is reported)"). {@link REPO_CONFIG} is the one
 * table of which runner reads which files; `test/unit/runners/repoConfig
 * .test.ts` fails when a scanner is spawned in `src/` without an entry here
 * (or in {@link NO_REPO_CONFIG}, saying why it reads none), or when the file
 * that spawns it does not name what it reads.
 *
 * Where honouring is not legitimate — a `trivy.yaml` that can point Trivy at
 * another server, a `.syft.yaml`, a `.bandit` below the root — the helper
 * that spawns the scanner keeps the file out instead (`trivyRun.ts`,
 * `syftRun.ts`, scan_sast's `--ini`), and there is nothing to name.
 *
 * `nested` files apply below the root too, each to its own subtree
 * (measured for `.semgrepignore` on Semgrep 1.176.1: a `sub/.semgrepignore`
 * excluded `sub/deep/`): every one the scanner would read is found — git's
 * own listing in a work tree (tracked, and untracked files `.gitignore` does
 * not exclude), else a bounded walk — and named.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { git, splitNul } from './git.js';
import { PROJECT_WALK_EXCLUDE, SCANNER_WALK_EXCLUDE } from './projectFiles.js';
const NUGET_CONFIGS = ['NuGet.config', 'nuget.config', 'NuGet.Config'];
/** Which project files each runner reads (or is handed), and what they decide. */
export const REPO_CONFIG = {
    // Passed explicitly (`--ignorefile`), never found by Trivy itself (trivyRun.ts).
    trivy: [{ file: '.trivyignore', decides: 'its entries are not reported' }],
    // gitleaks reads `<source>/.gitleaks.toml` itself; every pass reads `.gitleaksignore`.
    gitleaks: [
        { file: '.gitleaks.toml', decides: 'its rules and allowlists decide what is reported' },
        { file: '.gitleaksignore', decides: 'its fingerprints are not reported' },
    ],
    // The root one only, passed with `--ini` (scanSast.ts), whole-project and
    // scoped runs alike: one below it is kept out.
    bandit: [{ file: '.bandit', decides: 'its skips and tests decide what is reported' }],
    // Passed with `--config` (scanContainers.ts); hadolint runs outside the project.
    hadolint: [
        { file: '.hadolint.yaml', decides: 'its ignored rules and severity overrides decide what is reported' },
        { file: '.hadolint.yml', decides: 'its ignored rules and severity overrides decide what is reported' },
    ],
    actionlint: [
        { file: '.github/actionlint.yaml', decides: 'its ignore patterns silence errors' },
        { file: '.github/actionlint.yml', decides: 'its ignore patterns silence errors' },
    ],
    zizmor: [
        { file: 'zizmor.yml', decides: 'its rules can disable or ignore audits' },
        { file: '.github/zizmor.yml', decides: 'its rules can disable or ignore audits' },
    ],
    // A directory target only: explicit file targets ignore it (measured on 1.176.1).
    semgrep: [{ file: '.semgrepignore', decides: 'its patterns decide which files are scanned', nested: true }],
    // npm audit reads the project's .npmrc (registry, omit=dev, audit-level).
    npm: [{ file: '.npmrc', decides: 'its registry and settings decide what npm audit reads and reports' }],
    // `dotnet list package --vulnerable` asks the configured package sources.
    dotnet: NUGET_CONFIGS.map((file) => ({ file, decides: 'its package sources answer the vulnerability lookup', nested: true })),
    // The build the analyzers run in.
    'dotnet-analyzers': [
        { file: '.editorconfig', decides: 'its analyzer severities decide what is reported', nested: true },
        { file: '.globalconfig', decides: 'its analyzer severities decide what is reported' },
        { file: 'Directory.Build.props', decides: 'its build properties can switch analyzers off', nested: true },
        { file: 'Directory.Build.targets', decides: 'its build targets can switch analyzers off', nested: true },
        ...NUGET_CONFIGS.map((file) => ({ file, decides: 'its package sources are restored from', nested: true })),
    ],
    // ruff finds its configuration from each file upwards.
    ruff: [
        { file: 'ruff.toml', decides: 'its rule selection decides what is reported', nested: true },
        { file: '.ruff.toml', decides: 'its rule selection decides what is reported', nested: true },
        { file: 'pyproject.toml', decides: 'its [tool.ruff] rule selection decides what is reported', when: /^\[tool\.ruff/m, nested: true },
    ],
    // jscpd reads its config from the working directory (the project).
    jscpd: [
        { file: '.jscpd.json', decides: 'its thresholds and ignores decide what is reported' },
        { file: 'package.json', decides: 'its "jscpd" thresholds and ignores decide what is reported', when: /"jscpd"\s*:/ },
    ],
    // radon reads its config from the working directory (the project).
    radon: [
        { file: 'radon.cfg', decides: 'its excludes and ignores decide what is measured' },
        { file: 'setup.cfg', decides: 'its [radon] excludes and ignores decide what is measured', when: /^\[radon\]/m },
        { file: 'tox.ini', decides: 'its [radon] excludes and ignores decide what is measured', when: /^\[radon\]/m },
        { file: 'pyproject.toml', decides: 'its [tool.radon] excludes and ignores decide what is measured', when: /^\[tool\.radon\]/m },
    ],
    // staticcheck reads one per package directory, inherited below it.
    staticcheck: [{ file: 'staticcheck.conf', decides: 'its checks decide what is reported', nested: true }],
    // ESLint runs only on the project's own configuration (quality_check).
    eslint: [
        ...['eslint.config.js', 'eslint.config.mjs', 'eslint.config.cjs', 'eslint.config.ts', 'eslint.config.mts', 'eslint.config.cts'].map((file) => ({ file, decides: 'its rules decide what is reported' })),
        ...['.eslintrc', '.eslintrc.js', '.eslintrc.cjs', '.eslintrc.json', '.eslintrc.yaml', '.eslintrc.yml'].map((file) => ({
            file,
            decides: 'its rules decide what is reported',
            nested: true,
        })),
        { file: 'package.json', decides: 'its "eslintConfig" rules decide what is reported', when: /"eslintConfig"\s*:/ },
        { file: '.eslintignore', decides: 'its entries are not linted' },
    ],
    // dev-guardian's own: the factory applies it to every scan (scanToolFactory.ts).
    guardian: [{ file: '.guardianignore', decides: 'its entries are not scanned or reported' }],
};
/**
 * The scanners spawned in `src/` that read no project configuration, and
 * why — so the table above is complete by construction (the test).
 */
export const NO_REPO_CONFIG = {
    syft: 'runs outside the project with -c on an empty file (syftRun.ts)',
    phpcs: 'given --standard, so no project ruleset is looked up',
    wpscan: 'runs in the report directory; scans a URL or a WordPress install, not the repository',
    'pip-audit': 'reads the requirements file it is given; no project configuration file',
    cosign: 'reads an image and its registry, not the repository',
    nuclei: 'probes a URL; its configuration is the user\'s own',
    lighthouse: 'measures a URL; no configuration is loaded unless passed',
    k6: 'runs the script it is given',
    docker: 'runs the Semgrep image, which reads the project as Semgrep does (named on the semgrep run)',
};
/** Names a nested file may take at any depth, bounded like the other project walks. */
const MAX_WALK_DIRS = 20_000;
/** Most files named in a reason; `honoured_config` holds at most {@link MAX_LISTED}. */
const MAX_NAMED = 5;
const MAX_LISTED = 50;
/** A file read to test `when` is read up to this size. */
const MAX_WHEN_BYTES = 1024 * 1024;
/** Whether `rel` is a regular file whose name matches EXACTLY (case included, on any file system). */
function existsExactly(projectPath, rel) {
    const parts = rel.split('/');
    const name = parts.pop();
    if (name === undefined)
        return false;
    try {
        return readdirSync(join(projectPath, ...parts), { withFileTypes: true }).some((e) => e.name === name && e.isFile());
    }
    catch {
        return false;
    }
}
function matchesWhen(projectPath, rel, when) {
    if (when === undefined)
        return true;
    try {
        const abs = join(projectPath, ...rel.split('/'));
        if (statSync(abs).size > MAX_WHEN_BYTES)
            return false;
        return when.test(readFileSync(abs, 'utf8'));
    }
    catch {
        return false;
    }
}
/** Every file named `names` below the project: git's listing in a work tree, else a bounded walk. */
async function nestedFiles(projectPath, names) {
    const listed = await git(projectPath, [
        'ls-files',
        '-z',
        '--cached',
        '--others',
        '--exclude-standard',
        '--',
        ...names.map((n) => `:(glob)**/${n}`),
    ]);
    if (listed.exitCode === 0) {
        return splitNul(listed.stdout).filter((rel) => existsExactly(projectPath, rel));
    }
    const out = [];
    const stack = [''];
    let visited = 0;
    while (stack.length > 0 && visited < MAX_WALK_DIRS) {
        const rel = stack.pop();
        if (rel === undefined)
            break;
        visited += 1;
        let entries;
        try {
            entries = readdirSync(rel === '' ? projectPath : join(projectPath, ...rel.split('/')), { withFileTypes: true });
        }
        catch {
            continue;
        }
        for (const e of entries) {
            const child = rel === '' ? e.name : `${rel}/${e.name}`;
            if (e.isDirectory()) {
                if (!PROJECT_WALK_EXCLUDE.has(e.name) && !SCANNER_WALK_EXCLUDE.has(e.name))
                    stack.push(child);
            }
            else if (e.isFile() && names.includes(e.name)) {
                out.push(child);
            }
        }
    }
    return out;
}
/**
 * The files of `runner`'s {@link REPO_CONFIG} entry the project holds: at the
 * root (exact name), or anywhere below it for a `nested` one; a `when` file
 * only when its text matches. Sorted by path.
 */
export async function honouredFiles(projectPath, runner) {
    const specs = REPO_CONFIG[runner];
    const out = [];
    const nested = specs.filter((s) => s.nested === true);
    const found = nested.length > 0 ? await nestedFiles(projectPath, nested.map((s) => s.file)) : [];
    for (const spec of specs) {
        const paths = spec.nested === true
            ? found.filter((p) => p === spec.file || p.endsWith(`/${spec.file}`))
            : existsExactly(projectPath, spec.file)
                ? [spec.file]
                : [];
        for (const path of paths) {
            if (matchesWhen(projectPath, path, spec.when))
                out.push({ path, decides: spec.decides });
        }
    }
    return out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}
/** The files at the root only (sync): for a runner none of whose files is `nested`. */
export function honouredRootFiles(projectPath, runner) {
    return REPO_CONFIG[runner]
        .filter((spec) => existsExactly(projectPath, spec.file) && matchesWhen(projectPath, spec.file, spec.when))
        .map((spec) => ({ path: spec.file, decides: spec.decides }));
}
/** `honoured the project's A (what it decides), B (…)` — the one wording every runner uses. */
export function honouredNote(files) {
    if (files.length === 0)
        return null;
    const byDecides = new Map();
    for (const f of files)
        byDecides.set(f.decides, [...(byDecides.get(f.decides) ?? []), f.path]);
    const parts = [];
    let shown = 0;
    for (const [decides, paths] of byDecides) {
        const room = Math.max(0, MAX_NAMED - shown);
        if (room === 0)
            break;
        const listed = paths.slice(0, room);
        shown += listed.length;
        parts.push(`${listed.join(', ')} (${decides})`);
    }
    const more = files.length > shown ? ` and ${files.length - shown} more` : '';
    return `honoured the project's ${parts.join(', ')}${more}`;
}
/**
 * `run` naming the project files it honoured: the note on its reason (once),
 * the files in `honoured_config`. Unchanged when there are none.
 */
export function withProjectConfig(run, files) {
    const note = honouredNote(files);
    if (note === null)
        return run;
    const already = run.reason !== undefined && run.reason.includes(note);
    const reason = already ? run.reason : run.reason !== undefined && run.reason.length > 0 ? `${run.reason}; ${note}` : note;
    const listed = [...new Set([...(run.honoured_config ?? []), ...files.map((f) => f.path)])].slice(0, MAX_LISTED);
    return { ...run, ...(reason !== undefined ? { reason } : {}), honoured_config: listed };
}
/** {@link withProjectConfig} with `runner`'s files as the project holds them. */
export async function nameRepoConfig(run, projectPath, runner) {
    return withProjectConfig(run, await honouredFiles(projectPath, runner));
}
//# sourceMappingURL=repoConfig.js.map