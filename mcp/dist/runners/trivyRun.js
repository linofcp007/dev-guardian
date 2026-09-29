/**
 * Every Trivy spawn in this codebase — one helper, so that no pass can be
 * steered by the configuration of the repository it is scanning.
 *
 * ---- The defect ------------------------------------------------------------
 *
 * Trivy reads `trivy.yaml` from its WORKING DIRECTORY whenever `--config` is
 * not given, and every pass used to run with `cwd` set to the project. So a
 * repository could commit its own `trivy.yaml` and decide what its scan
 * reports. Reproduced with the CLI gate against a project pinning lodash
 * 4.17.15: without the file, exit 1, coverage full, 7 findings; with a
 * committed `trivy.yaml` of `severity: [UNKNOWN]`, exit 0, coverage full,
 * no gap, 0 findings. The same file can set `db.repository` or `server.addr`,
 * which would send the project's package list to a host of the file's
 * choosing and trust whatever it answers.
 *
 * ---- What this does --------------------------------------------------------
 *
 *   - Trivy runs in `workDir` — a report directory this scan created, never
 *     the project — and is handed its target as an explicit path.
 *   - It is always given `--config <an empty file this helper writes>`, so no
 *     `trivy.yaml` is looked up anywhere at all.
 *   - The project's `.trivyignore` (the one file Trivy used to pick up from
 *     the project on its own that a project legitimately owns: accepted
 *     risks) is honoured only EXPLICITLY — `--ignorefile <project>/.trivyignore`
 *     when it exists — and returned in `honoured`, so the caller names it in
 *     the result. A suppression file that decides what a scan reports is
 *     never applied in silence. Trivy's other cwd lookups (`trivy-secret.yaml`,
 *     a default `.trivyignore`) find nothing in a report directory.
 *
 * What the `.trivyignore` suppressed is counted and named (round 4, item 2):
 * silenced findings left no trace — a CI gate on a project ignoring every
 * lodash advisory read clean. A Trivy 0.50.0 or newer (absent in 0.49.1) is
 * given `--show-suppressed` on a JSON pass of the subcommands that accept it,
 * and lists them under `Results[].ExperimentalModifiedFindings` (measured on
 * 0.69.3); `trivy config` refuses that flag as unknown, so a config pass —
 * or a Trivy too old, or of unknown version — says it cannot list them
 * instead of claiming none. The run carries them
 * (`TrivyRunResult.suppressed`, then `ToolRun.suppressed_by_repo_config`):
 * the scan's warnings, the CI gate's output and SARIF (`suppressions`, kind
 * `external`) name them. Never a coverage gap: the repository decided it.
 *
 * Measured on Trivy 0.69.3: the project's `trivy.yaml` above takes the scan
 * from 7 findings to 0 when Trivy runs in the project; run from a report
 * directory with `--config` pointing at an empty file, the same project
 * reports all 7. `--skip-dirs` / `--skip-files` stay anchored at the target
 * (not the working directory), so `.guardianignore`'s native flags keep
 * working. `test/unit/runners/trivyRun.test.ts` fails when any spawn in
 * `src/` names Trivy outside this file.
 */
import { execa } from 'execa';
import { existsSync, lstatSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { compareSemver } from '../platform/semverCompare.js';
import { extractVersion } from './toolProbe.js';
import { runProcess } from './processRunner.js';
import { asArray, getProp, getString, parseInputAsJson } from './scannerParsers/index.js';
import { honouredNote as configNote, REPO_CONFIG, withProjectConfig } from './repoConfig.js';
import { assessManifestCoverage, trivyParser } from './scannerParsers/trivy.js';
/** The project's own Trivy suppression file, honoured explicitly. */
export const PROJECT_TRIVYIGNORE = '.trivyignore';
/** The empty configuration file written into the working directory. */
export const NEUTRAL_TRIVY_CONFIG = 'trivy-neutral-config.yaml';
const NEUTRAL_CONFIG_TEXT = "# Written by dev-guardian: an empty Trivy configuration, passed as --config so that the\n" +
    "# scanned repository's own trivy.yaml is never read.\n";
/** The project's `.trivyignore`, when it is a regular file; else null. */
export function projectTrivyIgnore(projectPath) {
    const path = join(projectPath, PROJECT_TRIVYIGNORE);
    try {
        return existsSync(path) && lstatSync(path).isFile() ? path : null;
    }
    catch {
        return null;
    }
}
/** The argv of one run — pure, for the tests. */
export function trivyArgv(inv, configPath, ignoreFile, version = null) {
    return [
        ...inv.args,
        ...(acceptsNoPhoneHomeFlags(version) ? NO_PHONE_HOME_FLAGS : []),
        '--config',
        configPath,
        ...(ignoreFile !== null ? ['--ignorefile', ignoreFile] : []),
        ...(ignoreFile !== null && unlistedBecause(inv.args, version) === null ? ['--show-suppressed'] : []),
        inv.target,
    ];
}
// ---------------------------------------------------------------- what .trivyignore suppressed
/** The first Trivy with `--show-suppressed` (absent in 0.49.1). */
export const SHOW_SUPPRESSED_SINCE = '0.50.0';
/** Subcommands that accept it; `trivy config` refuses it as an unknown flag (measured on 0.69.3). */
const SHOW_SUPPRESSED_COMMANDS = new Set([
    'fs',
    'filesystem',
    'image',
    'i',
    'repo',
    'repository',
    'rootfs',
    'sbom',
    'vm',
]);
const MAX_SUPPRESSED_IDS = 50;
const MAX_SUPPRESSED_FINDINGS = 25;
/** How many ids a note names before "and N more". */
const NOTE_IDS = 10;
/** The value of `--<flag> <v>` / `--<flag>=<v>` in `args`, or null. */
function flagValue(args, flag) {
    for (let i = 0; i < args.length; i += 1) {
        const a = args[i];
        if (a === flag)
            return args[i + 1] ?? null;
        if (a !== undefined && a.startsWith(`${flag}=`))
            return a.slice(flag.length + 1);
    }
    return null;
}
/** Why this run cannot list what `.trivyignore` suppressed; null when it can. */
function unlistedBecause(args, version) {
    const command = args[0] ?? '';
    if (!SHOW_SUPPRESSED_COMMANDS.has(command))
        return `trivy ${command} has no --show-suppressed`;
    if (flagValue(args, '--format') !== 'json')
        return 'the report is not JSON';
    if (version === null)
        return "the installed Trivy's version could not be read";
    if ((compareSemver(version, SHOW_SUPPRESSED_SINCE) ?? -1) < 0) {
        return `Trivy ${version} predates --show-suppressed (${SHOW_SUPPRESSED_SINCE})`;
    }
    return null;
}
/** Where each `ExperimentalModifiedFindings` Type goes in a report the parser reads. */
const FINDING_ARRAY = {
    vulnerability: 'Vulnerabilities',
    misconfiguration: 'Misconfigurations',
    secret: 'Secrets',
    license: 'Licenses',
};
/**
 * What the project's `.trivyignore` suppressed, from a report Trivy wrote
 * with `--show-suppressed`: every entry of `ExperimentalModifiedFindings`
 * counted, the findings rebuilt by the Trivy parser as they would have been
 * reported (same rule ids, same fingerprints), bounded.
 */
export function repoSuppressionFrom(raw, projectPath) {
    let count = 0;
    const distinct = new Set();
    const ids = [];
    const findings = [];
    let results = [];
    try {
        results = asArray(getProp(parseInputAsJson(raw), 'Results'));
    }
    catch {
        results = [];
    }
    for (const result of results) {
        const modified = asArray(getProp(result, 'ExperimentalModifiedFindings'));
        for (const entry of modified) {
            count += 1;
            const finding = getProp(entry, 'Finding');
            const id = getString(finding, 'VulnerabilityID') ??
                getString(finding, 'ID') ??
                getString(finding, 'AVDID') ??
                getString(finding, 'RuleID') ??
                getString(finding, 'Name');
            if (id !== undefined && !distinct.has(id)) {
                distinct.add(id);
                if (ids.length < MAX_SUPPRESSED_IDS)
                    ids.push(id);
            }
            const key = FINDING_ARRAY[getString(entry, 'Type') ?? ''];
            if (key === undefined || findings.length >= MAX_SUPPRESSED_FINDINGS)
                continue;
            const one = { Results: [{ Target: getString(result, 'Target') ?? '', [key]: [finding] }] };
            for (const f of trivyParser.parse(one, { project_path: projectPath }).findings) {
                const { message: _description, ...bounded } = f;
                findings.push(bounded);
            }
        }
    }
    const bounded = findings.slice(0, MAX_SUPPRESSED_FINDINGS);
    return { file: PROJECT_TRIVYIGNORE, count, ids, id_count: distinct.size, findings: bounded };
}
/** `N findings suppressed by the repository's .trivyignore: …`, or why they cannot be listed. */
export function suppressionNote(s) {
    if (s.count === null) {
        return `what the repository's ${s.file} suppressed cannot be listed (${s.unlisted_because ?? 'unknown'})`;
    }
    const named = s.ids.slice(0, NOTE_IDS).join(', ');
    const idCount = s.id_count ?? s.ids.length;
    const more = idCount > NOTE_IDS ? ` and ${idCount - NOTE_IDS} more` : '';
    const noun = s.count === 1 ? 'finding' : 'findings';
    return `${s.count} ${noun} suppressed by the repository's ${s.file}${named.length > 0 ? `: ${named}` : ''}${more}`;
}
// ---------------------------------------------------------------- no phoning home
//
// Every Trivy run contacted check.trivy.dev: its version check, which also
// carries anonymous usage data (`Trivy-Identifier`, the command line, OS and
// architecture — `pkg/notification/notice.go`), run in a goroutine with a
// 3 s timeout. Measured through a refusing proxy on 0.69.3 with `trivy
// config` (a sub-second `fs` scan can exit before the goroutine connects):
// bare, `--quiet`, `--skip-version-check` alone and `--disable-telemetry`
// alone all asked; both flags, or both environment variables, never did —
// the request is skipped only when both are set. So both variables go into
// every run's environment, and both flags onto every command line of a Trivy
// that has them: they arrived with the check itself in 0.63.0
// (`pkg/flag/scan_flags.go`: absent at v0.62.1, present at v0.63.0), and an
// older Trivy refuses an unknown flag outright. A Trivy whose version
// cannot be read gets the variables only.
/** Both, always: each alone still sends the request. */
export const TRIVY_NO_PHONE_HOME_ENV = {
    TRIVY_SKIP_VERSION_CHECK: 'true',
    TRIVY_DISABLE_TELEMETRY: 'true',
};
const NO_PHONE_HOME_FLAGS = ['--skip-version-check', '--disable-telemetry'];
/** The first Trivy with both flags (and with the check). */
export const NO_PHONE_HOME_FLAGS_SINCE = '0.63.0';
function acceptsNoPhoneHomeFlags(version) {
    if (version === null)
        return false;
    return (compareSemver(version, NO_PHONE_HOME_FLAGS_SINCE) ?? -1) >= 0;
}
let versionProbe = null;
/**
 * The installed Trivy's version (`Version: 0.69.3`), asked once per process —
 * through execa, not the scan runner: a quick query, never a scan — or null
 * when it cannot be read.
 */
async function installedTrivyVersion(cwd) {
    versionProbe ??= (async () => {
        try {
            const r = await execa('trivy', ['--version'], {
                cwd,
                env: { ...process.env, ...TRIVY_NO_PHONE_HOME_ENV },
                reject: false,
                timeout: 30_000,
                encoding: 'utf8',
            });
            const out = typeof r.stdout === 'string' ? r.stdout : '';
            return r.exitCode === 0 ? extractVersion(out) : null;
        }
        catch {
            return null;
        }
    })();
    return versionProbe;
}
/** Forget the probed version (tests, and after `install_toolchain`). */
export function resetTrivyVersionCache() {
    versionProbe = null;
}
/** Run Trivy — see the module comment. A config that cannot be written is a failed run, never one without it. */
export async function runTrivy(inv) {
    const configPath = join(inv.workDir, NEUTRAL_TRIVY_CONFIG);
    try {
        mkdirSync(inv.workDir, { recursive: true });
        writeFileSync(configPath, NEUTRAL_CONFIG_TEXT, 'utf8');
    }
    catch (e) {
        const why = e instanceof Error ? e.message : String(e);
        return {
            outcome: 'failed',
            exitCode: null,
            stdout: '',
            stderr: `could not write the neutral Trivy configuration ${configPath}: ${why}`,
            truncated: false,
            honoured: [],
        };
    }
    const ignoreFile = inv.ignoreFrom !== undefined ? projectTrivyIgnore(inv.ignoreFileFrom ?? inv.ignoreFrom) : null;
    const version = await installedTrivyVersion(inv.workDir);
    const run = await runProcess({
        command: 'trivy',
        args: trivyArgv(inv, configPath, ignoreFile, version),
        cwd: inv.workDir,
        // Merged over the server's own environment by the runner.
        env: { ...(inv.env ?? {}), ...TRIVY_NO_PHONE_HOME_ENV },
        ...(inv.signal !== undefined ? { signal: inv.signal } : {}),
        ...(inv.onLog !== undefined ? { onLog: inv.onLog } : {}),
        ...(inv.timeoutMs !== undefined ? { timeoutMs: inv.timeoutMs } : {}),
    });
    if (ignoreFile === null || inv.ignoreFrom === undefined)
        return { ...run, honoured: [] };
    const honoured = [PROJECT_TRIVYIGNORE];
    if (run.outcome !== 'completed')
        return { ...run, honoured };
    const why = unlistedBecause(inv.args, version);
    const output = flagValue(inv.args, '--output');
    if (why !== null || output === null) {
        const unlisted_because = why ?? 'the report was not written to a file';
        return { ...run, honoured, suppressed: { file: PROJECT_TRIVYIGNORE, count: null, ids: [], findings: [], unlisted_because } };
    }
    let raw;
    try {
        raw = readFileSync(output, 'utf8');
    }
    catch {
        const unlisted_because = 'Trivy wrote no report';
        return { ...run, honoured, suppressed: { file: PROJECT_TRIVYIGNORE, count: null, ids: [], findings: [], unlisted_because } };
    }
    return { ...run, honoured, suppressed: repoSuppressionFrom(raw, inv.ignoreFrom) };
}
/** Trivy's honoured files with what each decides, from the one table (`repoConfig.ts#REPO_CONFIG`). */
function trivyFiles(honoured) {
    return honoured.map((path) => ({
        path,
        decides: REPO_CONFIG.trivy.find((spec) => spec.file === path)?.decides ?? 'repository configuration',
    }));
}
/** The words a `tools_run` reason carries for what a run honoured, or null — the shared wording. */
export function honouredNote(honoured) {
    return configNote(trivyFiles(honoured));
}
/**
 * `run` naming what it honoured: the note appended to its reason, and the
 * files in `honoured_config` — and what they suppressed, when anything was
 * or when that cannot be listed (`suppressed_by_repo_config`, its note on
 * the reason too). Unchanged when nothing was honoured.
 */
export function withHonoured(run, trivy) {
    const files = trivyFiles(trivy.honoured);
    if (files.length === 0)
        return run;
    const named = withProjectConfig(run, files);
    const s = trivy.suppressed;
    const shown = s !== undefined && s.count !== 0 ? s : undefined;
    if (shown === undefined)
        return named;
    const note = suppressionNote(shown);
    const reason = named.reason !== undefined && named.reason.length > 0 ? `${named.reason}; ${note}` : note;
    return { ...named, reason, suppressed_by_repo_config: shown };
}
// ---------------------------------------------------------------- the dependency pass, judged
/** Listed missing when the manifest walk stopped early: see {@link judgeTrivyFs}. */
export const TRIVY_MANIFEST_WALK_GAP = 'trivy:manifest-walk';
/**
 * The `trivy` entry of a dependency pass (`trivy fs --scanners vuln[,license]`)
 * — the ONE judgement scan_deps, deps_audit and scan_wordpress share (review
 * I2: scan_wordpress had none, so a plugin whose composer.json has no lock
 * read `ok`, full, where scan_deps on the same tree read none):
 *
 *   - the process did not complete → `failed`;
 *   - every manifest the walk found was read → `ok`;
 *   - some were not, and Trivy reported other Results → `ok`, reason
 *     `no_supported_manifest`, each gap listed missing as `trivy:<ecosystem>`
 *     — never the bare `trivy`: `create_fix_pr`'s verification reads a
 *     literal `trivy` in `missing_tools` as "Trivy did not run", which would
 *     block every Trivy-sourced fix over one uncovered ecosystem;
 *   - none were, and Trivy reported nothing at all → `skipped`,
 *     `no_supported_manifest`, `trivy` missing.
 *
 * `trivy.ts#assessManifestCoverage` walks the tree (review I1). A walk that
 * stopped early (its 20 000-directory ceiling, an unreadable directory)
 * cannot say every manifest was read, so the run cannot be full (round 2,
 * item 7 — the rule `frameworks/projectLanguages.ts` applies to an
 * incomplete listing): the reason says why, and {@link TRIVY_MANIFEST_WALK_GAP}
 * is listed missing beside a `trivy` that stays ok. It measures no finding
 * (`history/runNames.ts`): Trivy itself read the whole tree; only this check
 * of it is short.
 */
export function judgeTrivyFs(args) {
    const { projectPath, raw, run, exclusions } = args;
    if (run.outcome !== 'completed') {
        return {
            toolRun: withHonoured({ name: 'trivy', status: 'failed', reason: run.outcome }, run),
            missing: [],
            gaps: [],
        };
    }
    const coverage = assessManifestCoverage(projectPath, raw ?? '', {
        ignores: exclusions === null ? null : (rel, isDir) => exclusions.ignores(rel, isDir),
        ...(args.maxDirs !== undefined ? { maxDirs: args.maxDirs } : {}),
    });
    const note = coverage.walkIncomplete !== undefined ? `${coverage.walkIncomplete} — manifests below were not checked` : null;
    const walkGap = note !== null ? [TRIVY_MANIFEST_WALK_GAP] : [];
    const withNote = (r) => withHonoured(note === null ? r : { ...r, reason: r.reason !== undefined ? `${r.reason}; ${note}` : note }, run);
    if (coverage.gaps.length > 0 && coverage.sawAnyResults) {
        return {
            toolRun: withNote({ name: 'trivy', status: 'ok', reason: 'no_supported_manifest' }),
            missing: [...coverage.gaps.map((g) => `trivy:${g.ecosystem}`), ...walkGap],
            gaps: coverage.gaps,
        };
    }
    if (coverage.gaps.length > 0) {
        return {
            toolRun: withNote({ name: 'trivy', status: 'skipped', reason: 'no_supported_manifest' }),
            missing: ['trivy'],
            gaps: coverage.gaps,
        };
    }
    return { toolRun: withNote({ name: 'trivy', status: 'ok' }), missing: walkGap, gaps: [] };
}
//# sourceMappingURL=trivyRun.js.map