/**
 * `deps_audit` — dependency audit (Trivy + bot detection + stack-specific
 * auditors).
 *
 * Builds on `scan_deps` (same Trivy invocation, plus a manifest-coverage
 * check — see `trivy.ts`'s own module comment for the bare-`.csproj` /
 * bare-`package.json` silent gap it closes) and adds:
 *
 *   - `bot_configured` flag — whether the project already has renovate.json
 *     or .github/dependabot.yml in place;
 *   - `npm audit --json` (npm 7+/6 both supported) parsed into Findings via
 *     `npmAuditParser` — npm's GitHub-advisory coverage is complementary to
 *     Trivy's, so its vulnerabilities are counted rather than merely
 *     captured. To avoid double-counting, an npm finding for a package Trivy
 *     already reported as a CVE is dropped (Trivy is canonical); npm findings
 *     for packages Trivy missed are kept;
 *   - `pip-audit --format json`, run per `requirements*.txt` file (`-r`) when
 *     any exist, else against the project directory for a `pyproject.toml`
 *     project — NEVER bare, which audits whatever Python is on PATH (the MCP
 *     host's own interpreter, not this project's dependencies). Parsed via
 *     `pipAuditParser`;
 *   - `dotnet list <target> package --vulnerable --include-transitive
 *     --format json --no-restore`, one call per root `.sln`/`.slnx`
 *     (preferred) or `.csproj`, when the .NET SDK is on PATH. **Each one is
 *     preceded by `dotnet restore <target> --locked-mode`**, which evaluates
 *     and runs the project's own MSBuild and reaches its NuGet feeds — the
 *     same trust boundary `deps_update_plan`'s own dotnet branch crosses.
 *     `../deps/dotnetRestore.ts` has the measured rules that keep that
 *     restore from creating or rewriting a lock file. Parsed via
 *     `dotnetScaParser`. Trivy cannot cover this stack at all without a
 *     `packages.lock.json` (see `trivy.ts`), so this is NuGet's only source
 *     of CVE-adjacent findings, not a complementary one like npm's.
 *
 * pip-audit resolves `-r` requirements by building a temporary virtualenv
 * and installing them into it from PyPI — network access, and an sdist's own
 * build step runs there. The tool description says so, next to the restore.
 *
 * All raw outputs are persisted under `.guardian/reports/depsaudit-<scan>/`.
 */
import { writeFileSync } from 'node:fs';
import { packageManagerEnvOptions } from '../fixpr/childEnv.js';
import { listProjectDir, presentInProject, projectPathKind, readProjectTextOrUndefined } from '../platform/projectFs.js';
import { join, relative } from 'node:path';
import { classifyRestoreFailure, findDotnetTargets, planDotnetRestore, removeCreatedLockFiles, } from '../deps/dotnetRestore.js';
import { dotnetScaParser } from '../runners/scannerParsers/dotnetSca.js';
import { NPM_AUDIT_TOOL_NAME, npmAuditParser } from '../runners/scannerParsers/npmAudit.js';
import { pipAuditParser } from '../runners/scannerParsers/pipAudit.js';
import { TRIVY_TOOL_NAME, trivyParser } from '../runners/scannerParsers/trivy.js';
import { runProcess } from '../runners/processRunner.js';
import { honouredRootFiles, nameRepoConfig, withProjectConfig } from '../runners/repoConfig.js';
import { checkRequirements, INDEX_KINDS, SOURCE_KINDS } from '../deps/pipRequirements.js';
import { checkPyproject, checkSetupCfg } from '../deps/pythonProject.js';
import { judgeTrivyFs, runTrivy } from '../runners/trivyRun.js';
import { trivySkipArgs } from '../platform/guardianIgnore.js';
import { Force, ProjectPath, SeverityMin } from '../schemas.js';
import { registerToolModule } from './index.js';
import { ensureReportDir, readJsonSafe, scannerAvailable, } from './scanHelpers.js';
import { makeScanTool, } from './scanToolFactory.js';
/**
 * The package name a scanner encoded in a finding's snippet. Both parsers write
 * `${pkg}@${version…}` (Trivy: `pkg@installed->fixed`; npm: `pkg@range`), so the
 * name is everything before the LAST `@` — which keeps scoped names like
 * `@babel/core` intact. Returns null when no package can be recovered.
 */
function packageFromSnippet(snippet) {
    if (!snippet)
        return null;
    const at = snippet.lastIndexOf('@');
    if (at <= 0)
        return null; // no version marker, or a leading '@' with empty name
    return snippet.slice(0, at).trim().toLowerCase() || null;
}
/**
 * Trivy is the canonical CVE source across stacks; npm audit is here for the
 * GitHub advisories Trivy misses. When both flag the SAME package they are
 * (almost always) the same vulnerability seen twice — Trivy by CVE, npm by
 * GHSA — and npm's finding would otherwise inflate the counts. So we drop each
 * npm-audit finding whose package Trivy already reported as a CVE. npm findings
 * for packages Trivy did NOT flag (its complementary value) are kept.
 */
function dropNpmDuplicatesOfTrivy(findings) {
    const trivyPackages = new Set();
    for (const f of findings) {
        if (f.tool === TRIVY_TOOL_NAME && f.subcategory === 'cve') {
            const pkg = packageFromSnippet(f.snippet);
            if (pkg)
                trivyPackages.add(pkg);
        }
    }
    if (trivyPackages.size === 0)
        return findings;
    return findings.filter((f) => {
        if (f.tool !== NPM_AUDIT_TOOL_NAME)
            return true;
        const pkg = packageFromSnippet(f.snippet);
        return !(pkg !== null && trivyPackages.has(pkg));
    });
}
function detectBots(projectPath) {
    return {
        renovate: presentInProject(projectPath, 'renovate.json') ||
            presentInProject(projectPath, '.renovaterc') ||
            presentInProject(projectPath, '.renovaterc.json'),
        dependabot: presentInProject(projectPath, join('.github', 'dependabot.yml')),
    };
}
registerToolModule(makeScanTool({
    name: 'deps_audit',
    title: 'Dependency audit (Trivy + native auditors + bot detection)',
    description: 'Run Trivy fs (vuln+license) plus stack-specific auditors when applicable: npm audit; ' +
        'pip-audit, once per requirements*.txt (or the project dir for pyproject.toml), never the ' +
        'host Python — it builds a TEMPORARY virtualenv and installs those requirements into it ' +
        'from PyPI, or from an index the requirements file names (named in tools_run) — network ' +
        'access; an sdist\'s build step runs there; and for any .sln/.csproj, ' +
        '`dotnet restore --locked-mode` then `dotnet list package --vulnerable --include-transitive ' +
        '--no-restore`. That restore EXECUTES the project\'s own MSBuild (targets, imported .props) ' +
        'and contacts its NuGet feeds; it never rewrites or creates a packages.lock.json (an ' +
        'out-of-sync lock, or one a restore would create, is reported as a gap). Returns Findings, ' +
        'indexed CVEs, and a `bot_configured` flag indicating whether Renovate or Dependabot is set ' +
        'up in this repo.',
    // Its own type, not scan_deps' 'deps': the two shared cache entries and
    // answered for each other. Readers that want "the latest deps_audit" use
    // `isDepsAuditScan`, which also recognises the 2.0.x rows typed 'deps'.
    scan_type: 'deps_audit',
    category: 'security',
    supportsAutoFix: false,
    inputSchema: {
        project_path: ProjectPath,
        severity_min: SeverityMin,
        force: Force,
    },
    invoke: async (_input, ctx) => {
        const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'depsaudit');
        const tools_run = [];
        const missing_tools = [];
        const parser_inputs = [];
        // --- Trivy fs (canonical CVE source for all stacks) ---------------
        let manifestCoverageGaps = [];
        const trivyBin = await scannerAvailable('trivy');
        if (trivyBin) {
            const outFile = join(reportDir, 'deps.json');
            // Never in the project, never its trivy.yaml (runners/trivyRun.ts).
            const result = await runTrivy({
                args: ['fs', '--scanners', 'vuln,license', '--format', 'json', '--output', outFile, '--quiet', ...trivySkipArgs(ctx.exclusions)],
                target: ctx.projectPath,
                workDir: reportDir,
                ignoreFrom: ctx.projectPath,
                env: ctx.scriptEnv,
                signal: ctx.signal,
                onLog: ctx.onLog,
            });
            const raw = readJsonSafe(outFile);
            if (raw)
                parser_inputs.push({ parser: trivyParser, input: raw });
            // The one judgement scan_deps, deps_audit and scan_wordpress share
            // (runners/trivyRun.ts#judgeTrivyFs): a manifest anywhere in the
            // tree that Trivy read nothing for (e.g. a bare .csproj with no
            // packages.lock.json) must never read as a clean scan.
            const judged = judgeTrivyFs({ projectPath: ctx.projectPath, raw, run: result, exclusions: ctx.exclusions });
            tools_run.push(judged.toolRun);
            missing_tools.push(...judged.missing);
            manifestCoverageGaps = judged.gaps;
        }
        else {
            tools_run.push({ name: 'trivy', status: 'skipped', reason: 'not_installed' });
            missing_tools.push('trivy');
        }
        // --- Native auditors ----------------------------------------------
        // npm audit is parsed into Findings; so is pip-audit, now that it is
        // pointed at this project's own manifests instead of the host Python.
        if (presentInProject(ctx.projectPath, 'package.json')) {
            await tryNativeAudit({
                command: 'npm',
                args: ['audit', '--json', '--audit-level=info'],
                outFile: join(reportDir, 'npm-audit.json'),
                ctx,
                tools_run,
                missing_tools,
                parser_inputs,
                parser: npmAuditParser,
            });
        }
        // pip-audit: NEVER invoked bare — a bare `pip-audit` audits whatever
        // Python is on PATH (the MCP host's own interpreter), not this
        // project's dependencies. One invocation PER requirements file (so
        // each finding is attributed to its REAL source file, fix round 1
        // item 9 — pip-audit's own JSON output never says which file a
        // dependency came from when several are combined into one call), or
        // the project directory for a pyproject.toml-only project.
        await runPipAudit({ ctx, reportDir, tools_run, missing_tools, parser_inputs });
        // .NET SCA: Trivy cannot cover NuGet at all without a
        // packages.lock.json (trivy.ts's own module comment), so this is the
        // stack's only source of dependency findings, run whenever a
        // .sln/.csproj exists and the SDK is on PATH.
        const dotnetFailures = await runDotnetSca({ ctx, reportDir, tools_run, missing_tools, parser_inputs });
        const bot_configured = detectBots(ctx.projectPath);
        return {
            outcome: 'completed',
            tools_run,
            missing_tools,
            parser_inputs,
            dedupeFindings: dropNpmDuplicatesOfTrivy,
            report_paths: [reportDir],
            extras: {
                bot_configured,
                ...(manifestCoverageGaps.length > 0 ? { manifest_coverage_gaps: manifestCoverageGaps } : {}),
                ...(dotnetFailures.length > 0 ? { dotnet_restore_failures: dotnetFailures } : {}),
            },
        };
    },
}));
/**
 * A real `npm audit --json` report has a `vulnerabilities` (npm 7+) or
 * `advisories` (npm 6) object. When npm cannot audit (no lockfile, config
 * error) it exits non-zero — often with the *same* code 1 it uses for
 * "vulnerabilities found" — and prints an `{ error: … }` object instead. We
 * must not mistake that error for a clean scan, so success is gated on the
 * output actually being a report.
 */
function looksLikeNpmAuditReport(raw) {
    try {
        const j = JSON.parse(raw);
        if (!j || typeof j !== 'object' || 'error' in j)
            return false;
        const isObj = (v) => typeof v === 'object' && v !== null;
        return isObj(j['vulnerabilities']) || isObj(j['advisories']);
    }
    catch {
        return false;
    }
}
/** The public npm registry: npm audit answered by it is not worth a note. */
const NPM_PUBLIC_REGISTRY = /^https?:\/\/registry\.npmjs\.org\/?$/i;
/**
 * The registry the project's own `.npmrc` sends `npm audit` to, when it is
 * not the public one — credentials in the URL removed — or null.
 *
 * `npm audit` runs in the project, so the project's `.npmrc` decides which
 * server answers it: a private registry is legitimate and stays honoured, but
 * the answer is that server's, and a repository could equally point it at a
 * server of its own that answers "no vulnerabilities". Named in the result,
 * never silent. Only the unscoped `registry` key: a `@scope:registry` line
 * does not move the audit endpoint. The user's own `~/.npmrc` and
 * `npm_config_registry` are the user's choice, not the project's, and are
 * not read here.
 */
export function projectNpmRegistry(projectPath) {
    // The repository's file: bounded, never through a link out of the project.
    const text = readProjectTextOrUndefined(projectPath, '.npmrc', 1024 * 1024);
    if (text === undefined)
        return null;
    let registry = null;
    for (const raw of text.split(/\r?\n/)) {
        const line = raw.trim();
        if (line === '' || line.startsWith('#') || line.startsWith(';'))
            continue;
        const m = /^registry\s*=\s*(.*)$/i.exec(line);
        if (m?.[1] === undefined)
            continue;
        // The last one wins, as in npm's own ini reader.
        registry = m[1].trim().replace(/^["']|["']$/g, '');
    }
    if (registry === null || registry === '' || NPM_PUBLIC_REGISTRY.test(registry))
        return null;
    // Never echo a credential written into the URL.
    return registry.replace(/^([a-z][a-z0-9+.-]*:\/\/)[^/@]*@/i, '$1');
}
async function tryNativeAudit(opts) {
    const bin = await scannerAvailable(opts.command);
    if (!bin) {
        opts.tools_run.push({
            name: opts.command,
            status: 'skipped',
            reason: 'not_installed',
        });
        // The manifest exists but its auditor is absent — a real coverage gap.
        opts.missing_tools?.push(opts.command);
        return;
    }
    const isNpmStdout = opts.command === 'npm';
    const result = await runProcess({
        command: opts.command,
        args: opts.args,
        cwd: opts.ctx.projectPath,
        ...auditEnv(opts.ctx),
        signal: opts.ctx.signal,
        onLog: opts.ctx.onLog,
    });
    // npm audit writes to stdout; redirect ourselves.
    if (isNpmStdout && result.stdout.length > 0) {
        try {
            writeFileSync(opts.outFile, result.stdout, 'utf8');
        }
        catch {
            /* swallow */
        }
    }
    // Exit code 0/1 (or `completed`) is a run that produced output — npm and
    // pip-audit both exit 1 when vulnerabilities are present, which is
    // information, not failure. But npm ALSO exits 1 on a hard error (no
    // lockfile), so for npm we additionally require the output to be a real
    // audit report. An error masquerading as exit 1 must count as a gap, not a
    // clean "0 findings".
    const exitOk = result.outcome === 'completed' || result.exitCode === 0 || result.exitCode === 1;
    const ok = isNpmStdout ? exitOk && looksLikeNpmAuditReport(result.stdout) : exitOk;
    // Feed the captured JSON to its parser so the findings are counted. npm
    // prints to stdout; file-output tools (pip-audit) are read back from disk.
    let parsed = false;
    if (ok && opts.parser && opts.parser_inputs) {
        const rawText = isNpmStdout ? result.stdout : readJsonSafe(opts.outFile);
        if (rawText && rawText.length > 0) {
            opts.parser_inputs.push({ parser: opts.parser, input: rawText });
            parsed = true;
        }
    }
    // The project's .npmrc is named whenever npm audit read one (round 5, item
    // 2: `runners/repoConfig.ts`) — its registry, `omit=dev`, `audit-level`
    // decide what is audited — and whoever answered, when the project chose a
    // registry other than npm's (see `projectNpmRegistry`).
    const registry = isNpmStdout ? projectNpmRegistry(opts.ctx.projectPath) : null;
    const npmrc = isNpmStdout ? honouredRootFiles(opts.ctx.projectPath, 'npm') : [];
    const registryNote = (run) => {
        const named = withProjectConfig(run, npmrc);
        if (registry === null)
            return named;
        const note = `npm audit answered by ${registry} (from the project's .npmrc)`;
        return {
            ...named,
            reason: named.reason !== undefined && named.reason.length > 0 ? `${named.reason}; ${note}` : note,
            honoured_config: [...new Set([...(named.honoured_config ?? []), '.npmrc'])],
        };
    };
    if (ok) {
        opts.tools_run.push(registryNote({
            name: opts.command,
            status: 'ok',
            reason: parsed ? 'parsed into findings' : 'captured (evidence only)',
        }));
    }
    else {
        const reason = isNpmStdout && exitOk
            ? 'ran but produced no audit report (missing lockfile?)'
            : 'failed to run';
        opts.tools_run.push(registryNote({ name: opts.command, status: 'failed', reason }));
        // A failed auditor is a coverage gap — surface it so the roll-up and the
        // executive summary do not read the result as fully covered.
        opts.missing_tools?.push(opts.command);
    }
}
/**
 * The environment of a package-manager process this tool starts: the scan's
 * own, except while `create_fix_pr` re-scans a fix — then the
 * package-manager environment (`fixpr/childEnv.ts`), with `extendEnv: false`,
 * so `npm audit`, `pip-audit` (which installs the requirements into a
 * temporary virtualenv, running an sdist's build code) and `dotnet restore`
 * see no token or credential beyond the user's own package-manager
 * configuration.
 */
function auditEnv(ctx) {
    const pm = packageManagerEnvOptions();
    return 'env' in pm ? { env: pm.env, extendEnv: false } : { env: ctx.scriptEnv };
}
// --------------------------------------------------------------- pip-audit
/**
 * `requirements*.txt` at the project root, plus one level into a
 * `requirements/` directory (the common `requirements/base.txt` +
 * `requirements/dev.txt` split) — never a recursive walk, matching this
 * file's other manifest checks (`package.json`, `pyproject.toml`), which are
 * root-level existence checks too.
 *
 * `files` are handed to pip-audit. `outside` — project-relative, a
 * `requirements/` directory with its trailing `/` — are candidates that lead
 * out of the project through a link (`platform/projectFs.ts`): never listed,
 * read or handed over, and named as not audited rather than skipped silently.
 */
function findRequirementsFiles(projectPath) {
    const files = [];
    const outside = [];
    const sort = (abs, rel) => {
        const kind = projectPathKind(projectPath, abs);
        if (kind === 'file')
            files.push(abs);
        else if (kind === 'outside')
            outside.push(rel);
    };
    for (const { name } of listProjectDir(projectPath, projectPath)) {
        if (/^requirements.*\.txt$/i.test(name))
            sort(join(projectPath, name), name);
    }
    const reqDir = join(projectPath, 'requirements');
    if (projectPathKind(projectPath, reqDir) === 'outside')
        outside.push('requirements/');
    for (const { name } of listProjectDir(projectPath, reqDir)) {
        if (name.toLowerCase().endsWith('.txt'))
            sort(join(reqDir, name), `requirements/${name}`);
    }
    return { files, outside };
}
/**
 * `run` naming the requirements candidates {@link findRequirementsFiles} did
 * not hand to pip-audit because they lead out of the project: in the reason,
 * each as not audited. Not in `honoured_config` — nothing was taken from them.
 */
function withOutsideRequirements(run, outside) {
    if (outside.length === 0)
        return run;
    const notes = outside.map((rel) => `${rel} leads out of the project: not read or audited by dev-guardian`);
    const shown = notes.slice(0, MAX_UNREAD_NAMED);
    const more = notes.length > shown.length ? [`and ${notes.length - shown.length} more not audited`] : [];
    const reason = [run.reason, ...shown, ...more].filter((s) => s !== undefined && s.length > 0).join('; ');
    return { ...run, reason };
}
/**
 * A real `pip-audit --format json` report has a `dependencies` array — even
 * an empty one on a clean project. pip-audit exits 1 on a resolution
 * failure (a Poetry-only `pyproject.toml` it cannot read, a broken
 * requirements file, a network error reaching PyPI) the SAME way it exits 1
 * when vulnerabilities are found, and on that failure path the `-o` file is
 * either never written or contains something that is not this shape (fix
 * round 1, item 3 / Global Constraint 3: "a scanner that failed is never
 * reported as ok"). Mirrors `looksLikeNpmAuditReport` above for the same
 * reason: exit code alone cannot tell a real report apart from a masked
 * error.
 */
function looksLikePipAuditReport(raw) {
    try {
        const j = JSON.parse(raw);
        return !!j && typeof j === 'object' && Array.isArray(j['dependencies']);
    }
    catch {
        return false;
    }
}
/**
 * Runs `pip-audit --format json` once PER requirements file (never bare —
 * see this file's own module comment), or once against the project
 * directory for a `pyproject.toml`-only project. One call per file, not one
 * call with several `-r` flags, so `pipAuditParser` can attribute every
 * finding to the REAL file it came from (fix round 1, item 9) — pip-audit's
 * own JSON says nothing about which requirements file a dependency was
 * read from, so a combined call cannot be attributed at all. The captured
 * JSON is annotated with `__source_file` before being handed to the parser
 * (`scanToolFactory.ts` builds one shared `ParserContext` for a whole scan,
 * so a per-call override cannot go through `ctx` — see `pipAuditParser`'s
 * own doc comment).
 *
 * Aggregated into ONE `tools_run` entry across every file (`ok` if at least
 * one call produced a real report, `failed` only if every call did not) —
 * `create_fix_pr` and every other consumer of `tools_run` expect one entry
 * per named tool, the same pattern `runDotnetSca` already uses for multiple
 * `.csproj` targets.
 */
async function runPipAudit(opts) {
    const { ctx, reportDir, tools_run, missing_tools, parser_inputs } = opts;
    const { files: requirementsFiles, outside } = findRequirementsFiles(ctx.projectPath);
    const hasPyproject = presentInProject(ctx.projectPath, 'pyproject.toml');
    // Nothing to audit — not a gap. A candidate that leads out of the project is one.
    if (requirementsFiles.length === 0 && !hasPyproject && outside.length === 0)
        return;
    const bin = await scannerAvailable('pip-audit');
    if (!bin) {
        tools_run.push({ name: 'pip-audit', status: 'skipped', reason: 'not_installed' });
        missing_tools.push('pip-audit');
        return;
    }
    // Something left unaudited is a gap in coverage, whatever the rest did.
    if (outside.length > 0)
        missing_tools.push('pip-audit');
    if (requirementsFiles.length === 0 && !hasPyproject) {
        tools_run.push(withOutsideRequirements({ name: 'pip-audit', status: 'skipped' }, outside));
        return;
    }
    // One "target" per invocation: each requirements file individually, or
    // the project directory itself when there is no requirements file at all.
    const targets = requirementsFiles.length > 0
        ? requirementsFiles.map((f) => ({ arg: f, sourceFile: relative(ctx.projectPath, f) || f }))
        : [{ arg: ctx.projectPath, sourceFile: 'pyproject.toml' }];
    let anyOk = false;
    let anyFailed = false;
    for (const [i, target] of targets.entries()) {
        const outFile = join(reportDir, `pip-audit-${i}.json`);
        const args = requirementsFiles.length > 0
            ? ['-r', target.arg, '--format', 'json', '-o', outFile]
            : ['--format', 'json', '-o', outFile, target.arg];
        const result = await runProcess({
            command: 'pip-audit',
            args,
            cwd: ctx.projectPath,
            ...auditEnv(ctx),
            signal: ctx.signal,
            onLog: ctx.onLog,
        });
        // Exit 0/1 alone is not success — pip-audit exits 1 on a genuine
        // failure the same way it does on "vulnerabilities found" (item 3).
        const exitOk = result.outcome === 'completed' || result.exitCode === 0 || result.exitCode === 1;
        const raw = exitOk ? readJsonSafe(outFile) : null;
        if (raw && looksLikePipAuditReport(raw)) {
            anyOk = true;
            let annotated = raw;
            try {
                const parsed = JSON.parse(raw);
                parsed['__source_file'] = target.sourceFile;
                annotated = JSON.stringify(parsed);
            }
            catch {
                /* raw already passed looksLikePipAuditReport, so this is unreachable
                 * in practice; fall back to the unannotated text rather than drop it */
            }
            parser_inputs.push({ parser: pipAuditParser, input: annotated });
        }
        else {
            anyFailed = true;
        }
    }
    // What decides where pip-audit's resolution installs from, named
    // (`runners/repoConfig.ts`): honoured — a private index, a VCS dependency
    // are legitimate in the user's own audit — never silently. Read with the
    // same fail-closed parser create_fix_pr refuses by (`deps/pipRequirements.ts`),
    // so an index option, a direct / URL / VCS / network-path requirement, an
    // editable one, and what pip reads that this server could not check (an
    // include out of the project or of a URL, `${VAR}`, an unreadable file)
    // are each named with its line — a URL as `scheme://host` only.
    const steering = pipSourcesNamed(ctx.projectPath, requirementsFiles, requirementsFiles.length === 0 && hasPyproject);
    const named = (run) => withOutsideRequirements(withProjectConfig(run, steering), outside);
    if (anyOk) {
        tools_run.push(named({
            name: 'pip-audit',
            status: 'ok',
            reason: anyFailed ? 'parsed into findings (failed for at least one target)' : 'parsed into findings',
        }));
        if (anyFailed && outside.length === 0)
            missing_tools.push('pip-audit');
    }
    else {
        tools_run.push(named({
            name: 'pip-audit',
            status: 'failed',
            reason: 'ran but produced no audit report for any target (resolution failure or unsupported project?)',
        }));
        if (outside.length === 0)
            missing_tools.push('pip-audit');
    }
}
/** Refusals shown per file in a note; `honoured_config` names every file. */
const MAX_LINES_NAMED = 3;
/** Requirements candidates leading out of the project, named in the reason at most. */
const MAX_UNREAD_NAMED = 5;
/**
 * What decides where pip-audit installs from, as honoured-config entries:
 * the requirements files handed to it (and all they include), or — when it
 * builds the project itself — `pyproject.toml` and `setup.cfg`. One entry
 * per file and category, its lines named:
 *
 *   - index options: "its package-index options decide which index
 *     pip-audit's resolution installs from" (the wording `REPO_CONFIG` has
 *     always used);
 *   - a direct, URL, VCS, network-path, local-path or editable requirement,
 *     a tool's own source table: "its <kinds> (line N (scheme://host)) decide
 *     where pip-audit's resolution fetches from";
 *   - anything else the parser did not admit: "pip reads what dev-guardian
 *     did not check (line N: …) — pip may take its sources from it".
 */
function pipSourcesNamed(projectPath, requirementsFiles, buildsProject) {
    const handed = requirementsFiles.map((f) => relative(projectPath, f) || f);
    const refusals = [
        ...checkRequirements(projectPath, handed, projectPath).refusals,
        ...(buildsProject ? [...checkPyproject(projectPath, projectPath, true), ...checkSetupCfg(projectPath, projectPath)] : []),
    ];
    const groups = new Map();
    for (const r of refusals) {
        const category = INDEX_KINDS.has(r.kind) ? 'index' : SOURCE_KINDS.has(r.kind) ? 'source' : 'unchecked';
        const key = `${r.file}\0${category}`;
        const g = groups.get(key) ?? { category, items: [] };
        g.items.push(r);
        groups.set(key, g);
    }
    const lineOf = (r) => {
        const at = r.line > 0 ? `line ${r.line}` : 'the file';
        const extra = [r.detail, r.host].filter((x) => x !== undefined && x !== '');
        return `${at}${extra.length > 0 ? ` (${extra.join(', ')})` : ''}`;
    };
    const out = [];
    for (const [key, g] of groups) {
        const file = key.slice(0, key.indexOf('\0'));
        const shown = g.items.slice(0, MAX_LINES_NAMED);
        const more = g.items.length > shown.length ? ` and ${g.items.length - shown.length} more` : '';
        if (g.category === 'index') {
            out.push({ path: file, decides: "its package-index options decide which index pip-audit's resolution installs from" });
        }
        else if (g.category === 'source') {
            const kinds = [...new Set(g.items.map((r) => r.kind))].join(', ');
            out.push({ path: file, decides: `its ${kinds} (${shown.map(lineOf).join('; ')}${more}) decide where pip-audit's resolution fetches from` });
        }
        else {
            const what = shown.map((r) => `${lineOf(r).replace(/^line \d+|^the file/, (m) => `${m}: ${r.kind}`)}`).join('; ');
            out.push({ path: file, decides: `pip reads what dev-guardian did not check (${what}${more}) — pip may take its sources from it` });
        }
    }
    return out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}
/**
 * Runs `dotnet list <target> package --vulnerable --include-transitive
 * --format json --no-restore` for every target `findDotnetTargets` finds,
 * each one preceded by an explicit `dotnet restore` planned by
 * `planDotnetRestore` (`../deps/dotnetRestore.ts` — its module comment has
 * the measured rules): `--locked-mode` on every restore, lock files found from
 * the solution/project list rather than a depth-limited walk, and a restore
 * that would create a lock file is either prevented
 * (`-p:RestorePackagesWithLockFile=false`) or not run at all. `dotnet list`
 * never restores on its own (`--no-restore`), so the listing is always built
 * from the restore this call just ran — which is also why no
 * `requestedVersion`/`resolvedVersion` comparison is made any more: after a
 * fresh restore the two legitimately differ for every floating (`12.*`),
 * range (`[12.0.1,13.0)`), two-part (`12.0`) or not-on-the-feed (`12.0.0`
 * resolving to `12.0.1`) reference, and treating that as staleness threw real
 * findings away.
 *
 * A failed target is one coverage gap, not a whole-scan failure — the other
 * targets still run — and its reason carries NuGet's own code, so an
 * out-of-sync lock (`NU1004`) reads differently from a missing package
 * (`NU1101`) or an unreachable feed (`NU1301`).
 */
async function runDotnetSca(opts) {
    const { ctx, reportDir, tools_run, missing_tools, parser_inputs } = opts;
    const targets = findDotnetTargets(ctx.projectPath);
    if (targets.length === 0)
        return []; // no .sln/.csproj — nothing to do, not a gap
    const dotnetBin = await scannerAvailable('dotnet');
    if (!dotnetBin) {
        tools_run.push({ name: 'dotnet', status: 'skipped', reason: 'not_installed' });
        missing_tools.push('dotnet');
        return [];
    }
    let anyOk = false;
    const failures = [];
    for (const [i, target] of targets.entries()) {
        const rel = relative(ctx.projectPath, target) || target;
        const plan = planDotnetRestore(ctx.projectPath, target);
        if (plan.blocked) {
            failures.push({ target: rel, code: plan.blocked.code, reason: plan.blocked.reason });
            continue;
        }
        const restore = await runProcess({
            command: 'dotnet',
            args: plan.args,
            cwd: ctx.projectPath,
            ...auditEnv(ctx),
            signal: ctx.signal,
            onLog: ctx.onLog,
        });
        const created = removeCreatedLockFiles(plan);
        if (created.length > 0) {
            failures.push({
                target: rel,
                code: 'lock_file_would_be_created',
                reason: `restore created ${created.map((c) => relative(ctx.projectPath, c) || c).join(', ')} ` +
                    '(a RestorePackagesWithLockFile opt-in this scan could not see) — deleted again; results not used',
            });
            continue;
        }
        if (restore.outcome !== 'completed') {
            // Never retried without --locked-mode: that retry would be exactly the
            // lock rewrite this whole sequence exists to prevent.
            const failure = classifyRestoreFailure(restore.stdout, restore.stderr);
            failures.push({ target: rel, code: failure.code, reason: failure.reason });
            continue;
        }
        const list = await runProcess({
            command: 'dotnet',
            args: ['list', target, 'package', '--vulnerable', '--include-transitive', '--format', 'json', '--no-restore'],
            cwd: ctx.projectPath,
            ...auditEnv(ctx),
            signal: ctx.signal,
            onLog: ctx.onLog,
        });
        if (list.outcome !== 'completed' || list.stdout.trim().length === 0) {
            failures.push({ target: rel, code: 'list_failed', reason: 'restored, but `dotnet list package --vulnerable` failed' });
            continue;
        }
        anyOk = true;
        parser_inputs.push({ parser: dotnetScaParser, input: list.stdout });
        try {
            writeFileSync(join(reportDir, `dotnet-list-${i}.json`), list.stdout, 'utf8');
        }
        catch {
            /* best-effort evidence copy */
        }
    }
    const gapReason = failures.map((f) => `${f.target}: ${f.reason}`).join('; ');
    // The project's NuGet.config files answer the lookup: named (`runners/repoConfig.ts`).
    if (anyOk) {
        tools_run.push(await nameRepoConfig({
            name: 'dotnet',
            status: 'ok',
            reason: failures.length > 0 ? `parsed into findings (gap — ${gapReason})` : 'parsed into findings',
        }, ctx.projectPath, 'dotnet'));
        if (failures.length > 0)
            missing_tools.push('dotnet');
    }
    else {
        tools_run.push(await nameRepoConfig({ name: 'dotnet', status: 'failed', reason: gapReason || 'no target could be listed' }, ctx.projectPath, 'dotnet'));
        missing_tools.push('dotnet');
    }
    return failures;
}
//# sourceMappingURL=depsAudit.js.map