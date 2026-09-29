/**
 * `applyGroup` — runs a `FixGroup`'s fix inside an already-created worktree
 * (the design of record).
 *
 * The property this module exists to hold: a command STRING never reaches a
 * shell. `runProcess` is `shell: false` end to end, so every command run
 * here is handed over as `{ command, args }` — an argv array — never as a
 * single string a shell would have to parse. `upgrade_command` carries a
 * version string read off a package registry: input this project did not
 * author, and it is never interpolated into anything a shell would
 * interpret, because nothing here ever calls a shell in the first place.
 *
 * Two fix sources, two shapes (the design of record):
 *
 *   - `deps`: each candidate carries the structured `UpgradeStep`s
 *     `deps_update_plan` planned for its package (Task 10), run ONE STEP AT A
 *     TIME, in order, stopping at the first failure so a later step never runs
 *     against a tree a failed upgrade already left half-modified:
 *       - a pip step is an EDIT of the pin in the step's structured `file`,
 *         inside the worktree — never `pip install` (it would upgrade the
 *         host's own site-packages; the step's `upgrade_command` is a
 *         human-readable label that fails closed if executed);
 *       - every other step's `upgrade_command` is split into argv and run,
 *         then its `follow_up_command` when it has one (an npm `overrides`
 *         step only edits package.json; `npm install` re-resolves the lock).
 *     Every npm command that installs runs with `--ignore-scripts`, and every
 *     composer command that installs with `--no-scripts`, added here when the
 *     plan's command lacks it: a dependency's lifecycle script is arbitrary
 *     code, and a dry run must never execute it (Task 11 items 1 and 5).
 *     Bundler runs only as `bundle lock` — `bundle update` would install
 *     gems into the host's GEM_HOME (see `harden`).
 *   - `semgrep`: ONE `--autofix` pass for the whole group, with ONLY the
 *     target rules (`./semgrepFix.ts` — filtered copies of local rule files,
 *     `r/<rule-id>` for registry rules), `--metrics=off`, over the targets'
 *     files only, and judged by its report (Global Constraint 3): a pass that
 *     scanned nothing or reported errors did not apply the fix. A target file
 *     that is not in the worktree (uncommitted in the user's tree) fails the
 *     group — it can be neither fixed nor verified from committed HEAD.
 *
 * `lockfileOnly` (the design of record): when no test command was derived for the
 * project, verification never needs an installed `node_modules` tree — only
 * the manifest and lockfile, which `npm audit`/Trivy read directly — so
 * `--package-lock-only` is added to an `npm install` step and the whole
 * verification stays in seconds. `applyGroup` only ever does what
 * `lockfileOnly` says, and only on npm's `install` subcommand.
 */
import { existsSync, rmSync } from 'node:fs';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { describeReadRefusal, describeWriteRefusal, PROJECT_FILE_MAX_BYTES, readProjectBytes, writeProjectFile, } from '../platform/projectFs.js';
import { batchArgs } from '../runners/argBatches.js';
import { runProcess } from '../runners/processRunner.js';
import { checkSemgrepReport } from '../runners/semgrepReport.js';
import { runSemgrep, SEMGREP_COMMAND } from '../runners/semgrepRun.js';
import { readJsonSafe } from '../tools/scanHelpers.js';
import { packageManagerEnv } from './testCommandEnv.js';
export async function applyGroup(opts) {
    const run = opts.run ?? runProcess;
    if (opts.group.source === 'semgrep') {
        if (opts.semgrepFix === undefined) {
            return {
                applied: false,
                commands: [],
                failure: { command: 'semgrep --autofix', outcome: 'failed', exit_code: null, stderr_head: 'no fix plan: the target rules were not resolved' },
            };
        }
        return applySemgrepPass(run, opts.worktreePath, opts.timeoutMs, opts.semgrepFix);
    }
    return applyDepsCandidates(run, opts.worktreePath, opts.timeoutMs, opts.lockfileOnly, opts.group.candidates);
}
// --------------------------------------------------------------- semgrep
async function applySemgrepPass(run, worktreePath, timeoutMs, plan) {
    const label = `semgrep --metrics=off --autofix [${plan.configLabels.join('; ')}]`;
    const missing = plan.files.filter((f) => !existsSync(join(worktreePath, f)));
    if (missing.length > 0) {
        return {
            applied: false,
            commands: [],
            failure: {
                command: label,
                outcome: 'failed',
                exit_code: null,
                stderr_head: `target file(s) not in the committed tree: ${missing.join(', ')} — a finding in an ` +
                    'uncommitted file can be neither fixed nor verified from HEAD',
            },
        };
    }
    const fixed = ['--metrics=off', ...plan.configs.map((c) => `--config=${c}`), '--autofix', '--json', '--quiet'];
    const batches = batchArgs(plan.files, {
        command: SEMGREP_COMMAND,
        fixedArgs: [...fixed, '--output', join(plan.dir, 'fix-000.json'), '--'],
    });
    const commands = [];
    for (let i = 0; i < batches.length; i++) {
        const batch = batches[i] ?? [];
        const report = join(plan.dir, `fix-${String(i).padStart(3, '0')}.json`);
        rmSync(report, { force: true });
        // UTF-8 mode comes with the helper (runners/semgrepRun.ts).
        const result = await runSemgrep({
            args: [...fixed, '--output', report, '--', ...batch],
            cwd: worktreePath,
            timeoutMs,
        }, run);
        const invoked = `${label} -- ${batch.join(' ')}`;
        commands.push(invoked);
        const check = checkSemgrepReport({ raw: readJsonSafe(report), exitCode: result.exitCode, outcome: result.outcome, targets: batch.length });
        if (!check.ok) {
            // `partial` on a clean exit: --autofix DID write the fix in the
            // worktree, but the run that would verify it is incomplete (a file not
            // fully parsed, a taint fixpoint timeout) — `incomplete`, never
            // "failed" (review of the LLM pack, round 3). Either way the worktree
            // is discarded and the project is untouched.
            const incomplete = check.verdict === 'partial';
            return {
                applied: false,
                commands,
                failure: {
                    command: invoked,
                    outcome: incomplete ? 'incomplete' : result.outcome === 'completed' ? 'failed' : result.outcome,
                    exit_code: result.exitCode,
                    stderr_head: check.reason ?? firstStderrLine(result.stderr),
                },
            };
        }
    }
    return { applied: true, commands, failure: null };
}
// --------------------------------------------------------------- deps
async function applyDepsCandidates(run, worktreePath, timeoutMs, lockfileOnly, candidates) {
    const commands = [];
    for (const candidate of candidates) {
        const steps = candidate.steps ?? [];
        if (steps.length === 0) {
            // Never happens for a `deps` group in practice — `buildGroups` pairs a
            // finding only with a real step. Handled anyway, with a NAMED failure
            // rather than a silent skip: a `continue` here would let this fix not
            // happen while the group still reported `applied: true`.
            return {
                applied: false,
                commands,
                failure: { command: candidate.label, outcome: 'failed', exit_code: null, stderr_head: `no upgrade step for '${candidate.label}'` },
            };
        }
        for (const step of steps) {
            const failure = await applyStep(run, worktreePath, timeoutMs, lockfileOnly, step, commands);
            if (failure !== null)
                return { applied: false, commands, failure };
        }
    }
    return { applied: true, commands, failure: null };
}
/** One step, then its follow-up. Null on success, the failure otherwise. */
async function applyStep(run, worktreePath, timeoutMs, lockfileOnly, step, commands) {
    if (step.ecosystem === 'pip') {
        const edit = editPipPin(worktreePath, step);
        commands.push(edit.label);
        if (!edit.ok)
            return { command: edit.label, outcome: 'failed', exit_code: null, stderr_head: edit.reason };
    }
    else {
        const failure = await runCommand(run, worktreePath, timeoutMs, lockfileOnly, step.upgrade_command, commands);
        if (failure !== null)
            return failure;
    }
    if (step.follow_up_command !== undefined && step.follow_up_command.trim().length > 0) {
        return runCommand(run, worktreePath, timeoutMs, lockfileOnly, step.follow_up_command, commands);
    }
    return null;
}
async function runCommand(run, worktreePath, timeoutMs, lockfileOnly, commandLine, commands) {
    const argv = toArgv(commandLine);
    if (argv === null) {
        return { command: commandLine, outcome: 'failed', exit_code: null, stderr_head: 'empty command' };
    }
    const refused = harden(argv, lockfileOnly);
    if (refused !== null) {
        return { command: commandLine, outcome: 'failed', exit_code: null, stderr_head: refused };
    }
    // A package manager, fetching: never with this server's environment — the
    // allowlist plus the user's own package-manager configuration
    // (`fixpr/testCommandEnv.ts#packageManagerEnv`).
    const result = await run({
        command: argv.command,
        args: argv.args,
        cwd: worktreePath,
        env: packageManagerEnv(),
        extendEnv: false,
        timeoutMs,
    });
    const invoked = [argv.command, ...argv.args].join(' ');
    commands.push(invoked);
    // `outcome !== 'completed'`, never a list of failure outcomes: a
    // timed_out or output_too_large step did not finish either.
    return result.outcome === 'completed' ? null : buildFailure(invoked, result);
}
/** npm subcommands that install packages — and so run lifecycle scripts. */
const NPM_INSTALLING = new Set(['install', 'i', 'add', 'ci', 'update', 'up', 'upgrade', 'install-clean']);
/** composer subcommands that install packages — and so run package scripts. */
const COMPOSER_INSTALLING = new Set(['require', 'install', 'update', 'upgrade']);
/**
 * `--ignore-scripts` on every installing npm command and `--no-scripts` on
 * every installing composer command (see the module comment), and
 * `--package-lock-only` on `npm install` when `lockfileOnly`. Bundler runs
 * only as `bundle lock` (re-resolving Gemfile.lock): `bundle update <gem>` is
 * rewritten to `bundle lock --update <gem>`, and any other subcommand is
 * refused — they install gems into the host's GEM_HOME and compile native
 * extensions. Returns why the command was refused, or null.
 */
function harden(argv, lockfileOnly) {
    const sub = argv.args[0] ?? '';
    if (argv.command === 'bundle') {
        if (sub === 'update')
            argv.args.splice(0, 1, 'lock', '--update');
        else if (sub !== 'lock') {
            return `refused: 'bundle ${sub}' would install gems into the host (only 'bundle lock' runs)`;
        }
    }
    if (argv.command === 'npm' && NPM_INSTALLING.has(sub)) {
        if (!argv.args.includes('--ignore-scripts'))
            argv.args.push('--ignore-scripts');
        if (lockfileOnly && (sub === 'install' || sub === 'i') && !argv.args.includes('--package-lock-only')) {
            argv.args.push('--package-lock-only');
        }
    }
    if (argv.command === 'composer' && COMPOSER_INSTALLING.has(sub) && !argv.args.includes('--no-scripts')) {
        argv.args.push('--no-scripts');
    }
    return null;
}
/**
 * The pip step, as an edit: the exact pin `name==installed` in the step's
 * `file` (a requirements file or pyproject.toml, relative to the project)
 * becomes `name==latest`. The name matches the way pip compares names
 * (PEP 503: case-insensitive, `-`/`_`/`.` interchangeable); extras and
 * environment markers are kept. A file outside the worktree, a missing file
 * or a pin that is not there fails the step by name.
 */
function editPipPin(worktreePath, step) {
    const file = step.file ?? '';
    const label = `edit ${file || '(no file)'}: ${step.package_name}==${step.installed_version} -> ${step.package_name}==${step.latest_version}`;
    if (file.length === 0)
        return { ok: false, label, reason: 'the pip step names no file to edit' };
    const target = resolve(worktreePath, file);
    const rel = relative(worktreePath, target);
    if (isAbsolute(file) || rel === '' || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
        return { ok: false, label, reason: `'${file}' is not a file inside the project` };
    }
    // The worktree is a checkout of the repository, and a checkout creates the
    // links the repository holds: read and write through `platform/projectFs.ts`,
    // which refuses a link out of the worktree for the read and any link for
    // the write. Bytes, so a byte-order mark survives the edit.
    const read = readProjectBytes(worktreePath, file, PROJECT_FILE_MAX_BYTES);
    if (read.status === 'absent')
        return { ok: false, label, reason: `'${file}' is not in the committed tree` };
    if (read.status === 'refused') {
        return { ok: false, label, reason: `'${file}' was not read: ${describeReadRefusal(read.reason)}` };
    }
    const text = read.bytes.toString('utf8');
    const name = step.package_name.split(/[-_.]+/).map(escapeRegExp).join('[-_.]+');
    const pin = new RegExp(`(^|[\\s"'\\[,])(${name})(\\s*\\[[^\\]]*\\])?(\\s*==\\s*)${escapeRegExp(step.installed_version)}(?=$|[\\s;"',#\\]\\\\])`, 'gim');
    let count = 0;
    const edited = text.replace(pin, (_m, lead, pkg, extras, op) => {
        count += 1;
        return `${lead}${pkg}${extras ?? ''}${op}${step.latest_version}`;
    });
    if (count === 0) {
        return { ok: false, label, reason: `no '${step.package_name}==${step.installed_version}' pin in '${file}'` };
    }
    const written = writeProjectFile(worktreePath, file, edited, { mode: 'replace' });
    if (!written.ok) {
        return { ok: false, label, reason: `'${file}' was not written: ${describeWriteRefusal(written.reason, written.detail)}` };
    }
    return { ok: true, label };
}
// --------------------------------------------------------------- shared
/**
 * Splits a command STRING into `{ command, args }` for `runProcess`, which
 * is `shell: false` end to end. Exact for every command this feature
 * receives: `deps_update_plan`'s templates interpolate only a package
 * identifier and a version between fixed literal tokens, and neither may
 * contain whitespace. It is NOT a shell-quoting parser — there is no shell on
 * the other end whose quoting rules would need reproducing
 * (`deps_update_plan` keeps `upgrade_command` unquoted for exactly this
 * reason; its `shell_command` is the quoted, human copy).
 */
function toArgv(commandLine) {
    const tokens = commandLine
        .trim()
        .split(/\s+/)
        .filter((token) => token.length > 0);
    const [command, ...args] = tokens;
    if (command === undefined)
        return null;
    return { command, args };
}
/**
 * `result.outcome` is reported verbatim, whatever it is — including
 * `timed_out` and `output_too_large`: a silently-swallowed timeout would
 * report a fix as applied when the process that was supposed to apply it
 * never finished.
 */
function buildFailure(invoked, result) {
    return {
        command: invoked,
        outcome: result.outcome,
        exit_code: result.exitCode,
        stderr_head: firstStderrLine(result.stderr),
    };
}
/** The first non-blank line of stderr — the one that says what happened. */
function firstStderrLine(stderr) {
    for (const line of stderr.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (trimmed.length > 0)
            return trimmed;
    }
    return '(no stderr output)';
}
function escapeRegExp(text) {
    return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
//# sourceMappingURL=apply.js.map