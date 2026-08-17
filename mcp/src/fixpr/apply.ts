/**
 * `applyGroup` — runs a `FixGroup`'s fix commands inside an already-created
 * worktree (design doc `docs/superpowers/specs/2026-08-16-create-fix-pr-design.md`
 * §2 and §4.3).
 *
 * The property this module exists to hold: a command STRING never reaches a
 * shell. `runProcess` is `shell: false` end to end, so every command run
 * here is handed over as `{ command, args }` — an argv array — never as a
 * single string a shell would have to parse. `upgrade_command` carries a
 * version string read off a package registry: input this project did not
 * author, and it is never interpolated into anything a shell would
 * interpret, because nothing here ever calls a shell in the first place.
 *
 * Two fix sources, two shapes (design doc §2):
 *
 *   - `deps`: each candidate carries its own pinned `command` — a full
 *     `npm install pkg@version` / `pip install -U pkg==version` / … string
 *     `deps_update_plan` already computed. Split on whitespace into argv and
 *     run ONE PROCESS PER CANDIDATE, in order, stopping at the first
 *     failure so a later candidate never runs against a tree a failed
 *     upgrade already left half-modified.
 *   - `semgrep`: candidates carry `command: null` — there is nothing to
 *     split, because `--autofix` rewrites everything its rules match across
 *     the whole tree in a SINGLE pass. Running it once per candidate would
 *     invoke Semgrep repeatedly over a tree it (partly) already rewrote on
 *     the previous pass. So the semgrep branch never looks at `candidates`
 *     at all: the group's mere existence is the trigger for exactly one call.
 *
 * `lockfileOnly` (design doc §4.3): when no test command was derived for the
 * project, verification never needs an installed `node_modules` tree — only
 * the manifest and lockfile, which `npm audit`/Trivy read directly — so
 * `--package-lock-only` is added to an `npm install` step and the whole
 * verification stays in seconds. When a test command DOES exist, the suite
 * needs a real install to run against, so the flag is withheld and the cost
 * moves from seconds to minutes. That trade is `create_fix_pr`'s decision,
 * not this module's — `applyGroup` only ever does what `lockfileOnly` says,
 * and only on npm's `install` subcommand: the flag is npm-install-specific,
 * and no other ecosystem's upgrade command has an equivalent shortcut.
 */

import { runProcess, type ProcessRunResult } from '../runners/processRunner.js';
import type { FixCandidate, FixGroup } from './types.js';

export interface ApplyResult {
  applied: boolean;
  /** The commands actually run, for the PR body. */
  commands: string[];
  /** Set when applied === false. */
  failure: { command: string; outcome: string; exit_code: number | null; stderr_head: string } | null;
}

export async function applyGroup(opts: {
  group: FixGroup;
  worktreePath: string;
  /** Injected so tests can supply a fake. Defaults to the real runProcess. */
  run?: typeof runProcess;
  timeoutMs?: number;
  /** True when no test command was derived, so the lockfile-only path is allowed. */
  lockfileOnly: boolean;
}): Promise<ApplyResult> {
  const run = opts.run ?? runProcess;
  return opts.group.source === 'semgrep'
    ? applySemgrepPass(run, opts.worktreePath, opts.timeoutMs)
    : applyDepsCandidates(
        run,
        opts.worktreePath,
        opts.timeoutMs,
        opts.lockfileOnly,
        opts.group.candidates,
      );
}

// --------------------------------------------------------------- semgrep

async function applySemgrepPass(
  run: typeof runProcess,
  worktreePath: string,
  timeoutMs: number | undefined,
): Promise<ApplyResult> {
  // One pass for the WHOLE group, never one per candidate — see the module
  // comment. How many findings the group covers has no bearing on how many
  // times this runs, so `candidates` is deliberately not a parameter here.
  const { invoked, result } = await runOne(run, worktreePath, timeoutMs, {
    command: 'semgrep',
    args: ['--config', 'auto', '--autofix', '--quiet'],
  });
  if (result.outcome !== 'completed') {
    return { applied: false, commands: [invoked], failure: buildFailure(invoked, result) };
  }
  return { applied: true, commands: [invoked], failure: null };
}

// --------------------------------------------------------------- deps

async function applyDepsCandidates(
  run: typeof runProcess,
  worktreePath: string,
  timeoutMs: number | undefined,
  lockfileOnly: boolean,
  candidates: readonly FixCandidate[],
): Promise<ApplyResult> {
  const commands: string[] = [];
  for (const candidate of candidates) {
    const argv = candidate.command === null ? null : toArgv(candidate.command);
    if (argv === null) {
      // Never happens for a `deps` group in practice — `buildGroups` (Task 1)
      // always sets a real, non-empty `upgrade_command` here; `command: null`
      // is the SEMGREP shape, the other branch of this same union. Handled
      // anyway, with a NAMED failure rather than a silent skip: a `continue`
      // here would let this candidate's fix simply not happen while the
      // group still reports `applied: true` for the others — exactly the
      // "something that did not happen acquiring the appearance of having
      // happened" this feature exists to rule out (design doc §4.1).
      return {
        applied: false,
        commands,
        failure: {
          // `||`, not `??`: a present-but-empty command string is exactly as
          // unrunnable as a missing one, and only `||` treats both as
          // "nothing useful here" — this project's own recurring `??` trap.
          command: candidate.command || candidate.label,
          outcome: 'failed',
          exit_code: null,
          stderr_head: `no runnable command for '${candidate.label}'`,
        },
      };
    }

    // npm-only, and only its `install` subcommand — see the module comment.
    if (lockfileOnly && argv.command === 'npm' && argv.args[0] === 'install') {
      argv.args.push('--package-lock-only');
    }

    const { invoked, result } = await runOne(run, worktreePath, timeoutMs, argv);
    commands.push(invoked);
    if (result.outcome !== 'completed') {
      // Stop here — see the module comment on why a later candidate must
      // never run against what this failed upgrade may have left behind.
      return { applied: false, commands, failure: buildFailure(invoked, result) };
    }
  }
  return { applied: true, commands, failure: null };
}

// --------------------------------------------------------------- shared

/**
 * Splits a command STRING into `{ command, args }` for `runProcess`, which
 * is `shell: false` end to end — the same plain-whitespace idiom
 * `bashGuard.ts` already uses elsewhere in this repo to tokenise a shell
 * command for INSPECTION (never execution).
 *
 * This is exact, not merely convenient, for every command this feature
 * actually receives: every `upgrade_command` template in
 * `depsUpdatePlan.ts` (all seven ecosystems — npm, pip, composer, cargo, go,
 * rubygems, dotnet) interpolates only a package/crate/gem/module identifier
 * and a version string between fixed literal tokens (`npm install
 * ${pkg}@${latest}`, `pip install -U ${name}==${latest}`, `cargo update -p
 * ${name} --precise ${latest}`, `composer require ${name}:^${latest}`, `go
 * get ${name}@${latest}`, `bundle update ${name}`, `dotnet add package
 * ${name} --version ${latest}`) — and none of those ecosystems' naming rules
 * allow whitespace inside a package identifier or a version string. A
 * quoted, space-containing argument such as `pip install
 * "requests>=2.32,<3"` never comes out of `depsUpdatePlan.ts` today: its pip
 * branch always emits an exact `==` pin, never a range, and never wraps
 * anything in quotes.
 *
 * This function is NOT a general shell-quoting parser and does not try to
 * become one: `runProcess` never invokes a shell, so "parsing quotes
 * correctly" is the wrong frame to begin with — there is no shell on the
 * other end whose quoting rules would need reproducing. If a future
 * ecosystem generator ever needs a compound argument, the fix belongs
 * upstream — hand `{ command, args }` over directly instead of a joined
 * string — not here, reverse-engineering intent out of text.
 */
function toArgv(commandLine: string): { command: string; args: string[] } | null {
  const tokens = commandLine
    .trim()
    .split(/\s+/)
    .filter((token) => token.length > 0);
  const [command, ...args] = tokens;
  if (command === undefined) return null;
  return { command, args };
}

async function runOne(
  run: typeof runProcess,
  worktreePath: string,
  timeoutMs: number | undefined,
  argv: { command: string; args: string[] },
): Promise<{ invoked: string; result: ProcessRunResult }> {
  const result = await run({ command: argv.command, args: argv.args, cwd: worktreePath, timeoutMs });
  return { invoked: [argv.command, ...argv.args].join(' '), result };
}

/**
 * `result.outcome` is reported verbatim, whatever it is — including
 * `timed_out` and `output_too_large`, both non-'completed' outcomes from
 * `runProcess` and both failures here, exactly like `failed`. Branching on
 * `outcome !== 'completed'` (the caller's job, not this function's) rather
 * than enumerating the failure outcomes one by one is what keeps every one
 * of them caught: a silently-swallowed timeout would report a fix as
 * applied when the process that was supposed to apply it never actually
 * finished.
 */
function buildFailure(invoked: string, result: ProcessRunResult): NonNullable<ApplyResult['failure']> {
  return {
    command: invoked,
    outcome: result.outcome,
    exit_code: result.exitCode,
    stderr_head: firstStderrLine(result.stderr),
  };
}

/**
 * The first non-blank line of stderr — not the whole blob. npm's error
 * output routinely runs to dozens of lines; the first is the one that says
 * what happened ("npm ERR! 404 Not Found"), and everything after is detail
 * a PR body has no room for.
 */
function firstStderrLine(stderr: string): string {
  for (const line of stderr.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.length > 0) return trimmed;
  }
  return '(no stderr output)';
}
