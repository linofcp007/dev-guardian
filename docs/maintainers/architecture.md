# Architecture — what the repository is

> Maintainer notes, moved from `CLAUDE.md` (the index). Not loaded into sessions: read this file before you
> change its area.

## What this repo is

An all-in-one, 100% open-source Claude Code / Cowork plugin for security, bugfix,
quality, deps, observability, performance and compliance. Two halves:

- **Plugin front-end** — `skills/` (13 skills) + `commands/` (10 slash commands),
  declared in [`.claude-plugin/plugin.json`](../../.claude-plugin/plugin.json).
- **MCP server** — `mcp/` (TypeScript on `node:sqlite`), the real engine: 50 tools (and 16 hidden aliases),
  18 resources, registered by the import list in `mcp/src/registerAll.ts` (the folds,
  `mcp/src/tools/folds.ts`, decide which names `tools/list` shows — see prose.md). Built
  into one bundle, `mcp/dist/engine.js`, which the CLI runs too (`dist/server.js`
  starts the server from it — [build-and-test.md](build-and-test.md));
  [`docs/tools.md`](../../docs/tools.md) is generated from the registry.
  Node ≥ 22.13 is the floor (`engines`), and nothing may need
  `--experimental-sqlite`.
- **Guardrail hooks** — `hooks/hooks.json` (auto-discovered at the plugin root)
  with the `hooks/guardian-hook.mjs` dispatcher. Dependency-free and fail-open:
  SessionStart posture briefing; PostToolUse secret warning on writes;
  PreToolUse on `Bash|PowerShell` — the catastrophic-command block, then
  install-time package vetting (`mcp/src/pkgvet/hookDecision.ts`, 3 s network
  budget, `GUARDIAN_PKG_VET=0` opts out); PreToolUse on writes — an assistant's
  `Write`/`Edit`/`MultiEdit` of the hook configuration is always denied, and
  writing a provider token is denied when `secrets.block` is on. A project's
  `.guardian/hooks.config.json` may only make the protective hooks stricter
  (`projectOverrides` in the dispatcher: its `enabled: false`, `bash.block:
  false` and `bash.warn: false` are ignored, and SessionStart says so) —
  because a shell command can still write that file. Detection lives in
  `mcp/src/hooks/{secretScan,bashGuard}.ts` (pure, unit-tested) and is shared
  with the `dev-guardian check` CLI subcommand; the dispatcher loads it from
  its own bundle, `mcp/dist/hooks.js` (`src/hooksEntry.ts`), and that bundle's
  per-event parts (`hooksBash.js`, `hooksVet.js`, `hooksWrite.js`,
  `hooksSession.js` — build-and-test.md). The shell guard's reading of a
  command lives in `mcp/src/hooks/shell/` — the tokenizer (`split.ts`), the
  command word (`command.ts`), cmd.exe's line (`cmd.ts`), paths as the command
  moves (`paths.ts`), where each command of the line runs (`workdir.ts`, which the
  install vetting reads too), what it does to the filesystem (`effects.ts`), the
  program text it hands an interpreter (`interpreters.ts`) — and
  `bashGuard.ts` judges it. Every file a hook reads from
  the project or the user's home goes through `mcp/src/hooks/configFile.ts`:
  open (non-blocking), `fstat` the DESCRIPTOR, read at most cap + 1 bytes —
  only a regular file of at most 64 KiB (1 MiB for registry configuration).
  Never judge the path and then read it: a FIFO swapped in between, or a
  Windows link to a named pipe (which `stat`s as an empty regular file), hangs
  the read, and a hook that hits its 15 s timeout lets the tool call through.
  A path on the network (`\\host\share`) is never asked of the filesystem at
  all (`isNetworkPath`): an unreachable host held a Write 21 s. Every
  `hooks.json` entry is in exec form (`"command": "node"`, the dispatcher and
  the event in `"args"` — Claude Code ≥ 2.1.139; no shell per call, and no
  shell quoting of the plugin path); keep it that way. The write matchers also
  route third-party MCP write tools (`mcp__<server>__<tool>` with a file verb),
  which `describeWrite` in the dispatcher turns into the path and text the
  write guards judge. Each event imports only its own detectors, and the
  install vetting loads only behind `pkgvet/mayInstall.ts` (held to
  `parseInstallCommands` by its test) — the hook runs on every Bash call. The
  shell guard can also return `ask` (`BashAssessment.ask`, an agent-run
  `baseline update`), which the hook sends as `permissionDecision: "ask"`.
  User-facing detail: [`docs/hooks.md`](../../docs/hooks.md).

## What a scan of the project's own files leaves out

Only the ROOT `.guardian/`'s generated output — `reports/`, the database,
`dashboard.html`, `last-grill.md`, the CLI's `.gitignore` — listed once in
`mcp/src/platform/guardianOutput.ts` and matched by exact project-relative
path (Semgrep's flags, gitleaks' working tree and in-place config, scopes,
the `.guardianignore` listing, the tree hash). A `.guardian` folder below the
root is the project's code: 3.3.0 left out every folder of that name and a
pull request hid a command injection in `lib/.guardian/` (review 10, finding
1). Never add `.guardian` to an any-depth exclusion; walks that only look for
manifests or languages may keep `PROJECT_WALK_EXCLUDE`, listings that stand
for what a scanner reads use `SCANNED_WALK_EXCLUDE`. A Semgrep `--exclude`
with a slash is anchored at the GIT ROOT; measure one from Git Bash only with
`MSYS_NO_PATHCONV=1` (MSYS rewrites a leading `/`).

## Async git and the tree kill

`platform/gitSafety.ts` is loaded by the hook bundle, which may hold no npm
package, so it never imports `runners/childProcess.ts`. Its async runs
(`execGit`, `execGitBuffer`, the probes) go through an installable spawner;
`runners/gitExec.ts` installs the one on the shared tree kill, and
`runners/git.ts` (and every module calling `execGit` itself) imports it — a
new direct caller of `execGit` imports `runners/gitExec.js` too. The hooks
(SessionStart's `git status` and probes) keep the default, `spawnGitPlain`,
which stops git's tree with Node and the OS alone — git leads its own process
group on POSIX and the group is killed; on Windows System32's `taskkill /T /F`
runs before git is killed — and answers at most 2 s after a stop, whatever
still holds the pipes (`gitSafetyPlainSpawn.test.ts`). Before 3.4.0's merge it
killed git alone and waited for the pipes, so a helper git had started held
the SessionStart briefing for as long as it lived.
