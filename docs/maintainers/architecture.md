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
  SessionStart posture briefing, and the session mark it leaves in the user's
  data directory for `health_status` (`mcp/src/hooks/heartbeat.ts` — the one
  thing a hook writes, and only SessionStart does); PostToolUse secret warning on writes;
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
  `hooksSession.js`, `hooksProbe.js` — build-and-test.md). The shell guard's reading of a
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
  User-facing detail: [`docs/hooks.md`](../../docs/hooks.md). What the guards
  do not cover is data, not prose: one record per limit in
  `mcp/test/fixtures/hooks/known-limits.yml`, each with examples the suite
  runs against the real detector and dispatcher, rendered to
  [`docs/hooks-known-limits.md`](../../docs/hooks-known-limits.md)
  ([build-and-test.md](build-and-test.md)).

## The selftest

`node cli/dev-guardian.mjs selftest` ([`docs/selftest.md`](../selftest.md)) lives in `mcp/src/selftest/` and is a
leaf: nothing under `runners/`, `ci/`, `history/` or the scan tools imports it, and `health_status` and
`check_toolchain` import only its read side (`store.ts`, `paths.ts`) — `controls.test.ts` holds both.

- `controls.ts` — the registry: one control per file of `configs/semgrep/`, gitleaks, the two Trivy scans, five
  hook checks, and the rule each pack's canary must fire. `controlsProblems` fails the suite, by name, on a pack
  with no control or no canary.
- `canaries.ts` — the temporary directory (`mkdtemp`, removed without following a link) and the seeding of
  `configs/selftest/**.canary`; the secret canary is put together there from two halves.
- `run.ts` — the orchestrator. One probe run with the selftest's own Semgrep rule, then one run per pack: a pack
  that does not report a canary the probe read is `silent`, one the probe never read is `unverified`. Everything
  that starts a process is behind `SelftestRunners`; the real ones (`defaultRunners.ts`) are the scan tools' own
  functions, and the dispatcher is started by `hookRunner.ts` with no shell. One hook check, `hooks:install-vet`,
  waits on the network (the registry and OSV, asked by the dispatcher): its launch starts before the other four and
  is awaited at its own turn. It is not launched offline or with package vetting switched off, and it recognises
  the hook's "could not vet" line by the constants `pkgvet/hookDecision.ts` writes it with. A test that starts the
  real dispatcher for a selftest replaces the registry (`registryReplaced` in `test/e2e/selftestCli.test.ts`).
- `verdict.ts`, `report.ts` — pure. `store.ts` — the result, per install, as two JSON files in the data directory,
  validated when read back; never the project's database.

It opens no database and reads no project. A new raw `node:fs` call there goes in `rawRepoFsSites.test.ts` like any
other, and a new rule pack needs a canary (`configs/selftest/README.md`).

## The diff's own passes (`mcp/src/testintegrity/`)

`review_pr`, a diff-scoped `scan_sast` and the CLI's `scan --diff-base` read the change itself in two passes, each
its own `tools_run` name (`history/runNames.ts`):

- `guardian-test-integrity` (`detect.ts`, `gitChanges.ts#runTestIntegrityCheck`): weakened tests. Null when the
  change touches no test file, `package.json` or Rust source; a change git cannot read is a failed run, a gap.
- `guardian-suppressions` (3.17.0, `suppressions.ts`, `gitChanges.ts#runSuppressionCheck`): the suppressions the
  change adds with no reason. Its own name so a reader of the verdict (dev-spec-driven's finish labels every
  `guardian-test-integrity` finding a weakened test) never takes one for the other. It never gates: no finding is high, a failed listing or
  a base with no merge base is `skipped`, and its bounds (500 listed files, 500 untracked ones, 2 MiB of text) are
  `ScanStepResult.notes` — the verdict's `coverage_notes`, never `missing_tools`.

Neither pass reads `.guardianignore`: `review_pr` and `scan_sast` hand their findings to the scan-tool factory, whose
result filter drops a path the file ignores; `ci/runScans.ts#declaredFilter` applies the same loader and rule to the
CLI's two diff steps (the `--rules-ref` copy's file when given). A suppressions-pass finding is keyed like a
credential (`fingerprint/findingIdentity.ts#keyedWithoutLine`: `suppression\n<rule id>`, the occurrence and the
group's count, never the line — a bare gitleaks allow line holds the secret).

The suppressions table (`ROWS`) is closed: each row is read the way its tool reads it (Semgrep anywhere on the line,
strings included; Bandit and gosec in comments only), and a line inside a multi-line literal is not read — the
lexer (`readLines`) carries a block comment, a string that runs on, a heredoc from line to line. Every row's match
holds one of its tokens, and `PICKAXE_ERE` (the tokens, `|`-joined: literals, bracket classes, `!?` — POSIX ERE and
V8 alike) is the one `git diff -G` listing, so a file whose diff holds no token is never diffed. A new row needs a
case in `test/fixtures/suppressions/examples.json` (bare and reasoned), a token its match always holds, and a
timing row (`suppressionsTiming.test.ts` loops over every row): a row's arguments grammar is the likeliest place
for a superlinear regex. The cases live under `test/fixtures/` because the pass never reads it: a test source that
held a bare `nosemgrep` in a string would be a real Semgrep suppression on dev-guardian's own branches. For the same
reason the table builds the two directives read on a whole line (gitleaks' allow, Semgrep's blank-led one) instead
of spelling them, and `suppressions.test.ts` holds every file of `mcp/src` to no token of those rows and no finding.
A tracked file git diffs as binary or `-diff` — the bundles in `mcp/dist/` (`.gitattributes`) — is never read: `git
diff -G` does not search it, so it is not listed, and no note says so; an untracked one is read from disk like any.

A row's scope says when a directive covers the whole file. Beyond `file`, the leading forms are certain by syntax
only before the file's first code: `leading` (mypy's `# type: ignore`), `leading-only` (`@ts-nocheck`),
`leading-bare` (own-line Pylint, RuboCop and ShellCheck forms naming no rule — their region runs on to the file's
end) and `package-bare` (a bare `//nolint` in the comment group directly above `package`, at its column, which
golangci-lint widens to the file: `packageDocOf`). Anywhere else, or naming its rules, such a form reads as its
line's. The line above a directive is no reason when it is the shebang or a line-1/2 coding or magic comment
(`MAGIC_COMMENTS`), and a byte-order mark is stripped from line 1 on both sides before the diff and the text are
compared (git's diff keeps it, `readProjectText` drops it).

## The metrics module

`mcp/src/metrics/` (3.17.0) is a leaf: no storage, no runner, no tool module imported. It reads the METRIC
lines of `metric-lines/1` (`metricLine.ts` — the contract is the fixture shared with dev-spec-driven,
[build-and-test.md](build-and-test.md)), judges them (`judge.ts`, exact decimals in `decimal.ts`), compares two
outputs and renders the `metrics` command's report (`compare.ts`; `metricFile.ts` is the one file read, a path
the operator named), and holds `perf_check`'s series rules (`perfSeries.ts`). `tools/perfCheck.ts` reads and
writes the `perf` rows (`scansRepo.listCompletedPerfSeries`, one statement per series); `src/cli.ts` re-exports
what the CLI uses directly — it is light, so `metrics` loads no `load*Modules()`. A `perf` row is `'never'`
(`history/scanRoles.ts`): it reports through `meta`, and as `'state'` it would be `latestStateScan`'s default.
`guardian://scans/history` leaves `perf` rows out (`scansRepo.listScanHistory`, in SQL, so its 50 are the other scans),
and `set_baseline` refuses a `'never'` type by `scan_id` and by `scan_type` alike. A run's samples come from its report:
CLS unrounded (its 0.01 tolerance is the summary's rounding step); the k6 series from its inputs only: the script, its
content and a digest of the `K6_*` settings perf_check hands k6, never a VU count k6 measured (k6 samples `vus_max`
from the start of the VUs' init, so its minimum jitters). What the key leaves out: the modules the script imports,
k6's own config file and the other variables k6 is handed (`CI`, `LANG`, the proxy), which a script can read through
`__ENV` to set its load; a `K6_*` setting that names a per-run file makes every run a new series. A label shows a
query, and the `K6_*` settings, as six hex digits of a digest (`?…#ab12cd`).

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
for what a scanner reads use `SCANNED_WALK_EXCLUDE`, and the two walks that
check what Trivy read (its manifests, its IaC-looking files) use
`trivyWalkSkipsDir` — build output left out at the root only, since Trivy
reads a `build/` at any depth (3.6.1). A Semgrep `--exclude`
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
