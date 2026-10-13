# Architecture — what the repository is

> Maintainer notes, moved from `CLAUDE.md` (the index). Not loaded into sessions: read this file before you
> change its area.

## What this repo is

An all-in-one, 100% open-source Claude Code / Cowork plugin for security, bugfix,
quality, deps, observability, performance and compliance. Two halves:

- **Plugin front-end** — `skills/` (13 skills) + `commands/` (10 slash commands),
  declared in [`.claude-plugin/plugin.json`](../../.claude-plugin/plugin.json).
- **MCP server** — `mcp/` (TypeScript on `node:sqlite`), the real engine: 63 tools,
  18 resources, registered by the import list in `mcp/src/registerAll.ts`. Built
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
  its own bundle, `mcp/dist/hooks.js` (`src/hooksEntry.ts`). Every file a hook reads from
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
