# CLAUDE.md — working in the dev-guardian repo

Guidance for AI assistants (and humans) **contributing to dev-guardian itself**.
For *using* the tools in another project, see [`host-rules/AGENTS.md`](host-rules/AGENTS.md).

## What this repo is

An all-in-one, 100% open-source Claude Code / Cowork plugin for security, bugfix,
quality, deps, observability, performance and compliance. Two halves:

- **Plugin front-end** — `skills/` (13 skills) + `commands/` (slash commands),
  declared in [`.claude-plugin/plugin.json`](.claude-plugin/plugin.json).
- **MCP server** — `mcp/` (TypeScript + SQLite), the real engine: 51 tools,
  16 resources. Built to `mcp/dist/`.
- **Guardrail hooks** — `hooks/hooks.json` (auto-discovered at the plugin root)
  with the `hooks/guardian-hook.mjs` dispatcher. Dependency-free and fail-open: SessionStart
  posture briefing, PostToolUse secret warning, PreToolUse catastrophic-Bash
  block. Detection lives in `mcp/src/hooks/{secretScan,bashGuard}.ts` (pure,
  unit-tested) and is shared with the `dev-guardian check` CLI subcommand.

## Build & test (always from `mcp/`)

```bash
cd mcp
npm install          # first time only (native better-sqlite3)
npm run build        # tsc -> mcp/dist + copy-assets
npm test             # vitest run (full suite)
```

## Conventions that bite if ignored

- **Commit the compiled `mcp/dist/`.** The repo *is* the distribution — Claude
  Code runs `mcp/dist/server.js` directly, with no install-time build. `dist/` is
  gitignored globally *except* `mcp/dist/` (see [`.gitignore`](.gitignore)).
- **Rebuild before committing TS changes.** A stale `dist/` silently desyncs from
  `src/`. Run `npm run build` and stage `mcp/dist/` in the *same* commit.
- **Markdownlint stays clean** for `skills/`, `commands/` and `README.md`
  (config: [`.markdownlint.jsonc`](.markdownlint.jsonc)).
- **Releases** bump the version in
  [`.claude-plugin/plugin.json`](.claude-plugin/plugin.json),
  [`.claude-plugin/marketplace.json`](.claude-plugin/marketplace.json) and
  [`mcp/package.json`](mcp/package.json) (keep all three in lock-step — the MCP
  server reports the `plugin.json` version at runtime), add a `CHANGELOG.md`
  entry, and tag `vX.Y.Z`.

## In-repo AI host configs (dogfooding)

This repo ships its own host configs so opening it in any AI host wires up the
dev-guardian MCP server out of the box: `.mcp.json` (Claude Code), `.cursor/`,
`.gemini/`, `.vscode/`, `.windsurf/`, `.github/copilot-instructions.md`, plus root
`AGENTS.md` / `GEMINI.md`. They use **relative** paths (`mcp/dist/server.js`), so
run `npm run build` once first. To install the same into *another* project, use the
`mcp-config` CLI (`node cli/dev-guardian.mjs mcp-config <host> --write`) — it fills in absolute paths.

**Never put the CLI back in a top-level `bin/`.** Claude Desktop / claude.ai does not clone the repo:
it validates it on a remote Anthropic service that *rejects* any plugin shipping a top-level `bin/`
(those files land on PATH in the CLI but are invisible on the admin approval surface). The sync fails
with `status=failed_content` and the UI shows only "Marketplace sync failed. Check the repository
URL", which points nowhere near the cause. The local CLI (`/plugin marketplace add`) uses `git clone`
and does **not** apply this rule, so it passes even when Desktop refuses — it is not a valid pre-check.
Executable entry points belong in `hooks/`, `commands/` or `mcpServers`.

## Prefer MCP tools over raw scanners

When working here, invoke the dev-guardian MCP tools rather than shelling out to
Semgrep / Trivy / gitleaks directly — you keep baselines, diffing and the
SQLite-persisted history. The full intent → tool map lives in
[`host-rules/AGENTS.md`](host-rules/AGENTS.md).
