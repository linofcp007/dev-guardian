# CLAUDE.md — working in the dev-guardian repo

Guidance for AI assistants (and humans) **contributing to dev-guardian itself**. For *using* the tools in another
project, see [`host-rules/AGENTS.md`](host-rules/AGENTS.md).

**This file is the index.** It is loaded into every session in this repository, so it holds only the hard rules,
the layout in brief and a topic map. The full notes live in [`docs/maintainers/`](docs/maintainers/), one file per
area; they are NOT loaded automatically (never `@`-import them here). **Before changing an area, read its topic
file.**

## What this repo is

An all-in-one, 100% open-source Claude Code / Cowork plugin for security, bugfix, quality, deps, observability,
performance and compliance:

- **Plugin front-end** — `skills/` (13 skills: a `SKILL.md`, plus `references/` read on demand) and `commands/`
  (10 slash commands), declared in [`.claude-plugin/plugin.json`](.claude-plugin/plugin.json).
- **MCP server** — `mcp/` (TypeScript on `node:sqlite`; Node ≥ 22.13, never `--experimental-sqlite`): 52 tools
  and 18 resources, registered by `mcp/src/registerAll.ts`, built to `mcp/dist/engine.js` (`dist/server.js` starts it).
- **Guardrail hooks** — `hooks/hooks.json` (auto-discovered) and the `hooks/guardian-hook.mjs` dispatcher:
  dependency-free, fail-open; detection in `mcp/src/hooks/`, bundled to `mcp/dist/hooks.js`. User-facing detail:
  [`docs/hooks.md`](docs/hooks.md).
- **CLI** — `cli/dev-guardian.mjs`, running on the server's own bundle `mcp/dist/engine.js` (`scan`, `baseline
  update`, `status`, `dashboard`, `db adopt`, `mcp-config`, `ci-init`, …).
- **Plugin evals** — [`evals/`](evals/README.md), run with `claude plugin eval` (maintainer-side, local).

## Hard rules

- **Never ship a top-level `bin/`.** Claude Desktop / claude.ai validates the repository on a remote service that
  rejects a plugin with a top-level `bin/`; the sync fails with only "Marketplace sync failed. Check the repository
  URL". `/plugin marketplace add` (a `git clone`) does not apply the rule, so it is no pre-check. Executable entry
  points belong in `hooks/`, `commands/`, `cli/` or `mcpServers`.
- **Commit the compiled `mcp/dist/`, rebuilt in the same commit** as the `src/` change: the repository is the
  distribution (`distSync.test.ts` fails on a stale `dist/`).
- **`mcp/dist/` is two bundles and nothing per-file**: `engine.js` (server + CLI), `hooks.js` (the hooks' detectors,
  with its four per-event parts `hooksBash.js`, `hooksVet.js`, `hooksWrite.js`, `hooksSession.js`), the short
  `server.js` and the copied assets — no tsc output, no source maps (`distSync.test.ts`). The CLI imports Node builtins
  and `mcp/dist/engine.js` only, the dispatcher `mcp/dist/hooks.js` only (which loads its parts); `git add` a new
  file an install needs (`pluginInstall.test.ts`).
- **Generated files are never edited by hand**: `host-rules/*` and the in-repo rules copies (from
  `mcp/src/hostsetup/rulesTemplate.ts`), `docs/tools.md`, `docs/rule-packs.md`. `npm run build` writes them; drift
  tests fail otherwise.
- **Never `U+00C1` or `U+00CD` (nor `U+00CF`, `U+00D0`, `U+00DD`) in `configs/semgrep/*.yml`**, comments included:
  Semgrep reads a pack with the locale codec, and on cp1252 one such character makes the pack scan nothing with
  zero errors. Pack comments are in Portuguese.
- **Never `${CLAUDE_PROJECT_DIR}` in `.mcp.json`** — Claude Code does not expand it there.
- **Counts are tested**: every tool, resource, skill and command count in the READMEs, this file, `mcp/README.md`
  and `docs/` equals the code (`mcp/test/docs/docs.test.ts`) — fix the number in the same commit.
- **The prose has budgets**: skill descriptions ≤ 300 characters, the listing ≤ 4 000, `SKILL.md` ≤ 12 KB,
  `host-rules/AGENTS.md` ≤ 8 000 bytes, `tools/list` + instructions ≤ 72 000, a tool description ≤ 600 — see
  [`docs/maintainers/prose.md`](docs/maintainers/prose.md).
- **Three READMEs** — `README.md`, `README.pt-PT.md` (European Portuguese), `README.es.md` — changed together.
- When working here, use the dev-guardian MCP tools rather than Semgrep / Trivy / gitleaks directly.

## Build & test (always from `mcp/`; on Windows, from Git Bash)

```bash
npm ci                # first time only — no native modules
npm run lint          # tsc over src/ AND test/ (one pass)
npm run build         # type-check, esbuild bundles -> dist, copy-assets, host-rules, docs
npm test              # vitest (full suite) — the gate before a commit
npm run test:fast     # unit tests minus the slowest files — the inner loop
npm run test:docker   # Linux containers: Node 22.13 floor (coverage enforced) + LTS — before a release
npm run ablate -- <pack>   # rule-pack ablation harness (not a vitest test)
```

## Topic map (`docs/maintainers/`)

Read the file BEFORE you change its area:

- [`architecture.md`](docs/maintainers/architecture.md) — the plugin's halves in full, the hooks' fail-open and
  file-reading rules (`configFile.ts`).
- [`build-and-test.md`](docs/maintainers/build-and-test.md) — the build's generated files, the Semgrep-dependent
  e2e tests and their `GUARDIAN_REQUIRE_*` switches, timing tests, containers.
- [`conventions.md`](docs/maintainers/conventions.md) — TypeScript conventions (no `!`, no `any`, NodeNext), the
  dist / bundle rules in full, markdownlint, the cp1252 pack rule, releases.
- [`ablation.md`](docs/maintainers/ablation.md) — `npm run ablate`: the axes, the coverage line, `DEAD`, the
  per-pack corpora, the routes pack; its rule-pack table is held to the packs by `docs.test.ts`.
- [`prose.md`](docs/maintainers/prose.md) — skills, references, commands, descriptions and their budgets, the
  dev-spec-driven routing, the version-history guard, the plugin-eval suite.
- [`hosts-and-dogfood.md`](docs/maintainers/hosts-and-dogfood.md) — the in-repo host configs, the rules template
  (safety first, ≤ 8 000 bytes, agent-requested in Cursor / Windsurf).
- [`history.md`](docs/maintainers/history.md) — where the removed design documents are in git.
