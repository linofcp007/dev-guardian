# Contributing to dev-guardian

Thanks for helping. This is a Claude Code / Cowork plugin plus an MCP server;
[CLAUDE.md](CLAUDE.md) is the orientation, and holds the conventions in full.

## Build & test

Node.js ≥ 22.13. All work happens from `mcp/`:

```bash
cd mcp
npm ci               # reproducible install — no native modules, storage is node:sqlite
npm run lint         # tsc over src/ and test/ (two tsconfigs)
npm run build        # tsc -> mcp/dist, copy SQL migrations, regenerate host rules,
                     # esbuild bundle (dist/server.js), regenerate docs/tools.md and docs/rule-packs.md
npm test             # vitest run (full suite)
```

On Windows, run the full suite from Git Bash: from PowerShell, `bash` can be the
WSL launcher stub. `GUARDIAN_REQUIRE_SEMGREP=1` turns a missing Semgrep from a
skip into a failure.

Markdown is linted with markdownlint (config: [.markdownlint.jsonc](.markdownlint.jsonc)):

```bash
npx --yes markdownlint-cli2 "skills/**/*.md" "commands/**/*.md" "README*.md" "docs/**/*.md"
```

## Non-negotiables

- **Commit the compiled `mcp/dist/`.** The repo *is* the distribution — Claude
  Code runs `mcp/dist/server.js` directly, no install-time build. Rebuild
  (`npm run build`) and stage `mcp/dist/` in the **same** commit as the `src/`
  change — a comment-only change too, since comments reach the sourcemaps.
  There is no CI to catch drift, so it is on you to verify before committing.
- **Generated files are regenerated, never edited**: `host-rules/*`, the in-repo
  rules copies (root `AGENTS.md`, `GEMINI.md`, `.cursor/rules/`, `.windsurf/rules/`,
  `.github/copilot-instructions.md`), `docs/tools.md` and `docs/rule-packs.md`.
  Drift tests fail on a hand edit.
- **Counts in the docs are tested.** The READMEs, CLAUDE.md and `mcp/README.md`
  state tool, resource, skill and command counts; `mcp/test/docs/docs.test.ts`
  holds each one to the code.
- **Tests stay green** (`npm test`), **`npm run lint` passes**, and
  **markdownlint stays clean**.
- **The MCP tool surface is snapshotted.** Adding or removing a tool or resource
  means importing it in `mcp/src/registerAll.ts` and updating
  `mcp/test/integration/toolSurface.test.ts` — an intentional change, reviewed as
  such. Tool descriptions stay under 1500 characters and skill descriptions
  under 1024 (`descriptionLimits.test.ts`).
- **No GitHub Actions, no npm publish, no top-level `bin/`** in this repository.
  Hooks stay dependency-free and fail open.

## Commit style

Conventional Commits: `feat(scope): …`, `fix(scope): …`, `chore(release): …`,
`docs: …`, `test: …`. Breaking changes carry a `BREAKING CHANGE:` footer.

## Releases

1. Bump the version in all three: [`.claude-plugin/plugin.json`](.claude-plugin/plugin.json),
   [`.claude-plugin/marketplace.json`](.claude-plugin/marketplace.json) and
   [`mcp/package.json`](mcp/package.json). The server reports the `plugin.json`
   version at runtime.
2. Turn `Unreleased` in [CHANGELOG.md](CHANGELOG.md) into the release section, and
   point the clone instructions in the three READMEs and `docs/hosts.md` at the new
   tag (`git clone … --branch vX.Y.Z`; they clone the default branch until the first
   release after 2.0.0).
3. Tag `vX.Y.Z` and create a GitHub release. `dev-guardian ci-init` pins that tag
   by commit SHA, so do not move a tag once published.

## Listing on MCP directories (GitHub-indexed)

We do **not** publish to npm. Distribution is the git-based Claude Code
marketplace, so the MCP directories that index public GitHub repos are the way
to get extra reach — no packaging required, they install from source.

- **Glama** — [`glama.json`](glama.json) (root) declares the `maintainers`
  (GitHub usernames). After it's on the default branch, claim the listing at
  <https://glama.ai/mcp/servers> ("Add server" → point at the repo → the
  `glama.json` proves ownership). Claiming unlocks editing the name/description
  and optionally configuring a Docker image later.
- **PulseMCP** — submit the repo at <https://www.pulsemcp.com/submit>. It reads
  the README's MCP section for install details.
- **mcp.so** — submit at <https://mcp.so/submit>. Same: it crawls the repo +
  README.

Keep the README's MCP and install sections current — these crawlers parse them.
To list on a **1-command-install** registry instead (official MCP Registry,
Smithery), you'd first need an npm package or an OCI image; that's a separate
decision, intentionally not done here.

## Adding a scanner / tool

- Put pure parsing in `mcp/src/runners/scannerParsers/` with a unit test.
- Build the tool in `mcp/src/tools/` (scan tools through `makeScanTool` in
  `scanToolFactory.ts`) and import it in `mcp/src/registerAll.ts`.
- Degrade honestly when the scanner is absent: `skipped` with a reason and a
  `missing_tools` entry, coverage `partial` or `none` — never a crash and never
  "0 findings". Place every name it writes to `tools_run` / `missing_tools` in
  `mcp/src/history/runNames.ts`.
- Add an integration test; if it needs a real scanner, gate it like the e2e
  fixtures so the suite still passes without the binary.
- Add the scanner to `mcp/src/runners/installCatalog.ts` if `install_toolchain`
  should offer it.
