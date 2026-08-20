# CLAUDE.md — working in the dev-guardian repo

Guidance for AI assistants (and humans) **contributing to dev-guardian itself**.
For *using* the tools in another project, see [`host-rules/AGENTS.md`](host-rules/AGENTS.md).

## What this repo is

An all-in-one, 100% open-source Claude Code / Cowork plugin for security, bugfix,
quality, deps, observability, performance and compliance. Two halves:

- **Plugin front-end** — `skills/` (13 skills) + `commands/` (slash commands),
  declared in [`.claude-plugin/plugin.json`](.claude-plugin/plugin.json).
- **MCP server** — `mcp/` (TypeScript + SQLite), the real engine: 54 tools,
  18 resources. Built to `mcp/dist/`.
- **Guardrail hooks** — `hooks/hooks.json` (auto-discovered at the plugin root)
  with the `hooks/guardian-hook.mjs` dispatcher. Dependency-free and fail-open: SessionStart
  posture briefing, PostToolUse secret warning, PreToolUse catastrophic-Bash
  block. Detection lives in `mcp/src/hooks/{secretScan,bashGuard}.ts` (pure,
  unit-tested) and is shared with the `dev-guardian check` CLI subcommand.

## Build & test (always from `mcp/`)

```bash
cd mcp
npm install          # first time only — no native modules, storage is node:sqlite
npm run build        # tsc -> mcp/dist + copy-assets + esbuild bundle
npm test             # vitest run (full suite)
npm run test:coverage # the only run that enforces the coverage thresholds
```

Semgrep-dependent e2e tests skip when Semgrep is absent. A skip is visible as a
skip, and `GUARDIAN_REQUIRE_SEMGREP=1` turns absence into a hard failure — set it
when you need to know the rule pack was actually exercised.

## Ablating a Semgrep rule pack (`npm run ablate`)

```bash
cd mcp
npm run ablate -- all                          # every registered pack
npm run ablate -- bugfix-js                    # one pack
npm run ablate -- bugfix-java --filter=map-get # one rule, while iterating
npm run ablate -- bugfix-js --list             # enumerate clauses, no scanning
```

Semgrep is found via `--semgrep=<path>`, then `GUARDIAN_SEMGREP`, then `PATH`.
Code lives in [`mcp/test/ablate/`](mcp/test/ablate/) — under `test/` because
it is developer tooling that must never reach `dist/`, and because
`tsconfig.test.json` already type-checks that tree at full strictness. It is
**not** a vitest test (`vitest.config.ts` only collects `*.test.ts`): a full
run is tens of minutes, and the report is the product. Its pure half — clause
enumeration and removal — *is* unit-tested, in
[`mcp/test/ablate/clauses.test.ts`](mcp/test/ablate/clauses.test.ts).

**What it is for.** Six exclusion clauses that did nothing at all have shipped
across the rule-pack series. Every one was written by someone sure it was
needed, and found only when somebody deleted it and watched nothing change.
The harness deletes one clause at a time, re-runs the pack, and reports three
verdicts — all three, because each axis was added after a defect escaped the
previous ones:

1. **live** — removing the clause changes the result somewhere. A clause that
   changes nothing is dead: delete it, don't keep it "for symmetry".
2. **keeps true positives** — removing it must not *reveal* findings in
   `hits/`. `pattern-not-inside` excludes the whole node it matched, so a
   guard written for an `if` also swallowed the `else` arm, where the bug was.
3. **no added noise on real code** — scan a corpus nobody wrote as a fixture
   (`mcp/src`, for the JS/TS pack) and compare. If removing the clause *lowers*
   the count, the clause was adding those findings. This is the axis that
   caught `unchecked-match` going 0 → 13 false positives on our own
   TypeScript; axes 1 and 2 both passed, because "live" and "keeps true
   positives" are both true of a clause that only *adds* false positives.

Axis 3 needs a real-code corpus in a language the pack matches, so it is a
property of the invocation — registered per pack in
[`mcp/test/ablate/packs.ts`](mcp/test/ablate/packs.ts), overridable with
`--real-code=<dir>` / `--no-real-code`, and reported as `N/A` (never silently
skipped) where none exists.

**Invariants worth knowing before you change it.**

- **The pack is never written to.** The source is read once, hashed, and
  ablated variants go to a temp dir. That is what makes it byte-identical
  after a crash or a Ctrl-C, without a restore path that can itself fail. The
  on-disk hash is re-checked before every ablation, which also catches the
  pack being edited mid-run.
- **Clauses are named by body text, never by line number.** A previous
  hand-rolled run was discarded because a *comment* was edited while it ran:
  every line shifted, and since all 86 `- pattern-not-inside:` first lines in
  `bugfix-java.yml` are identical, the one INERT verdict could not be
  attributed to any clause.
- **`paths.scanned == 0` is an exception, not a result.** This repo has five
  recorded ways for Semgrep to scan nothing while printing success and exit 0;
  two of them emit neither `RuleParseError` nor `Invalid YAML`, so matching on
  error strings does not cover the set.
- **A round-trip control runs first.** Removal goes through the YAML AST, so
  the unmodified pack is re-serialised and scanned before anything is ablated;
  if it does not reproduce the on-disk result exactly, the run aborts rather
  than measure the serialiser.

Exit code is 1 when any clause is flagged, 0 when every clause passes.
`routes.yml` is unregistered: it has no `hits/` + `misses/` fixture pair, so
axes 1 and 2 have nothing to measure against.

## TypeScript conventions

Enforced by the compiler where possible, by review where not:

- **ESM `NodeNext`.** Every relative import ends in `.js`, including from
  `.ts` sources. `isolatedModules` is on, so `import type` is required for
  type-only imports.
- **`noUncheckedIndexedAccess` is on.** `arr[i]` is `T | undefined`. Narrow it
  (`const x = arr[i]; if (x === undefined) continue;`) rather than asserting.
- **No `!` non-null assertions, and no `any`.** Both are currently at zero
  across `mcp/src` and `mcp/test`, so any reappearance is a regression rather
  than the status quo. An assertion does not check anything — it only silences
  the compiler, and every one that was here restated something the code had
  *just* established (a `push` before re-indexing the array, a `filter` before
  a `map`, a length check before an index), which is exactly the case where
  narrowing costs nothing. The three that were load-bearing were hiding real
  gaps: a WP-CLI call that can succeed and print nothing, and a shell whose
  non-null-ness came from a check in a *different* file.
- **Type-check the tests too.** `npm run lint` runs `tsconfig.json` and
  `tsconfig.test.json`. The second exists because nothing ever type-checked
  `test/` — `tsconfig.json` excludes it and vitest's esbuild strips types
  without checking them. It excludes `test/fixtures`, which is deliberately
  broken sample code fed to scanners as input.
- Note what `tsc` does **not** catch: interpolating a non-string into a
  template (`` `--config=${someArray}` ``) types as `string` at any
  strictness. That needs `@typescript-eslint/restrict-template-expressions`,
  and this repo has no ESLint setup.

## Conventions that bite if ignored

- **Commit the compiled `mcp/dist/`.** The repo *is* the distribution — Claude
  Code runs `mcp/dist/server.js` directly, with no install-time build. `dist/` is
  gitignored globally *except* `mcp/dist/` (see [`.gitignore`](.gitignore)).
- **Rebuild before committing TS changes.** A stale `dist/` silently desyncs from
  `src/`. Run `npm run build` and stage `mcp/dist/` in the *same* commit.
- **Markdownlint stays clean** for `skills/`, `commands/` and `README.md`
  (config: [`.markdownlint.jsonc`](.markdownlint.jsonc)).
- **Two characters are banned from `configs/semgrep/*.yml`, messages and
  comments alike: `U+00C1` (A-acute) and `U+00CD` (I-acute)** — plus `U+00CF`,
  `U+00D0`, `U+00DD` for languages that use them. Semgrep loads a rule file with
  the **locale** codec, not UTF-8, and on a cp1252 locale the bytes `0x81`,
  `0x8D`, `0x8F`, `0x90`, `0x9D` are undefined; each of those characters encodes
  to one of them, so a single occurrence takes the whole pack down. Measured on
  a broken file: the scan returns `results: 0`, `paths.scanned: 0` **and
  `errors: 0`** — indistinguishable from a clean project. Rule messages in this
  repo are written in Portuguese, which is what makes this a live hazard.

  **Only those characters.** `Ã À Â É Ê Ó Ô Õ Ú Ç` are all fine and every
  lowercase accented letter is fine — the broad version of this rule ("no
  uppercase accented letters") is wrong for ten of the twelve accented capitals
  Portuguese uses, so write the accented word in lower case rather than
  mangling its spelling. Enforced for every pack by
  `mcp/test/integration/semgrepPacks.test.ts`, which also runs
  `semgrep --validate` over each one and carries a positive control.
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
