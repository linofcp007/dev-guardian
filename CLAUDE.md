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
enumeration and removal, and the report's coverage arithmetic — *is*
unit-tested, in [`mcp/test/ablate/clauses.test.ts`](mcp/test/ablate/clauses.test.ts)
and [`mcp/test/ablate/report.test.ts`](mcp/test/ablate/report.test.ts).

**What it is for.** Six exclusion clauses that did nothing at all have shipped
across the rule-pack series. Every one was written by someone sure it was
needed, and found only when somebody deleted it and watched nothing change.
The harness deletes one clause at a time, re-runs the pack, and reports three
verdicts — all three, because each axis was added after a defect escaped the
previous ones. A fourth, **axis 0**, is a property of the *rule* rather than of
a clause, and is the only one that reaches a rule with no clauses at all:

0. **fires on `hits/`** — the rule produces at least one baseline finding in
   the fixture directory built to hold the bugs it is for. A rule that matches
   nothing is the sixth silent-failure mode: in C#, `foreach ($T $X in $C)`
   found **0 of 5** real bugs where `foreach (var $X in $C)` found all five,
   with `paths.scanned` healthy, zero errors and every gate green. A rule
   ported by textual analogy finds nothing and nothing complains. It costs no
   extra scan — the baseline fixture scan is already there — and it applies to
   every rule in the pack, not only the clauseless ones.
1. **live** — removing the clause changes the result somewhere.
2. **keeps true positives** — removing it must not *reveal* findings in
   `hits/`. `pattern-not-inside` excludes the whole node it matched, so a
   guard written for an `if` also swallowed the `else` arm, where the bug was.
3. **no rise in the real-code count** — scan a corpus nobody wrote as a
   fixture (`mcp/src`, for the JS/TS pack) and compare. If removing the clause
   *lowers* the count, the clause was adding those findings. This is the axis
   that caught `unchecked-match` going 0 → 13 false positives on our own
   TypeScript; axes 1 and 2 both passed, because "live" and "keeps true
   positives" are both true of a clause that only *adds* false positives.

**Read the coverage line, not the axis fractions.** Axes 1–3 are properties of
a **clause**, so a rule with no ablatable clause has no verdict on any of them.
Two shapes have none: a bare `pattern:` (or `pattern-regex:`) with no
`patterns:` group and no `pattern-either:`, and a `patterns:` group holding
nothing but positive terms. **30 of the 136 rules** across the nine packs are
one of those — 24 bare and 6 positive-only — and they used to appear
**nowhere** in the report: not in the clause list, not under `skipped`. So
`52/52 live, 0 DEAD` read as "the pack was checked" when it covered 11 rules of
12. The capability was never missing — there is genuinely nothing to ablate.
The *reporting* was dishonest, in exactly the way axis 3 refuses to be when it
prints `N/A`.

| pack | rules | with ablatable clauses | with none |
| --- | --- | --- | --- |
| `bugfix-js` | 13 | 12 | 1 |
| `bugfix-py` | 10 | 10 | 0 |
| `bugfix-go` | 9 | 8 | 1 |
| `bugfix-java` | 8 | 7 | 1 |
| `bugfix-cs` | 12 | 11 | 1 |
| `bugfix-php` | 6 | 6 | 0 |
| `bugfix-rs` | 1 | 1 | 0 |
| `base` | 13 | 7 | 6 |
| `routes` | 64 | 44 | 20 |

The report therefore leads with a coverage line naming both halves —
`52 clause(s) across 11 of 12 rules; 1 rule(s) have no ablatable clauses (axis
0 only)` — lists **every** rule under `RULE COVERAGE` with its clause count and
its `hits/` count, and names each clauseless rule with the reason it has none.
`npm run ablate -- <pack> --list` does the same without scanning.

**`DEAD` never means "safe to delete" on its own.** Three different situations
produce it, and they have different fixes:

- the clause really is inert — six of those have shipped here;
- the clause works, but the **fixture that would prove it** does not exist. All
  four `bugfix-js` DEAD verdicts from the first run were this: probed by hand,
  each one did exactly its job on a shape no fixture carried. The fix is a
  fixture, not a deletion, and the same call was made for nine Java clauses;
- the clause is **mutually redundant with a sibling** in the same rule. Each
  half alone reads DEAD; removing both is a regression. `type-assert-no-ok`
  and `err-discarded` have both shipped that pair. The harness re-ablates
  same-rule DEAD clauses **in pairs** and reports `MOVES` when it finds one,
  but it only pairs clauses that were already DEAD, so a redundant pair whose
  halves are individually live is still invisible.

Probe the shape by hand before deleting anything.

Axes 2 and 3 are attributions, not proofs, and both flag more than the defect
they were built for. Axis 2 fires whenever a `hits/` fixture deliberately
carries the excluded near-miss beside the bug — the `real_bugs` files do, and
annotate it. Axis 3 fires for any clause whose removal makes the rule match
less, which includes a *working* positive branch. Read the lines it prints.

Axis 3 needs a real-code corpus in a language the pack matches, so it is a
property of the invocation — registered per pack in
[`mcp/test/ablate/packs.ts`](mcp/test/ablate/packs.ts), overridable with
`--real-code=<dir>` / `--no-real-code`, and reported as `N/A` (never silently
skipped) where none exists. Axis 0 needs a `hits/` corpus on the same terms and
reports `N/A` for the whole pack where the fixture root has no `hits/`
subdirectory.

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
  error strings does not cover the set. The **sixth** mode is not one of these
  and this gate cannot see it: the rule loads, `paths.scanned` is healthy,
  `errors` is empty, and the rule simply matches nothing. Only axis 0 catches
  that one.
- **A round-trip control runs first.** Removal goes through the YAML AST, so
  the unmodified pack is re-serialised and scanned before anything is ablated;
  if it does not reproduce the on-disk result exactly, the run aborts rather
  than measure the serialiser.

Exit code is 1 when any clause is flagged **or any rule fires on nothing in
`hits/`**, 0 when every clause passes axes 1–3 and every rule passes axis 0.
Having no ablatable clauses is reported, never counted against a pack: it is a
fact about the rule, not a defect in it.

`routes.yml` is unregistered: it has no `hits/` + `misses/` fixture pair, so
axes 0, 1 and 2 all have nothing to measure against. Twenty of its 64 rules
have no ablatable clause, so registering it would need fixtures before the
report said anything about two thirds of the pack.

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

  **Rule comments are Portuguese too**, not just the messages — measured, not
  asserted: six of the seven `bugfix-*` packs are roughly half Portuguese by
  comment line, and the outlier is `bugfix-js`, the first one written. Two
  independent implementers overruled a plan of mine that said otherwise, and
  both were right. Write comments in Portuguese and keep docs, commits and
  identifiers in English.

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
