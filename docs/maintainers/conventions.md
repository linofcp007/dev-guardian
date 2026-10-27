# Conventions

> Maintainer notes, moved from `CLAUDE.md` (the index). Not loaded into sessions: read this file before you
> change its area.

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
- **Type-check the tests too.** `npm run lint` runs `tsconfig.test.json`,
  which covers `src/` and `test/` in one pass (`npm run build` type-checks
  `src/` alone, through `tsconfig.json`). It exists because nothing ever
  type-checked `test/` — `tsconfig.json` excludes it and vitest's esbuild
  strips types without checking them. It excludes `test/fixtures`, which is
  deliberately broken sample code fed to scanners as input.
- **Type-check the JavaScript too** (3.4.0). `npm run lint` then runs
  `tsconfig.js.json` (`allowJs` + `checkJs`, the same strictness) over
  `cli/dev-guardian.mjs`, `hooks/guardian-hook.mjs` and `mcp/scripts/*.mjs`,
  typed with JSDoc (`@param`, `@typedef`, `@type` casts). The bundles they
  import are typed by their sources: `npm run build` writes
  `dist/engine.d.ts` and `dist/hooks.d.ts`, one `export *` each of
  `src/engine.ts` / `src/hooksEntry.ts` (`bundleOptions.mjs#DECLARATIONS`,
  held by `distSync.test.ts`), so the checker stops at the bundle boundary and
  a call the engine would not accept fails the lint. No checked file may say
  `@ts-nocheck` (`jsTypeCheck.test.ts`). Turning it on found three real bugs —
  the hooks merged the settings files without looking at their types (a
  string `"ignorePaths"` threw on every write, and the secret warning was
  lost), `mcp-config --scope <anything else>` silently meant `project`, and
  `scan` read a falsy value thrown by the pipeline as "no error" — and a
  Docker script that would have downloaded from a URL holding `undefined`.
- **No export that nothing imports.** `noUnusedLocals` cannot see an export,
  so `npm run lint` also runs `scripts/unusedExports.mjs`: an export of
  `src/` no other module of `src/` or `test/` imports, re-exports or reaches
  through `import *` / `import()` fails it (the bundle entries `engine.ts`,
  `cli.ts`, `hooksEntry.ts` and `server.ts` excepted). Use it, un-export it,
  or delete it. `scripts/unusedExports.baseline.json` is a ratchet: the
  entries left when the check began (the tool modules' and `schemas.ts`',
  whose surface was being reworked) — an entry that is imported again, or
  gone, must leave it too (review 8, finding 15: 438 such exports, 9 of them
  dead code; `schemas.ts`' eight went in review 10).
- **A tool's input is typed by its schema, never cast.** A tool module is
  `defineTool({ inputSchema, handler })` (`tools/index.ts`): the handler
  takes `ToolInput<typeof inputSchema>` — the schema's parse, defaults
  applied. A scan tool's `makeScanTool` callbacks (`invoke`, `rulePacks`,
  `cacheState`, …) are typed the same way from its `inputSchema`. The one
  cast from the registry's `Record<string, unknown>` is inside those two
  helpers: the SDK and a fold hand a handler the strict parse of exactly that
  schema (dg-maint finding 12 found 51 hand-written `input as {…}` casts).
  The LLM scan's three tools also parse their input again in the handler
  (a step's own refusal is `invalid_input`); `check_toolchain` takes none.
- **A tool's `project_path` is `toolProjectPath(inp.project_path)`**
  (`tools/projectArg.ts`): the resolved path, or the `{ ok: false, error }`
  refusal (`projectPathErrorCode`'s code) a handler returns as it is — not a
  `resolveProjectPath` try / catch per tool (dg-maint finding 14). A tool that
  answers an unusable path otherwise keeps its own: the WordPress install
  audits (`not_a_wordpress_install`), the wrappers that let the scan pipeline
  report it (`review_pr`, `scan_secrets`, `scan_containers`), and the two
  agent-config audits, which rethrow anything but an invalid path.
- Note what `tsc` does **not** catch: interpolating a non-string into a
  template (`` `--config=${someArray}` ``) types as `string` at any
  strictness. That needs `@typescript-eslint/restrict-template-expressions`,
  and this repo has no ESLint setup.

## Conventions that bite if ignored

- **Text a tool hands a program is validated where it enters, and a batch file
  never gets an argument `cmd.exe` can misread** (review 10, finding 3,
  "BatBadBut"). On Windows WP-CLI, WPScan, Lighthouse, npm, composer and
  bundle are `.bat` / `.cmd` files, which `cmd.exe` parses twice; a `"` before
  an `&` in a slug or a URL ran a second command. `runners/spawn.ts` refuses,
  for every caller, an argument with `"`, `%`, CR, LF or NUL — or ending in
  two or more backslashes, which cross-spawn escapes wrong (3.4.0) — when the
  command runs through `cmd.exe` (`notRun.code: 'batch_argument_refused'`); a tool
  parses a URL and hands over its `href` (`platform/toolArgs.ts#httpUrl`,
  `schemas.ts#httpUrlField`), takes a slug or a token by its alphabet, refuses
  a `"` in a path, and passes a body (`gh … --body-file`, `runners/argFile.ts`)
  in a file, never on the command line — and its own fixed arguments hold no
  `"` either (`create_github_issues` searched with `'"[guardian:" in:title'`,
  so through a `gh.cmd` it could not run at all, review 11). An npm cmd-shim
  (`lighthouse.cmd`, the two templates npm's `cmd-shim` writes, Node only) is
  not a batch file to judge: `runners/npmCmdShim.ts` runs the Node script it
  names directly, every argument literal — a percent-escaped URL reached
  Lighthouse only that way. A new tool that passes user or
  repository text to a program does the same, with a test that puts the `"`
  BEFORE the `&` (`test/integration/batchArgumentTools.test.ts`).
- **Every path-shaped tool argument is held to the `project_path` rule for
  the network** (3.4.0, review 11): `platform/projectPath.ts#networkPathOf`
  — a UNC spelling, `//host`, `\\?\UNC\…` or a local spelling a link leads to
  a share — refused before any file call, which on Windows authenticates to
  the host the path names. `toolProjectPath` applies it; `wp_install_path`,
  `scan_skill`'s `target` and `map_attack_surface`'s `spec_paths` call it.
- **Commit the compiled `mcp/dist/`.** The repo *is* the distribution — Claude
  Code runs `mcp/dist/server.js` directly, with no install-time build. `dist/` is
  gitignored globally *except* `mcp/dist/` (see [`.gitignore`](../../.gitignore)).
- **Rebuild before committing TS changes.** A stale `dist/` silently desyncs from
  `src/`. Run `npm run build` and stage `mcp/dist/` in the *same* commit.
  `test/unit/pluginSurface/distSync.test.ts` fails when the committed `dist/`
  is not, byte for byte, what the build makes of `src/` (the bundles, the
  server's entry, copy-assets — and nothing else). The build layout
  is in [build-and-test.md](build-and-test.md).
- **Everything runs on a bundle; nothing ships per-file.** A plugin install is
  a checkout with no `node_modules`, and tsc's per-file output imports the npm
  packages by name: 3.2.0's `scan` and `status` failed in every install with
  `Cannot find package 'yaml'` while every test passed. Since 3.3.0 the build
  emits no per-file output at all. `cli/dev-guardian.mjs` imports Node
  builtins and `mcp/dist/engine.js` — the esbuild bundle of `mcp/src/engine.ts`,
  which re-exports `src/cli.ts` and starts the server — and nothing else
  (`test/e2e/cliLazyStorage.test.ts`). What the CLI needs from `src/` is
  exported from `src/cli.ts`: re-exported when it is light, through one of its
  lazy `load*Modules()` when it reaches the storage layer or the scan
  pipeline. The hook dispatcher loads `mcp/dist/hooks.js` (`src/hooksEntry.ts`)
  and nothing else from the build — that entry loads its per-event parts: a
  detector it needs is a new `load*` there, its module re-exported by the
  part of the event that runs it (`src/hooksBash.ts`, …). `test/e2e/pluginInstall.test.ts` runs the CLI's
  subcommands, the hooks and the server from a real `git archive` of the
  index's tree (every tracked file at its working-tree content; a copy of the
  index, never the index) extracted at a path with a space — so `git add` a
  new file the install needs (a build output too) before it passes, as it
  must be committed to ship. The hooks run exactly as `hooks/hooks.json`
  declares them (exec form, `${CLAUDE_PLUGIN_ROOT}` the install), a damaged
  `mcp/dist` beside it is the negative control, and outside a git checkout
  the suite is skipped (3.4.0, review 11).
- **Markdownlint stays clean** for `skills/`, `commands/`, the three READMEs
  and `docs/` (config: [`.markdownlint.jsonc`](../../.markdownlint.jsonc)):
  `npx --yes markdownlint-cli2 "skills/**/*.md" "commands/**/*.md" "README*.md" "docs/**/*.md"`.
- **The READMEs come in three languages** — `README.md` (English),
  `README.pt-PT.md` (European Portuguese: "ficheiro", "utilizador", never the
  Brazilian forms) and `README.es.md` — each about 300 lines at most, linking
  to the others. Change all three together; the count test reads each.
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
- **Releases** update the clone instructions — `git clone … --branch vX.Y.Z` in
  the three READMEs and `docs/hosts.md` — to the new tag (they clone the default
  branch until the first release after 2.0.0), and bump the version in
  [`.claude-plugin/plugin.json`](../../.claude-plugin/plugin.json),
  [`.claude-plugin/marketplace.json`](../../.claude-plugin/marketplace.json) and
  [`mcp/package.json`](../../mcp/package.json) (keep all three in lock-step — the MCP
  server reports the `plugin.json` version at runtime), add a `CHANGELOG.md`
  entry, and tag `vX.Y.Z`.
- **Pinned versions** — every scanner and action dev-guardian pins (`configs/ci/pinned.json`,
  `PINNED_RELEASES` and the other pins in `mcp/src/runners/installCatalog.ts`) — are checked against
  upstream with `npm run pins` (network; `GH_TOKEN` lifts GitHub's rate limit): exit 1 names each one
  behind, with the sha256 GitHub records for the newer assets as a starting point. Never bump on that
  alone: hash the download yourself, match the release's own checksums and its signature where it has
  one, and record how beside the pin. A PyPI release with no upstream tag (Semgrep 1.182.1) is not
  taken as the latest. The CI templates install bandit, Semgrep and zizmor, with every dependency,
  from `configs/ci/python/requirements-<X.Y>.txt` (3.7.0): bump one of them in `pinned.json` and
  `configs/ci/python/requirements.in` together, then recompile every lock with the `uv pip compile`
  command in its header, from the repository root (`pinnedCiData.test.ts` fails until the locks
  agree; `npm run pins` reports a stale lock, a yanked locked release, and newer dependencies).
