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
  gitignored globally *except* `mcp/dist/` (see [`.gitignore`](../../.gitignore)).
- **Rebuild before committing TS changes.** A stale `dist/` silently desyncs from
  `src/`. Run `npm run build` and stage `mcp/dist/` in the *same* commit.
  `test/unit/pluginSurface/distSync.test.ts` fails when the committed `dist/`
  is not, byte for byte, what the build makes of `src/` (tsc, the bundles,
  copy-assets — and nothing stale).
- **The CLI runs on its bundle, never on tsc's per-file output.** A plugin
  install is a checkout with no `node_modules`, and `dist/<area>/*.js` imports
  the npm packages by name: 3.2.0's `scan` and `status` failed in every install
  with `Cannot find package 'yaml'` while every test passed. So
  `cli/dev-guardian.mjs` imports Node builtins and `mcp/dist/cli.js` — the
  esbuild bundle of `mcp/src/cli.ts`, built beside `dist/server.js` with the
  same options — and nothing else (`test/e2e/cliLazyStorage.test.ts`). What the
  CLI needs from `src/` is exported from `src/cli.ts`: re-exported when it is
  light, through one of its lazy `load*Modules()` when it reaches the storage
  layer or the scan pipeline. `test/e2e/pluginInstall.test.ts` runs the CLI's
  subcommands, the hooks and the server from a copy of the files git tracks —
  so `git add` a new file the install needs (a build output too) before it
  passes, as it must be committed to ship.
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
