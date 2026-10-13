# Build and test

> Maintainer notes, moved from `CLAUDE.md` (the index). Not loaded into sessions: read this file before you
> change its area.

## Build & test (always from `mcp/`)

```bash
cd mcp
npm ci               # first time only — Node >= 22.13; no native modules, storage is node:sqlite
npm run lint         # tsc over src/ AND test/ (tsconfig.test.json, which includes src/)
npm run build        # tsc type-check, esbuild bundles -> mcp/dist, copy-assets, host-rules, docs
npm test             # vitest run (full suite)
npm run test:coverage # the only run that enforces the coverage thresholds
```

What `npm run build` writes to `mcp/dist/` (review 8, findings 2 and 3), all
of it committed:

- `engine.js` — the esbuild bundle of `src/engine.ts`: the MCP server and
  everything the CLI uses (`src/cli.ts`), every npm package inlined. The server
  and the CLI shared 98.8% of their code as two 3.7 MB bundles; one bundle
  cannot ship them from different builds.
- `server.js` — two lines that import `engine.js` and call `startServer()`
  (`SERVER_JS` in `scripts/bundleOptions.mjs`), at the path `plugin.json` and
  every host configuration name.
- `hooks.js` — the bundle of `src/hooksEntry.ts`: the detectors the hook
  dispatcher loads, each behind a lazy `load*` loader, so an event evaluates
  only its own (the hook runs on every tool call). Its inputs are this repo's
  sources only — no npm package, no storage layer (`hooksDistImports.test.ts`).
- `storage/migrations/*.sql` and `hostsetup/legacyRulesTemplates/*` —
  `copy-assets.mjs`, one level below the bundles, where their probes look.

Nothing else: `tsconfig.json` is `noEmit` (tsc only type-checks), no source
map ships, and `scripts/bundle.mjs` empties `dist/` before it writes — 743
files / 17 MB before 3.3.0, 22 files / 4.5 MB since. Code that finds a file
relative to `import.meta.url` (`platform/scriptsDir.ts`, `configsDir.ts`,
`version.ts`, the migrations runner, `hostsetup/setup.ts`) still probes two
depths: a bundle in `dist/`, or its own file in `src/` under tsx and vitest.
esbuild keeps a `//` comment inside a function body, so even a comment can
change a bundle: rebuild after every `src/` change, and let
`distSync.test.ts` say whether it mattered. `.gitattributes` marks
`mcp/dist/**` generated, with no text diff.

`npm run build` ends by regenerating the committed, generated files: every
`host-rules/*` template and the in-repo rules copies (from
`mcp/src/hostsetup/rulesTemplate.ts`), then `docs/tools.md` and
`docs/rule-packs.md` (`npm run docs`, i.e. `tsx test/docs/generate.ts`, from the
registry and the pack files). Drift tests fail when a committed copy differs, and
`mcp/test/docs/docs.test.ts` also holds every tool, resource, skill and command
count in the READMEs, this file and `mcp/README.md` — and the pack table below —
to the code. The fix for any of those failures is `npm run build` or correcting
the number, never editing a generated file.

On Windows, run the full suite from **Git Bash**. From PowerShell, `bash` can
resolve to the WSL launcher stub, and the `ci-init` e2e fails for that reason
alone.

Semgrep-dependent e2e tests skip when Semgrep is absent. A skip is visible as a
skip, and `GUARDIAN_REQUIRE_SEMGREP=1` turns absence into a hard failure — set it
when you need to know the rule pack was actually exercised. Only absence skips:
a Semgrep on `PATH` that fails `--version` fails the rule-pack tests.
`GUARDIAN_REQUIRE_LINTERS=1` does the same for actionlint and zizmor. The
suite keeps Semgrep's settings, log and version cache out of your home
directory (`test/setup/semgrepHome.ts`). Timing tests assert a shape, not a
number of milliseconds (`test/helpers/timing.ts`): a ratio of 8x the input,
and — where a 16 KB cap keeps a slow rule's total linear — a ceiling against
a benign input of the same size. A new one must fail by its assertion with
the defect it guards reintroduced in `src/`, and pass under load
(`GUARDIAN_TEST_TIMING_LOG=<file>` records every reading).
`GUARDIAN_PERF_STRICT=1` adds or tightens absolute bounds for a quiet machine
— see [`docs/env.md`](../../docs/env.md). The FIFO-swap test in
`test/unit/hooks/configFile.test.ts` reads `/proc` to tell a killed process
from its zombie, so a POSIX run needs no reaping PID 1; `docker run --init` is
still the recommended way to run the suite in a container.
