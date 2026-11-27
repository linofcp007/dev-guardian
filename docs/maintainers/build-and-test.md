# Build and test

> Maintainer notes, moved from `CLAUDE.md` (the index). Not loaded into sessions: read this file before you
> change its area.

## Build & test (always from `mcp/`)

```bash
cd mcp
npm ci               # first time only — Node >= 22.13; no native modules, storage is node:sqlite
npm run lint         # tsc over src/ AND test/ (tsconfig.test.json), then the hand-written JS (tsconfig.js.json)
npm run build        # tsc type-check, esbuild bundles -> mcp/dist, copy-assets, host-rules, docs
npm test             # vitest run (full suite) — the gate before a commit
npm run test:fast    # unit + docs minus the 18 slowest unit files (vitest.fast.config.ts) — the inner loop
npm run test:coverage # the coverage thresholds, natively
npm run test:docker  # Linux containers: Node 22.13 (with coverage) and the LTS (scripts/test-docker.mjs)
```

**Linux, the Node floor, coverage (review 8, findings 1 and 8).** There is no
CI by policy, the maintainer machine is Windows on a current Node, and 36
POSIX-only tests, the 22.13–22.15 fallbacks in `storage/db.ts` and the coverage
floor never ran. `npm run test:docker` streams `git archive HEAD` into
`node:22.13-bookworm-slim` and `node:24-bookworm-slim` (git added, built once
and cached), runs `npm ci` and `vitest run` there as the unprivileged `node`
user — and on the floor image with `--coverage`, so the thresholds in
`vitest.config.ts` are enforced in the run every release makes (CONTRIBUTING,
Releases, step 0). Not in `npm test`: coverage instrumentation adds a third or
more to an already long run on every commit, and the floor is a release
question. `--toolchain` adds Semgrep and Bandit (pip-pinned) and gitleaks and
Trivy (the release archives `src/runners/installCatalog.ts` pins, sha256-
checked) and sets `GUARDIAN_REQUIRE_SEMGREP`/`_GITLEAKS`, so a missing scanner
fails instead of skipping. It is the run a release makes (CONTRIBUTING, Releases,
step 0): without it every test of a real scanner is skipped on Linux, and the
suite had never been green with it until 3.9.3 — ten tests, among them a rule
pack that found half of its fixture on Linux. The image is Debian 12, whose git
is 2.39.5: older than `GIT_ATTR_SOURCE` (2.40), which is why two secret-history
tests assert the limit the pass names there (`test/helpers/gitVersion.ts`), and
the locale is UTF-8, which is why the pack-encoding tests' Semgrep runs are for
Windows alone. The toolchain image's tag ends in a digest of its own
recipe, so a pin that moved builds a new image: named by its base alone, the
image built once went on being used, and the run after a bump tested the old
scanner. Logs: `<tmpdir>/dev-guardian-docker/`. `@types/node`
is held to `~22.13` for the same reason: an API newer than the floor does not
type-check.

What `npm run build` writes to `mcp/dist/` (review 8, findings 2 and 3), all
of it committed:

- `engine.js` — the esbuild bundle of `src/engine.ts`: the MCP server and
  everything the CLI uses (`src/cli.ts`), every npm package inlined. The server
  and the CLI shared 98.8% of their code as two 3.7 MB bundles; one bundle
  cannot ship them from different builds.
- `server.js` — the server's entry: it turns Node's compile cache on (in a directory only the account can write — the block it shares with the hook and the CLI), imports `engine.js`, has the cache written at once (a killed server never wrote it) and calls `startServer()`
  (`SERVER_JS` in `scripts/bundleOptions.mjs`), at the path `plugin.json` and
  every host configuration name.
- `hooks.js` — the bundle of `src/hooksEntry.ts`: what every hook event needs
  (the configuration reader, the guarded-path resolution, the choice of the session's and the project's folder) and the `load*`
  loaders of the detectors, which live in five parts of their own, each a
  self-contained bundle of what one kind of event runs (3.4.0):
  `hooksBash.js` (the shell guard and the install gate), `hooksVet.js`
  (install vetting), `hooksWrite.js` (the write guards and the secret scan),
  `hooksSession.js` (SessionStart's git, database registry and engine check),
  `hooksProbe.js` (the child process that asks whether a network folder answers — only a call with one loads it).
  The entry's `import('./hooksBash.js')` is left to the runtime (the
  `hook-parts` plugin in `bundleOptions.mjs`); under tsx and vitest it is the
  source `src/hooksBash.ts`. An event parses only its parts: 3.3.0's one file
  made every write parse 368 KB and load `node:crypto` and
  `node:child_process`. Not esbuild's code splitting, which made a chunk per
  module: a dozen files per event, each a dynamic `import()` with its own
  cost (~3 ms on Windows), was slower than the one file. The hooks build
  carries the engine's size and SHA-256 (`define`d as
  `__GUARDIAN_ENGINE_DIGEST__`, read by `src/hooks/distCheck.ts`), so
  SessionStart names a damaged `engine.js` without loading it — the engine is
  built first (`buildDist`). Their inputs are this repo's sources only — no
  npm package, no storage layer (`hooksDistImports.test.ts`, which also holds
  each event to its own part).
- `storage/migrations/*.sql` and `hostsetup/legacyRulesTemplates/*` —
  `copy-assets.mjs`, one level below the bundles, where their probes look.
- `engine.d.ts`, `hooks.d.ts` — one line each, `export * from
  '../src/engine.js'` / `'../src/hooksEntry.js'`: the types the CLI and the
  hook dispatcher are checked against (`tsconfig.js.json`), so the checker
  never reads a bundle (`DECLARATIONS` in `bundleOptions.mjs`, 3.4.0).

Nothing else: `tsconfig.json` is `noEmit` (tsc only type-checks), no source
map ships, and `scripts/bundle.mjs` empties `dist/` before it writes — 743
files / 14.6 MB before 3.3.0, 24 files / 4.1 MB since. Code that finds a file
relative to `import.meta.url` (`platform/scriptsDir.ts`, `configsDir.ts`,
`version.ts`, the migrations runner, `hostsetup/setup.ts`) still probes two
depths: a bundle in `dist/`, or its own file in `src/` under tsx and vitest.
esbuild keeps a `//` comment inside a function body, so even a comment can
change a bundle: rebuild after every `src/` change, and let
`distSync.test.ts` say whether it mattered. `.gitattributes` marks
`mcp/dist/**` generated, with no text diff.

`npm run build` ends by regenerating the committed, generated files: every
`host-rules/*` template and the in-repo rules copies (from
`mcp/src/hostsetup/rulesTemplate.ts`), then `docs/tools.md`,
`docs/rule-packs.md` and `docs/hooks-known-limits.md` (`npm run docs`, i.e.
`tsx test/docs/generate.ts`, from the registry, the pack files and
`test/fixtures/hooks/known-limits.yml`). Drift tests fail when a committed copy differs, and
`mcp/test/docs/docs.test.ts` also holds every tool, resource, skill and command
count in the READMEs, this file and `mcp/README.md` — and the pack table below —
to the code. The fix for any of those failures is `npm run build` or correcting
the number, never editing a generated file.

**The hooks' known limits are data.** `test/fixtures/hooks/known-limits.yml`
holds one record per limit — its published text, and examples with the verdict
the guard gives each today, measured with the platform, the home and the
working directory injected. `test/unit/hooks/knownLimits.test.ts` runs the
shell and secret examples through the real detectors and
`test/e2e/knownLimitsHook.test.ts` the hook examples through the real
dispatcher. A failure names the limit and the direction: a guard that answers
more strictly has closed the limit, and its record leaves the file (or its
example is corrected) in the same commit; one that answers less strictly got
weaker — fix the guard, never the record. A new limit is a new record, never a
line of prose in `docs/hooks.md`, which the docs test refuses.

**The METRIC line's contract is one file shared with dev-spec-driven (3.17.0).**
`test/fixtures/metrics/metric-lines.v1.json` (`metric-lines/1`: the line's
grammar and the one set of reader bounds, the judge's rule, 36 lines, 5 whole
outputs and 21 judge cases) is committed byte-identical at dev-spec-driven's
`mcp/tests/fixtures/`, and both suites pin the same sha256 literal
(`test/unit/metrics/metricLinesFixture.test.ts` here, `09-evidence-runs.js`
there). The two readers are written in two languages and no suite can read the
other repository, so the pin is what keeps them on one contract. The file is
never edited: a change is `metric-lines/2`, a new file landed in both
repositories before either tags. The pin test also holds the file's shape —
every case's fields (an absent value is `null`, never a missing key), the cases
the decisions name, ASCII with LF ends, no CI or PR word — and the readers are
tested against its cases in their own files — here `test/unit/metrics/metricLine.test.ts` (every line
and output case, and the points the fixture leaves to each suite: tokens split on runs of blanks, keys in
any order, `__proto__` an ordinary name, a 513-byte candidate a drop, CSI removed — but a keyword one splits
is none, as dev-spec-driven reads the keyword in the raw output —, each bound's drop said) and
`judge.test.ts` (every judge case, the symmetric verdict, terms a current line adds creating no judgment).

**The bytes are a second shared file (3.18.0).** `test/fixtures/metrics/metric-bytes.v1.json`
(`metric-bytes/1`, 11 cases) holds a run's stdout and stderr as hex and two decided readings of them: `file`,
the `metrics` command's (a `2>&1` capture in print order, decoded by `decodeText`), and `stream`,
dev-spec-driven's `done --run` (each stream apart, as UTF-8); `differs` gives the reason exactly when the two
differ, order included. It is committed byte-identical at dev-spec-driven's `mcp/tests/fixtures/`, both suites
pin one sha256 (`test/unit/metrics/metricBytesFixture.test.ts` here, with the shape and a coverage read from the
bytes, never from the guess's numbers), and `metricFile.test.ts` reads every case through `readMetricFile` and
`readMetricOutput` against its `file` column. A sample, not a proof: a change that alters no case still passes.
`decodeText` is shared with `check --file`: a change to it for `check --file`'s sake is made on its own merits,
and if it flips a case, `metric-bytes/2` follows in both repositories in the same round — the fixture never holds
a secret-scan fix back.

On Windows, run the full suite from **Git Bash**. From PowerShell, `bash` can
resolve to the WSL launcher stub, and the `ci-init` e2e fails for that reason
alone.

Semgrep-dependent e2e tests skip when Semgrep is absent. A skip is visible as a
skip, and `GUARDIAN_REQUIRE_SEMGREP=1` turns absence into a hard failure — set it
when you need to know the rule pack was actually exercised. Only absence skips:
a Semgrep on `PATH` that fails `--version` fails the rule-pack tests. The same
switch requires Trivy in the tests that need a real one, and
`GUARDIAN_REQUIRE_GITLEAKS=1` gitleaks.

"Installed" is asked the way the server asks it (`test/helpers/toolchain.ts`):
on `PATH`, or in the per-user tools directory `install_toolchain` writes to
(`~/.local/bin`, `%USERPROFILE%\.local\bin`), which the probe appends to the
test process's `PATH` as the server appends it to its own. A scanner the
product would run is never a skipped test: with `where` / `which` alone, every
real-Trivy and real-gitleaks test was skipped on a machine the product itself
had set up, and two `create_fix_pr` tests stayed red behind the skip.

A test that gives the .NET SDK a faked home (`DOTNET_CLI_HOME`) sets
`DOTNET_ADD_GLOBAL_TOOLS_TO_PATH=0` and `DOTNET_GENERATE_ASPNET_CERTIFICATE=0`
with it. A home the SDK has never seen gets its first run, and two steps of a
first run write to the real account, not to the home: on Windows
`<home>\.dotnet\tools` is appended to the user's `PATH` in the registry, and
the account's certificate store is consulted and, when empty, filled. The last
test of `test/e2e/nugetCredentialBinding.test.ts` holds it.
`GUARDIAN_REQUIRE_LINTERS=1` does the same for actionlint, zizmor and shellcheck, and
`GUARDIAN_REQUIRE_GOSEC=1` for gosec, govulncheck and the Go toolchain (`test/e2e/gosecSast.test.ts`,
`test/e2e/govulncheckDeps.test.ts`;
neither is in `--toolchain`, so run it where both are on `PATH`), and
`GUARDIAN_REQUIRE_CPPCHECK=1` for cppcheck (`test/e2e/cppcheckSast.test.ts`; not in `--toolchain`
either — on Windows, `msiexec /a` of the release MSI unpacks it without installing), and
`GUARDIAN_REQUIRE_PSALM=1` for Psalm and PHP (`test/e2e/psalmSast.test.ts`: `psalm.phar` in a
directory on `PATH`), and `GUARDIAN_REQUIRE_DETEKT=1`, `GUARDIAN_REQUIRE_RUBOCOP=1` and
`GUARDIAN_REQUIRE_SPOTBUGS=1` for detekt, RuboCop and SpotBugs (`test/e2e/detektQuality.test.ts`,
`rubocopQuality.test.ts`, `spotbugsSast.test.ts`: `detekt-cli.jar` and the `rubocop` script in a
directory on `PATH`, SpotBugs where install_toolchain puts it or in `SPOTBUGS_HOME`, with Java,
`javac` and Ruby; a portable Temurin and RubyInstaller unpacked anywhere will do), and
`GUARDIAN_REQUIRE_WPSCAN=1` for WPScan (`test/e2e/wpscanNoDatabase.test.ts`; not in `--toolchain`). The
suite keeps Semgrep's settings, log and version cache out of your home
directory (`test/setup/semgrepHome.ts`). Timing tests assert a shape, not a
number of milliseconds (`test/helpers/timing.ts`): a ratio of 8x the input,
and — where a 16 KB cap keeps a slow rule's total linear — a ceiling against
a benign input of the same size. A new one must fail by its assertion with
the defect it guards reintroduced in `src/`, and pass under load
(`GUARDIAN_TEST_TIMING_LOG=<file>` records every reading). A defect that is
a WAIT rather than a cost — a read blocked on a FIFO or a network path, a
budget ignored — takes `hangBound(strictMs)`: the tight bound under
`GUARDIAN_PERF_STRICT=1`, else 12 s, under a hook's 15 s kill and short of
every such defect. No test asserts "under N ms" on its own (review 8,
finding 13).
`GUARDIAN_PERF_STRICT=1` adds or tightens absolute bounds for a quiet machine
— see [`docs/env.md`](../../docs/env.md). The FIFO-swap test in
`test/unit/hooks/configFile.test.ts` reads `/proc` to tell a killed process
from its zombie, so a POSIX run needs no reaping PID 1; `docker run --init` is
still the recommended way to run the suite in a container.
