# Build and test

> Maintainer notes, moved from `CLAUDE.md` (the index). Not loaded into sessions: read this file before you
> change its area.

## Build & test (always from `mcp/`)

```bash
cd mcp
npm ci               # first time only — Node >= 22.13; no native modules, storage is node:sqlite
npm run lint         # tsc over src/ AND test/ (two tsconfigs)
npm run build        # tsc -> mcp/dist, copy-assets, host-rules, esbuild bundles, docs
npm test             # vitest run (full suite)
npm run test:coverage # the only run that enforces the coverage thresholds
```

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
