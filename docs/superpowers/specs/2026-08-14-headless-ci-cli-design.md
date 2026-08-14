# Design — headless CI scanning from the command line

Item 5 of 7 in the strix-gap project. Everything this plugin does today needs
an MCP host and a human in a conversation. This makes the same scans runnable
from a pipeline, gated against a committed baseline, reporting in the format a
code-review surface can render.

## 1. Context

`dev-guardian` runs as an MCP server: a host connects over stdio, an agent
calls tools, findings land in SQLite under `.guardian/`. That model assumes an
interactive session and local state. A CI runner has neither — it is
non-interactive, and its filesystem is discarded when the job ends.

Two consequences drive this design:

- **State does not survive.** Baselines, suppressions and scan history are the
  reason to use this over calling Semgrep directly, and a fresh database makes
  every finding new. Without an answer, the CLI is a scanner wrapper.
- **Nobody reads a CI log.** A finding that does not appear on the diff of the
  pull request that introduced it may as well not have been found.

### Non-goals (v1)

- **No npm publish, no Docker image, no CI of its own.** This repository stays
  CI-free by an explicit standing decision — the tool targets *users'*
  pipelines, not its own. Distribution is `git clone` (§2).
- **No second implementation of any scan.** The CLI calls the same MCP tool
  handlers the server does. A parallel scan path would drift.
- **No mutation of the user's repository** beyond the baseline file, and only
  when explicitly asked (`baseline update`).

## 2. Decisions taken during design

Locked with the user, in order:

1. **Distribution:** `git clone --depth 1` plus `node cli/dev-guardian.mjs`,
   documented now. This works today with no build step because `mcp/dist/` is
   committed. A root `package.json` with a `bin` field (enabling
   `npx github:…`) is **investigated separately**, with a real test against the
   Claude Desktop plugin validator before it is promised to anyone — a
   top-level `bin/` has already broken that validator once, with an error
   message that points nowhere near the cause.
2. **State:** a **committed baseline file**. Portable, reviewable in a pull
   request, needs no cache. What `gitleaks` and `semgrep` do.
3. **Gate:** fails on findings **absent from the baseline** that meet a
   severity threshold. Historical debt does not fail the build; regressions do.
4. **Scope:** every static analysis **plus** `scan_dast`, including starting
   the application, behind explicit flags.

## 3. Architecture

### The logic lives in TypeScript, not in the `.mjs`

`mcp/src/ci/` holds the behaviour; `cli/dev-guardian.mjs` parses arguments and
dispatches, importing from `../mcp/dist/` exactly as the existing `check`
command already does.

This is not tidiness. The code that decides whether someone's build fails gets
the same tests, the same `noUncheckedIndexedAccess`, and the same review as the
rest of the server. An 800-line `.mjs` would be the only untested part of the
project, and the one part that runs with no human watching.

### Scans run through the tool handlers

`runScans.ts` builds a `PluginContext` and calls
`TOOLS.find(t => t.name === …).handler(input, ctx)`. There is no second
implementation of any scan. This is `host-rules/AGENTS.md`'s own rule —
*"invoke the MCP tools rather than shelling out to the scanners"* — applied to
the CLI itself: when `scan_sast` changes, CI changes with it, because there is
no parallel path to drift.

The SQLite database is ephemeral: a temporary directory, discarded at exit.
**The portable state is the baseline file, not the database.**

### Which scans, and in what order

Order is not cosmetic — three of the tools consume what an earlier one
persisted, and running them out of sequence produces a refusal rather than a
result:

1. `detect_stack` — everything downstream reads it.
2. `security_scan_full` — the existing composite (SAST, secrets, dependencies,
   containers, IaC). One call, so the CLI inherits its orchestration rather
   than reimplementing it.
3. `license_compatibility`.
4. `map_attack_surface` — **must precede** the next two; both refuse without a
   surface snapshot.
5. `scan_dast` — only when `--base-url` or `--start-command` is given.
6. `validate_finding` — last, because it qualifies findings the earlier steps
   produced, and reads the DAST results for its anonymous-exposure evidence.

A step that refuses (a missing prerequisite, an uninstalled scanner) does not
abort the run: it is recorded, its absence feeds the coverage signal in §5, and
the remaining steps proceed. A CI tool that stops at the first gap reports less
than one that continues and says what it missed.

### Modules

| Module | Kind | Responsibility |
| --- | --- | --- |
| `mcp/src/ci/baseline.ts` | **pure** | Read, write, and diff a baseline against a finding set. |
| `mcp/src/ci/gate.ts` | **pure** | Findings + baseline + threshold + coverage → verdict and exit code. |
| `mcp/src/ci/report.ts` | **pure** | Format human / JSON / SARIF. |
| `mcp/src/ci/runScans.ts` | I/O | Build the ephemeral context, invoke the handlers, collect results. |
| `mcp/src/ci/appRunner.ts` | I/O | Application lifecycle for the DAST pass. **Separable** (§7). |
| `cli/dev-guardian.mjs` | shim | Argument parsing and dispatch. |

The pure/I-O split is the boundary that survived items 1–4: every fabrication
defect in this project was born in a layer that read input and decided at the
same time.

## 4. The baseline

`.guardian/baseline.json`, committed to the user's repository.

Each entry carries the fingerprint plus the context that makes a pull request
reviewable: severity, title, file path, and the date it entered. Somebody
editing this file is suppressing a finding, and the diff shows another human
what was suppressed and when.

Two commands:

- `dev-guardian scan` — compares the current findings against it.
- `dev-guardian baseline update` — regenerates it from the current scan.

`baseline update` is the only operation that writes to the user's repository,
and it never runs implicitly. A `scan` that silently absorbed new findings into
the baseline would turn the gate into decoration.

An **absent** baseline file is not an empty one: on the first run the CLI says
so, reports what it found, and tells the user to run `baseline update` to
adopt the current state. Treating "no file" as "no known findings" would fail
the first build of every existing repository.

## 5. The gate, and why `coverage` is a precondition

The gate fails when a fingerprint **absent from the baseline** meets or exceeds
`--fail-on` (default `high`).

Carried forward from items 1, 3 and 4, and load-bearing here: **a finding count
without `coverage` beside it is not an answer.** If Semgrep was not installed,
"zero new findings" is not a green build — it is a scan that did not run. The
CLI exits with a distinct code and names the missing scanner rather than
letting it pass.

"Expected but absent" is **not** a new judgement invented here. Every scan tool
already reports `tools_run` and `missing_tools`, and `tools/scanCoverage.ts`'s
`computeCoverage` already distils them into `full` / `partial` / `none` — with
the case that matters already handled: a scan with genuinely nothing to do (no
Dockerfile, so no container scan) reports `full`, because there were no gaps,
just no work. The CLI **reuses that function** across every step it ran. Any
step reporting worse than `full` produces exit `2`, and the report names which
scanner and why. Re-deriving this in `gate.ts` would create a second definition
of "complete" that could disagree with the one the tools themselves report.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Passed |
| `1` | Gate failed — new findings at or above the threshold |
| `2` | **Incomplete scan** — an expected scanner did not run |
| `3` | Usage or configuration error |

`2` is the code most tools lack, and it is what prevents the silent failure:
without it, a missing Semgrep produces "zero new findings" and exits `0`. A
pipeline may choose to treat `2` as a warning or as a failure — but it must be
able to tell it apart from a genuine pass.

## 6. Output

Three formats: **human** (default), **JSON** (scripting), **SARIF**.

SARIF is the one that matters and the one missing today. GitHub Code Scanning,
GitLab and Azure DevOps all ingest it, and with it the findings appear
**annotated on the lines of the pull request diff** instead of buried in a log.
That is the difference between a check people read and one they learn to
ignore.

SARIF output must be **validated against the schema** in tests, not against
this document's idea of it: GitHub accepts a malformed SARIF file silently and
simply displays nothing, which is indistinguishable from a clean scan.

## 7. `--start-command`, and the rule that makes it safe

Item 3 deliberately withheld application startup from the `scan_dast` MCP tool:
the parameter would be filled by a model whose context includes the repository
under analysis, so an injected comment in a README would have somewhere to
point. The capability was deferred to here, on the reasoning that **the filler
is a human writing a pipeline file.**

That reasoning stops being true if the command can come from a file *inside the
repository*. A pull request from a fork that edits `.guardian/ci.yml` would
then execute arbitrary code in CI — the classic *pwn request*, which has
compromised real projects.

Therefore:

- **`--start-command` may come only from argv. Never from a file in the
  repository.** If a repository config file declares one, the CLI **refuses**
  and says why. Other configuration may live in the repo; this key may not.
- **No shell.** argv as an array, `shell: false`. No string interpolation.
- **Health-check polling with a timeout**, so a failed start is a clear error
  rather than a hang.
- **Teardown of the process tree on every path, including failure.** A scan
  that crashes must not leave the user's application running on the runner.

`appRunner.ts` is a separable subsystem — application lifecycle in CI has its
own failure modes (ports, health checks, timeouts, orphaned processes) and gets
its own tasks, so it can be deferred without taking the rest of the CLI with
it.

## 8. Testing

- **Pure modules** (`baseline`, `gate`, `report`) carry the weight, with one
  named test per rule: historical debt does not fail; a new finding below the
  threshold does not fail; a missing scanner exits `2` and not `0`; an absent
  baseline file is not an empty baseline.
- **SARIF validated against the schema.**
- **`appRunner` tested against a real child process**, including a test that
  kills the scan mid-run and asserts **nothing is left running**.
- **An e2e that invokes `cli/dev-guardian.mjs` as a subprocess**, because that
  is how a user runs it, and it is the only test that catches a defect in
  argument dispatch.
- **Assertions must distinguish the correct implementation from the
  plausible-wrong one.** The previous feature had thirteen findings of that
  shape; most were caught only by executing the shipped code or mutating it.
  This is a standing review criterion.

## 9. Known limitations at first release

- Distribution is a `git clone` of a plugin repository — heavier than an
  `npx` one-liner. Mitigated by `--depth 1` and a pinned tag; revisited if the
  `npx` investigation (§2) succeeds.
- The ephemeral database means no trend history in CI. The baseline carries
  what must persist; anything else is out of scope by design.
- `scan_dast` in CI reaches only what the pipeline can reach. An application
  behind a private network the runner cannot see is out of scope.
- SARIF carries findings plus two run-level facts, and nothing more. **Amended
  after implementation**, because the original wording was blunter than the
  format allows: SARIF has `invocation.executionSuccessful`, which is set
  `false` whenever coverage is not `full`, and `toolExecutionNotifications`,
  which carries the unreadable-baseline line. So a consumer reading only the
  upload can tell an incomplete run from a clean one — it just cannot see
  *which* scanner was missing or why. That detail lives in the exit code and
  the human/JSON output, and the documentation must say so.

## 10. Definition of done

- `scan` and `baseline update` implemented, logic in `mcp/src/ci/`, the `.mjs`
  a dispatch shim.
- Scans run through the MCP tool handlers, with no second implementation.
- Baseline is committed-file-based; an absent file is distinct from an empty
  one.
- Four exit codes, with `2` reachable and tested.
- Human, JSON and SARIF output; SARIF schema-validated in tests.
- `--start-command` refused from any repository file; no shell; teardown on
  every path, proven by a test that leaves nothing running.
- `npm run build` clean; `npm test` green with **zero skips** under
  `GUARDIAN_REQUIRE_SEMGREP=1`; coverage thresholds held.
- Documented in `README.md` and `host-rules/AGENTS.md` with a copy-pasteable
  pipeline snippet, and the distribution caveat stated plainly.
