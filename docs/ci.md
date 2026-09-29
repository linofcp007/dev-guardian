# Running dev-guardian in CI

The CLI runs the same tool handlers an MCP session does — no Claude Code, no MCP connection — against a throwaway database, and gates the result against a baseline you commit.

## The short version

Run the CLI from the project you want to scan, by the absolute path of a dev-guardian clone (see [hosts.md](hosts.md#1-clone-once) — `ci-init` needs 3.0.0 or later) or of the installed plugin:

```text
npm ci --omit=dev --prefix ~/tools/dev-guardian/mcp                  # once: the runtime packages scan needs
node ~/tools/dev-guardian/cli/dev-guardian.mjs ci-init github --write      # or gitlab, bitbucket
node ~/tools/dev-guardian/cli/dev-guardian.mjs baseline update --project .  # once, locally
git add .github/workflows/dev-guardian.yml .guardian/baseline.json
```

`ci-init` writes a pipeline for the project you are in (never for dev-guardian's own repository); `baseline update` records today's findings so the gate only fails on new ones. The examples below write `dev-guardian.mjs` for that same path.

## `scan` and `baseline update`

```text
node dev-guardian.mjs scan --project . --fail-on high --sarif results.sarif
node dev-guardian.mjs baseline update --project .
```

`scan` runs, in this order: `detect_stack`, `security_scan_full` (which runs `scan_sast`, `scan_secrets`, `scan_deps` and `scan_iac`), `license_compatibility`, `map_attack_surface`, then `scan_dast` (only with `--base-url`) and `validate_finding`. A step that fails is recorded as a coverage gap and the rest still run. `quality_check` and `.guardian/budgets.yml` are not part of the CI gate.

| Flag | Meaning |
| --- | --- |
| `--project <path>` | project to scan (default: current directory) |
| `--fail-on <severity>` | `info`, `low`, `medium`, `high` (default) or `critical`: a finding new to the baseline at or above it fails the gate |
| `--format human\|json` | report on stdout |
| `--sarif <path>` | also write SARIF 2.1.0 |
| `--local-only` | Keeps Semgrep local: only rules on disk — the project's own and the plugin's packs (the LLM-application pack still runs) — with `--metrics=off`: no registry download, no Semgrep metrics, fewer rules. It is not "nothing leaves the machine": Trivy still fetches its vulnerability database, Semgrep's own version check still runs (`SEMGREP_ENABLE_VERSION_CHECK=0` turns it off), and a .NET project is still restored and built, which contacts its NuGet feeds — see [SECURITY.md](../SECURITY.md#network-egress) |
| `--base-url <url>` + `--authorized-target` | include `scan_dast` against a running app you are authorized to test |
| `--start-command <cmd> [args…]` | start the app for the DAST pass (argv, never a shell) and kill its whole process tree afterwards; requires `--base-url`. **Command line only** — a `start_command` in `.guardian/ci.json` or any other repository file makes the CLI refuse, because a fork's pull request could edit that file and run code on your runner. |
| `--accept-partial-parse <path>` | repeatable: accept that Semgrep could parse this file only in part — see [below](#files-semgrep-can-only-partly-parse). **Command line only**, like `--start-command`: an `accept_partial_parse` in `.guardian/ci.json` makes the CLI refuse. |
| `--baseline-ref <ref>` | read `.guardian/baseline.json` from the commit `<ref>` names, never from the checkout — see [below](#a-pull-request-cannot-gate-itself) |
| `--rules-ref <ref>` | read the project's Semgrep rules, `.guardianignore`, `.trivyignore` and `.bandit` from `<ref>` — see [below](#a-pull-request-cannot-gate-itself) |

| Exit code | `scan` | `baseline update` |
| ---: | --- | --- |
| 0 | pass | written, full coverage |
| 1 | gate failed | — |
| 2 | **incomplete scan**: an expected scanner did not run — never read this as a pass | written, but a scanner did not run, so the baseline may under-represent findings |
| 3 | usage or configuration error | usage or configuration error |

`baseline update` is the only command that writes `.guardian/baseline.json`; `scan` never does. The file keeps `version: 1`; entries carry a line-independent `identity` next to the fingerprint, so a finding that merely moved down a line is not "new". A 2.0.x build still reads a file written by this one, and this one reads a 2.0.x file.

### Files Semgrep can only partly parse

Semgrep sometimes reads a file only in part and says so with a warning — PHP's legal `const NAMESPACE`, common in WordPress plugins, is one on Semgrep 1.176.1. The file's other code is still analysed, but findings (or routes) in the unreadable span are missing. `scan_sast`, `map_attack_surface` and the batched scoped runs report that as **partial** coverage: Semgrep ran, is also listed missing, and the file is named. The gate exits 2 for it, and the gap line names the file:

```text
coverage gaps:
  - security_scan_full: semgrep ran with reduced coverage (partial: 1 file(s) only partly parsed — … (PartialParsing: wp/rest-controller.php)) — not accepted: wp/rest-controller.php (--accept-partial-parse <path> accepts one file, matched exactly)
```

Once you have looked at the file and decided the gap is acceptable, name it:

```text
node dev-guardian.mjs scan --project . --accept-partial-parse wp/rest-controller.php
```

- When **every** file a Semgrep step only partly parsed is accepted, that gap prints under `accepted (--accept-partial-parse):` and no longer forces exit 2 (JSON: `accepted_gaps`). A path you accepted that nothing reported is printed as unused (JSON: `unused_partial_parse_acceptances`).
- Coverage still reads `partial` — in the human report, the JSON and the SARIF (`executionSuccessful: false`). Accepting a gap is not measuring it.
- Paths are relative to `--project` and matched exactly: `/` or `\` separators and a leading `./` are fine; no globs, no directories, no case folding. An absolute path or one with `..` is a usage error (exit 3).
- Only a **parse** problem can be accepted: Semgrep's `PartialParsing`, `Syntax error` or `Lexical error` on a file you named. Semgrep reports other per-file problems the same way — a per-file `Timeout` means it gave up on the file, so nothing in it was analysed — and those still exit 2 whatever you accept; the gap line names the type (`not accepted: Timeout on wp/rest-controller.php`).
- A Semgrep that was skipped, failed (a rule or config error, an unclean exit), or scanned nothing, and any partly parsed file you did not name, still exits 2.
- With `--base-url`, the DAST step's `guardian-dast:partial-surface` gap is accepted with the same files, unless the surface has another gap (its route recovery failed). Accepting it means accepting that **routes in the unparsed spans were never in the inventory, so DAST never probed them** — not only that their static findings may be missing.
- The findings an earlier scan reported inside an accepted file stay in the open set (`findings/open`, `risk_score`, the dashboard) marked `not_remeasured`: no scan has looked at them again, so none is ever read as fixed.

### A shallow checkout exits 2

Most CI checkouts are shallow by default — GitHub's `actions/checkout` fetches one commit (`fetch-depth: 1`), GitLab uses `GIT_DEPTH: 20` / 50, Bitbucket clones 50 commits. The secrets pass reads git history, and on a shallow clone that history ends at the boundary the checkout fetched: a secret committed before it and removed since is invisible. So `scan` on a shallow checkout names the gap — `gitleaks … history truncated at <commit> — a shallow clone: the commits before it were not scanned` — and **exits 2** (incomplete), never 0.

The fix is to fetch the whole history:

| CI | Setting |
| --- | --- |
| GitHub Actions | `actions/checkout` with `fetch-depth: 0` |
| GitLab CI | `variables: { GIT_DEPTH: "0" }` |
| Bitbucket Pipelines | `clone: { depth: full }` |

The pipelines `ci-init` writes already do this. With the MCP tools rather than the CLI, a history scan limited to commits you did fetch is complete too: `scan_secrets` with `log_opts: "<base>..HEAD"` reads only that range, and a range that stays above the shallow boundary is not truncated (`--all`, or no `log_opts`, reaches the boundary and is).

### What the repository's `.trivyignore` suppressed

A `.trivyignore` in the scanned repository is honoured — accepted risks are the project's call — but never in silence. Trivy 0.50.0 or newer lists what it suppressed, and the gate names it without counting it:

```text
suppressed by the repository's own configuration (not counted by the gate):
  - security_scan_full: trivy: 7 findings suppressed by the repository's .trivyignore: CVE-2020-8203, …
```

The JSON carries the same under `suppressed_by_repo_config` (step, scanner, file, count, ids and the first findings), and the SARIF carries each suppressed finding as a result with `suppressions: [{ "kind": "external", "justification": "suppressed by the repository's .trivyignore" }]`. They change neither the exit code nor coverage. `trivy config` (the IaC pass) cannot list what it suppressed; the line then says so instead of a count, as it does for a Trivy older than 0.50.0. Review changes to `.trivyignore` like code: `review_pr` warns when a diff edits it.

### A pull request cannot gate itself

A pull request's checkout holds the pull request's own `.guardian/baseline.json` and its own scanner configuration. Read from there, the change under review decides how it is judged: a fork adds its new finding to the baseline, deletes the rule that would catch it from `.semgrep.yml`, or lists the file in `.guardianignore` — and the gate passes. Two flags take those files from a commit the pull request does not control, its base:

```text
node dev-guardian.mjs scan --project . --baseline-ref "$BASE_SHA" --rules-ref "$BASE_SHA"
```

- `--baseline-ref <ref>` reads `.guardian/baseline.json` with git from the commit `<ref>` names (size-checked first, at most 32 MiB), never from the working tree. None at that commit means no baseline: every finding is new. A `<ref>` that names no commit — a shallow clone, a base branch the checkout never fetched — is exit 3, never "no baseline" and never the checkout's copy. So is an empty value: `--baseline-ref "$BASE"` with `BASE` unset.
- `--rules-ref <ref>` copies these files from `<ref>` into a temporary directory and hands the scanners that copy; the checkout's are not read. A file the ref does not have is read from nowhere — the scan runs as the project would without it.

  | File | Read by | From the ref as |
  | --- | --- | --- |
  | `.semgrep.yml`, `.semgrep.yaml`, and the rule files the ref's `.dev-guardian/configs.json` records | Semgrep (`scan_sast`) | `--config=<copy>`; findings keep the rule id a scan of the checkout stores, so the baseline still matches |
  | `.guardianignore` | every scan | the ref's patterns, applied to the checkout's files — also for which submodules and oversized files are named as gaps, and which languages the project counts |
  | `.trivyignore` | Trivy (`scan_deps`, `scan_iac`) | `--ignorefile <copy>` |
  | `.bandit` | Bandit (`scan_sast`) | `--ini <copy>` (an empty one when the ref has none) |

  A file the ref has but that cannot be copied — over 8 MiB, a directory, a link leaving the repository, a manifest entry outside the project — stops the scan (exit 3): leaving it out would run fewer rules than the ref says. Without Semgrep on `PATH` the Docker fallback is not used (it would read the checkout's rules): Semgrep is a named gap and the scan exits 2.

- **The rest stays the checkout's, and is named.** Some configuration no flag can take from a ref:
  - `.semgrepignore` — Semgrep reads every one in the tree it scans; the only flags that would change that are marked internal and unstable in Semgrep 1.176.1.
  - `.gitleaks.toml` and `.gitleaksignore` — gitleaks 8.30.1 does take its config from `--config`, but reads `<source>/.gitleaksignore` whatever `--gitleaks-ignore-path` says (measured). A fingerprint there hides a secret as surely as an allowlist, so taking one file from the ref and not the other would protect nothing.
  - actionlint's and zizmor's configuration — the workflows they audit are the pull request's own anyway.
  - the .NET build's `.editorconfig`, `.globalconfig`, `Directory.Build.props`/`.targets` and NuGet configuration — the build reads them from the tree it compiles.

  Every one of those the pull request adds, changes or deletes against `<ref>` — a `.gitleaksignore` git ignores included, since gitleaks reads it anyway — is listed under `read from the scanned tree although it differs from <ref>`, and every file of the table above it changes under `changed in the scanned tree, not applied`. Neither changes the exit code: a pull request may legitimately edit its `.editorconfig`, and a reviewer decides.

The report always says where both came from — `baseline:` and `rules and configuration:` lines in the human output, `baseline_source` and `rules_source` in the JSON (with `tree_differences`: path, change, which copy was applied, and which scanners read it). A pull-request run that says `in the scanned tree (no --baseline-ref)` is gating the pull request against itself.

The pipelines `ci-init` writes pass both flags on a pull-request pipeline and nothing on a push, where the committed files are the gate:

| CI | Base passed | Fetch |
| --- | --- | --- |
| GitHub Actions | `github.event.pull_request.base.sha`, through the step's `env:` | none: `fetch-depth: 0` already fetched the base branch |
| GitLab CI | `CI_MERGE_REQUEST_TARGET_BRANCH_SHA` in a merged results pipeline, else `CI_MERGE_REQUEST_DIFF_BASE_SHA`; a merge request pipeline with neither stops (exit 3) | the target branch, only when that commit is missing |
| Bitbucket Pipelines | `origin/$BITBUCKET_PR_DESTINATION_BRANCH` | that branch, first |

**What this does not cover: the pipeline file itself.** GitHub's `pull_request` workflows, GitLab's merge request pipelines and Bitbucket's pull-request pipelines all run the pipeline definition from the pull request's own branch, so a pull request can edit it to drop the flags. Require review of that file (CODEOWNERS on `.github/workflows/`, `.gitlab-ci.yml` or `bitbucket-pipelines.yml`, and a required approval), and read the `baseline:` line of a pull request's report.

### Things a green pipeline does not tell you

- **SARIF carries one bit of coverage.** `invocation.executionSuccessful` turns `false` when coverage is not full, but SARIF has no field for *which* scanner was missing. That is in exit code 2 and the human/JSON output. Treat an uploaded SARIF with zero results as inconclusive until you have checked the exit code.
- **An incomplete scan's SARIF is not uploaded.** GitHub code scanning closes as fixed every open alert of a scanner an upload does not contain, whatever `executionSuccessful` says — so after an incomplete scan the missing scanner's findings would read as resolved. That is every exit 2, and an exit 1 too when a blocking finding outranked a scanner that did not run. The generated GitHub workflow uploads after exit 0, or after exit 1 only when every run in the SARIF says `executionSuccessful: true` (coverage full); the scan step records the decision as `steps.scan.outputs.upload-sarif` and the exit code as `exit-code`. A workflow of your own that uploads on `if: always()` should do the same. GitLab and Bitbucket keep the SARIF as a plain artifact, which closes nothing, so their templates keep it either way.
- **CWE and OWASP tags say what a result is, not what was tested.** A result and its rule carry `external/cwe/cwe-<n>` and `owasp-2025-a<nn>` tags when the scanner named a CWE (Semgrep rule metadata, Trivy, Bandit) or the finding is one weakness by definition (a vulnerable dependency is CWE-1395, a committed secret CWE-798). A result without tags is unmapped, not harmless, and no OWASP category is clean because it has no results: which categories a scan actually tested — judged per source language of the project, since a rule set tests only the languages it has rules for — is in `report_export`'s "OWASP Top 10:2025 coverage" table and in `compliance_evidence` with `framework: "owasp-top10-2025"`.
- **Code-scanning upload needs a public repository, or GitHub Code Security on a private one.** Otherwise the upload step fails for a reason unrelated to findings; drop it and use `--format json` plus the exit code.
- **A CI run leaves `.guardian/` in the workspace** (`security_scan_full` and `map_attack_surface` write raw reports under `.guardian/reports/`). The MCP server adds the right `.gitignore` lines whenever it starts in a project; the CLI never does. A project scanned only in CI needs them by hand — and they must let the baseline through:

  ```text
  **/.guardian/*
  !**/.guardian/baseline.json
  ```

  A bare `.guardian/` line would stop you committing the baseline: git cannot re-include a file inside an excluded directory. Without the `**/` the lines match at the repository root only, and a sub-project's `.guardian/` (a scan pointed at `packages/api`) shows up untracked.

## `ci-init`

```text
node dev-guardian.mjs ci-init <github|gitlab|bitbucket> [--project <path>] [--branch <name>] [--write] [--force] [--attest]
```

| Target | File written |
| --- | --- |
| `github` | `.github/workflows/dev-guardian.yml` |
| `gitlab` | `.gitlab-ci.yml` |
| `bitbucket` | `bitbucket-pipelines.yml` |

Without `--write` the pipeline is printed. `--write` creates the file atomically and refuses to replace an existing one unless `--force` is given; it never writes through a symlink that leaves the project. `--branch` (default `main`) is the GitHub push trigger. Exit codes: 0 done, 1 unknown target or an existing file refused, 3 usage or configuration error.

What the generated pipeline does:

- checks out the project with **full history** (`fetch-depth: 0` / `GIT_DEPTH: "0"` / `clone: depth: full`), so gitleaks attributes each secret to the commit that introduced it rather than to a shallow boundary that moves on every push; on GitHub with `persist-credentials: false`. A shallow checkout is scanned, but its history pass names the boundary it stopped at and the scan is incomplete (exit 2), never clean;
- clones dev-guardian at the release tag named in `.claude-plugin/plugin.json`, **resolved to its commit SHA when you ran `ci-init`** and verified again with `git rev-parse HEAD` after cloning — a tag that moved since is refused. The clone goes to `$RUNNER_TEMP` / `/tmp`, outside the checkout, so dev-guardian's own source is never scanned as part of your project; then `npm ci --omit=dev` in its `mcp/`;
- installs Trivy, gitleaks and actionlint pinned by version and sha256 (verified against each tool's GitHub release), and bandit, Semgrep and zizmor pinned by exact version through pipx — into a scratch directory, never the checkout. Every pinned value lives in [`configs/ci/pinned.json`](../configs/ci/pinned.json); every GitHub Action is pinned by full commit SHA;
- on GitHub, installs the .NET SDK only when the project has a root `.csproj`, `.fsproj`, `.sln` or `.slnx`; the GitLab and Bitbucket templates document that requirement instead (without the SDK, a .NET project's scan exits 2);
- runs `dev-guardian scan --fail-on high` against the committed baseline — on a pull request, the base commit's baseline and rules ([above](#a-pull-request-cannot-gate-itself)) — and uploads SARIF to code scanning on GitHub — only for a complete run (exit 0, or exit 1 with coverage full), never after an incomplete one — or keeps it as a build artifact on GitLab and Bitbucket (neither ingests raw SARIF).

Resolving the tag needs `git`: from the local checkout's tags when they are there, otherwise over the network with `git ls-remote`.

### Attesting the reports (`--attest`, GitHub only)

`ci-init github --attest` makes the pipeline prove where its reports came from. On a push to the branch:

- the scan step also writes the JSON report (`--format json`, through `tee` under `pipefail`, so the log still shows it and the scan's exit code still decides the step), and the scan job keeps `dev-guardian-report.json` and `dev-guardian-results.sarif` as the `dev-guardian-reports` artifact;
- a separate `attest` job downloads them, refuses a report that is empty or not a report (`tee` creates the file even when the scan crashed before writing one), and signs a SLSA build-provenance attestation for both with `actions/attest-build-provenance` — Sigstore keyless, with the workflow's own OIDC identity, stored in the repository's attestations. Every action involved is pinned by commit SHA in [`configs/ci/pinned.json`](../configs/ci/pinned.json).

The `attest` job runs **even when the gate failed**: an attestation proves where a report came from — this workflow, this commit, this run — never that the gate passed. Read the report for that.

On a **public repository** this exposes the results: the full JSON report (every new finding, with its file and line) is printed to the public job log, and the `dev-guardian-reports` artifact — SARIF and JSON — can be downloaded by any signed-in GitHub user while it is retained. Secrets stay redacted in both, as everywhere else.

Permissions: the `attest` job holds `id-token: write` and `attestations: write` and nothing else. The scan job — which builds and scans the project, and so runs code from it — keeps exactly `contents: read`, `security-events: write` and `actions: read`, as without `--attest`; with two jobs these move from the workflow level to each job (`permissions: {}` at the top). Pull requests are not attested: a fork's pull request gets no OIDC token, and nobody verifies a pull request's reports later.

Artifact attestations need a public repository, or GitHub Enterprise Cloud for a private or internal one; anywhere else the `attest` job fails.

To verify a report, download the run's artifact and check it against the workflow that should have produced it:

```text
gh run download <run-id> --repo OWNER/REPO --name dev-guardian-reports
gh attestation verify dev-guardian-results.sarif --repo OWNER/REPO \
  --signer-workflow OWNER/REPO/.github/workflows/dev-guardian.yml \
  --source-ref refs/heads/main
gh attestation verify dev-guardian-report.json --repo OWNER/REPO \
  --signer-workflow OWNER/REPO/.github/workflows/dev-guardian.yml \
  --source-ref refs/heads/main
```

Use the branch you passed to `--branch` (`ci-init` prints the command with it). Keep `--source-ref`: `--signer-workflow` names the workflow **file**, and a copy of it on any other branch — edited to run on a push there — signs as the same path.

`--attest` is **command line only**, like `scan --start-command`: a `.guardian/ci.json` declaring `attest` makes `ci-init` refuse (exit 3), because a pull request could edit that file and hand a job the right to sign in the repository's name. GitLab and Bitbucket refuse `--attest` (exit 3): Bitbucket's OIDC tokens are no Sigstore identity, and on GitLab a cosign keyless signature of the reports would carry no provenance and have no store to be verified against — not the same guarantee, so the generator does not pretend it is.

## Scanning workflows

`scan_iac` also audits `.github/workflows/*.yml` when they exist: **zizmor** (template injection, unpinned `uses:`, excessive `permissions:`, persisted credentials) and **actionlint** (schema and expression errors). dev-guardian runs actionlint with `-shellcheck= -pyflakes=`, so its shellcheck and pyflakes checks of `run:` blocks are off. Either tool missing is a named gap in `missing_tools`, never silence.
