# Running dev-guardian in CI

The CLI runs the same tool handlers an MCP session does — no Claude Code, no MCP connection — against a throwaway database, and gates the result against a baseline you commit.

## The short version

```text
node cli/dev-guardian.mjs ci-init github --write      # or gitlab, bitbucket
node cli/dev-guardian.mjs baseline update --project .  # once, locally
git add .github/workflows/dev-guardian.yml .guardian/baseline.json
```

`ci-init` writes a pipeline for the project you are in (never for dev-guardian's own repository); `baseline update` records today's findings so the gate only fails on new ones.

## `scan` and `baseline update`

```text
node cli/dev-guardian.mjs scan --project . --fail-on high --sarif results.sarif
node cli/dev-guardian.mjs baseline update --project .
```

`scan` runs, in this order: `detect_stack`, `security_scan_full` (which runs `scan_sast`, `scan_secrets`, `scan_deps` and `scan_iac`), `license_compatibility`, `map_attack_surface`, then `scan_dast` (only with `--base-url`) and `validate_finding`. A step that fails is recorded as a coverage gap and the rest still run. `quality_check` and `.guardian/budgets.yml` are not part of the CI gate.

| Flag | Meaning |
| --- | --- |
| `--project <path>` | project to scan (default: current directory) |
| `--fail-on <severity>` | `info`, `low`, `medium`, `high` (default) or `critical`: a finding new to the baseline at or above it fails the gate |
| `--format human\|json` | report on stdout |
| `--sarif <path>` | also write SARIF 2.1.0 |
| `--local-only` | Semgrep runs only the rules on disk, with `--metrics=off`: no registry download, no telemetry, fewer rules |
| `--base-url <url>` + `--authorized-target` | include `scan_dast` against a running app you are authorized to test |
| `--start-command <cmd> [args…]` | start the app for the DAST pass (argv, never a shell) and kill its whole process tree afterwards; requires `--base-url`. **Command line only** — a `start_command` in `.guardian/ci.json` or any other repository file makes the CLI refuse, because a fork's pull request could edit that file and run code on your runner. |

| Exit code | `scan` | `baseline update` |
| ---: | --- | --- |
| 0 | pass | written, full coverage |
| 1 | gate failed | — |
| 2 | **incomplete scan**: an expected scanner did not run — never read this as a pass | written, but a scanner did not run, so the baseline may under-represent findings |
| 3 | usage or configuration error | usage or configuration error |

`baseline update` is the only command that writes `.guardian/baseline.json`; `scan` never does. The file keeps `version: 1`; entries carry a line-independent `identity` next to the fingerprint, so a finding that merely moved down a line is not "new". A 2.0.x build still reads a file written by this one, and this one reads a 2.0.x file.

### Things a green pipeline does not tell you

- **SARIF carries one bit of coverage.** `invocation.executionSuccessful` turns `false` when coverage is not full, but SARIF has no field for *which* scanner was missing. That is in exit code 2 and the human/JSON output. Treat an uploaded SARIF with zero results as inconclusive until you have checked the exit code.
- **Code-scanning upload needs a public repository, or GitHub Code Security on a private one.** Otherwise the upload step fails for a reason unrelated to findings; drop it and use `--format json` plus the exit code.
- **A CI run leaves `.guardian/` in the workspace** (`security_scan_full` and `map_attack_surface` write raw reports under `.guardian/reports/`). The MCP server adds the right `.gitignore` lines whenever it starts in a project; the CLI never does. A project scanned only in CI needs them by hand — and they must let the baseline through:

  ```text
  .guardian/*
  !.guardian/baseline.json
  ```

  A bare `.guardian/` line would stop you committing the baseline: git cannot re-include a file inside an excluded directory.

## `ci-init`

```text
node cli/dev-guardian.mjs ci-init <github|gitlab|bitbucket> [--project <path>] [--branch <name>] [--write] [--force]
```

| Target | File written |
| --- | --- |
| `github` | `.github/workflows/dev-guardian.yml` |
| `gitlab` | `.gitlab-ci.yml` |
| `bitbucket` | `bitbucket-pipelines.yml` |

Without `--write` the pipeline is printed. `--write` creates the file atomically and refuses to replace an existing one unless `--force` is given; it never writes through a symlink that leaves the project. `--branch` (default `main`) is the GitHub push trigger. Exit codes: 0 done, 1 unknown target or an existing file refused, 3 usage or configuration error.

What the generated pipeline does:

- checks out the project with **full history** (`fetch-depth: 0` / `GIT_DEPTH: "0"` / `clone: depth: full`), so gitleaks attributes each secret to the commit that introduced it rather than to a shallow boundary that moves on every push; on GitHub with `persist-credentials: false`;
- clones dev-guardian at the release tag named in `.claude-plugin/plugin.json`, **resolved to its commit SHA when you ran `ci-init`** and verified again with `git rev-parse HEAD` after cloning — a tag that moved since is refused. The clone goes to `$RUNNER_TEMP` / `/tmp`, outside the checkout, so dev-guardian's own source is never scanned as part of your project; then `npm ci --omit=dev` in its `mcp/`;
- installs Trivy, gitleaks and actionlint pinned by version and sha256 (verified against each tool's GitHub release), and bandit, Semgrep and zizmor pinned by exact version through pipx — into a scratch directory, never the checkout. Every pinned value lives in [`configs/ci/pinned.json`](../configs/ci/pinned.json); every GitHub Action is pinned by full commit SHA;
- on GitHub, installs the .NET SDK only when the project has a root `.csproj`, `.fsproj`, `.sln` or `.slnx`; the GitLab and Bitbucket templates document that requirement instead (without the SDK, a .NET project's scan exits 2);
- runs `dev-guardian scan --fail-on high` against the committed baseline and uploads SARIF to code scanning on GitHub, or keeps it as a build artifact on GitLab and Bitbucket (neither ingests raw SARIF).

Resolving the tag needs `git`: from the local checkout's tags when they are there, otherwise over the network with `git ls-remote`.

## Scanning workflows

`scan_iac` also audits `.github/workflows/*.yml` when they exist: **zizmor** (template injection, unpinned `uses:`, excessive `permissions:`, persisted credentials) and **actionlint** (schema and expression errors, and shellcheck on `run:` blocks when shellcheck is installed). Either one missing is a named gap in `missing_tools`, never silence.
