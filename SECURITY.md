# Security Policy

dev-guardian is a security tool, so we hold its own code to the bar it enforces.

## Supported versions

Only the latest release receives security fixes; older tags are not patched —
upgrade to the newest release.

| Version | Supported |
| ------- | --------- |
| 2.0.x   | ✅        |
| < 2.0   | ❌        |

## Reporting a vulnerability

**Do not open a public issue for security reports.**

Email **[carlospereira@prodigitalkey.com](mailto:carlospereira@prodigitalkey.com)** with:

- a description of the issue and its impact,
- steps to reproduce (PoC if possible),
- the affected version / commit.

You can expect an acknowledgement within **72 hours** and a remediation plan
once the report is triaged. Please allow a reasonable disclosure window before
going public; we will credit reporters who want it.

## Scope

In scope: the MCP server (`mcp/`), the CLI (`cli/dev-guardian.mjs`), the
guardrail hooks (`hooks/`), the skills and slash commands, the bundled configs
and CI templates (`configs/`), and the supply-chain logic in `scan_skill`,
`vet_packages` and `audit_agent_config`.

Out of scope: vulnerabilities in the third-party scanners dev-guardian
orchestrates (Semgrep, Trivy, gitleaks, Syft, WPScan, …) — report those to
their respective projects.

## Hardening posture

- **dev-guardian sends no telemetry of its own.** Results persist to
  `.guardian/guardian.db` in the scanned project and never leave it. Reports and
  the dashboard are self-contained and load no external assets.
- **Secrets stay redacted.** gitleaks runs with `--redact`; a credential
  finding's snippet is cleared before it is stored, and cleared again before an
  exported report, a GitHub issue or the dashboard shows it. `suggest_fix`
  never reads a credential finding's file back. The one exception is opt-in:
  `verify_live` (below) reads the value from a private temporary report, sends
  it only to its own provider, and deletes the report.
- **A project cannot switch the protective hooks off.** In a project's
  `.guardian/hooks.config.json`, `enabled: false`, `bash.block: false` and
  `bash.warn: false` are ignored (SessionStart tells the model so), and there is
  no project-level switch for install vetting; only advisory settings
  (`secrets.warn`, `sessionStart`, `ignorePaths`) and stricter ones take
  effect. Switching a protective hook off takes the user-level
  `~/.config/dev-guardian/hooks.json` or the environment (`GUARDIAN_HOOKS=off`,
  `GUARDIAN_HOOKS_BASH_BLOCK=0`, `GUARDIAN_PKG_VET=0`). The write guard denies
  an assistant's `Write` / `Edit` / `MultiEdit` of any hook configuration file,
  and the shell guard denies what it can see a command do to one: write it
  (`>`, `tee`, `sed -i`, `perl -pi`, `rsync`, `cp` / `mv` onto it, PowerShell
  `Set-Content` / `[IO.File]::WriteAllText`, cmd `>` inside `cmd /c "…"`, …),
  remove or move it away, copy a directory onto `.guardian` or
  `~/.config/dev-guardian`, or name it in program text on the command line
  (`node -e`, `python -c`, a heredoc fed to `python`), relative paths resolved
  after a `cd`. A program run from a file is not seen, which matters only for
  the user-level file ([docs/hooks.md](docs/hooks.md) lists what else is not).
  A project's `ignorePaths` and `.guardian/hooks-allowlist.json` narrow the
  secret warning only, never a secret block the user enabled. Each hook
  configuration file is first checked, component by component with `lstat` +
  `readlink`, for a link to a network or device path (`\\host\share`), which
  is refused unopened; it is then opened (non-blocking where the OS allows) and
  judged by `fstat` on what was opened: only a regular file of at most 64 KiB
  is read, so a FIFO, a link to `/dev/zero`, a Windows link to a named pipe or
  to an unreachable share in its place no longer hangs the hook into its 15 s
  timeout — which used to let the tool call run unguarded — and the shell
  guard denies creating one there. The install hook reads its registry
  configuration (`.npmrc`, `pip.conf`, `nuget.config`, …) through the same
  link walk; one that is there but could not be read counts as possibly a
  private registry, so a missing name warns. **Claude Code's own settings**: an assistant's `Write` / `Edit` /
  `MultiEdit` of `.claude/settings.json` or `settings.local.json` is denied
  when it would newly set `disableAllHooks`, an `env` entry setting
  `GUARDIAN_HOOKS=off`, `GUARDIAN_HOOKS_BASH_BLOCK=0` or `GUARDIAN_PKG_VET=0`,
  or an `enabledPlugins` entry turning dev-guardian off; every other edit of
  those files is allowed. A shell write of them is denied when the command
  names one of those keys, and so is `claude plugin disable|uninstall` of
  dev-guardian.
  See [docs/hooks.md](docs/hooks.md).
- **Least privilege.** The MCP server reads and writes within the target project
  and its `.guardian/` directory, plus the temporary directories and user cache
  listed in [mcp/README.md](mcp/README.md#what-the-server-writes).

## Network egress

`GUARDIAN_OFFLINE=1` stops the lookups dev-guardian makes on its own initiative
— marked ★ below: threat intelligence, package vetting, `scan_skill`'s OSV
lookup, live secret verification, the Wordfence / wordpress.org feed and
`scan_containers`' cosign check of an image's signature. What could not be checked
is then reported as `unknown` or as a coverage gap, never as clean. It does
**not** stop a request to a target you named (DAST, a skill URL, a Lighthouse
URL), anything a third-party scanner or build tool does on its own, or the
project's own build and test commands.

### Requests dev-guardian makes

| Destination | Who contacts it | When |
| --- | --- | --- |
| `api.osv.dev` | `vet_packages` ★, the install hook ★, `scan_skill` with `check_deps` ★ (offline, `osv.dev` reads `skipped`) | per call |
| `registry.npmjs.org`, `pypi.org`, `repo.packagist.org`, `api.nuget.org`, `azuresearch-usnc.nuget.org` | `vet_packages` ★, the install hook ★ (3 s budget) | per call; the hook only for a command that installs a package by name |
| `www.cisa.gov` (KEV catalog), `api.first.org` (EPSS) | `prioritize_findings` ★, `risk_score` ★, `create_fix_pr` ★ | at most once per 24 h per CVE and for the catalog; `guardian://cves/active` only reads the cache |
| The secret's own provider: `api.github.com`, `gitlab.com`, `slack.com`, `api.stripe.com`, `api.openai.com`, `api.anthropic.com`, `registry.npmjs.org`, `api.sendgrid.com` | `scan_secrets` with `verify_live: true` ★ | **off by default**. Each secret goes only to its own provider's read-only identity endpoint (a fixed URL per rule, never a host from the repository), 5 s timeout, at most 4 in flight and 50 per scan; `security_scan_full` never verifies |
| `www.wordfence.com`, `api.wordpress.org` | `wp_vuln_check_source` ★ | Wordfence only with `WORDFENCE_API_KEY`; the feed is cached for 24 h |
| The target you name | `scan_dast` (loopback only unless `authorized_target: true`), `wp_rest_audit`, the CLI's DAST health check | per call |
| The URL you name | `scan_skill` given an HTTP(S) or git URL | per call |

### Requests the scanners and tools dev-guardian runs make

| Destination | Who triggers it | When |
| --- | --- | --- |
| Semgrep registry (`semgrep.dev`) — rules download **and usage metrics to Semgrep Inc.** | `scan_sast` and `security_scan_full` (`--config=auto`), `review_pr`, `bug_hunt` (`p/r2c-bug-scan`, `p/security-audit`, optional language packs), `scan_wordpress` (`p/php`, `p/wordpress`), `init_project`'s first-pass status report (`semgrep --config=auto`, when a bash is available) | by default. Semgrep refuses `--config=auto` with metrics off, so `scan_sast`, `security_scan_full`, `review_pr` and the CLI's `--local-only` offer `local_only: true`: only rules on disk, `--metrics=off`, nothing sent to Semgrep's registry or metrics endpoint. `bug_hunt` and `scan_wordpress` have no local-only mode. Semgrep's `--metrics=auto` also sends metrics with local rules when you are logged in to Semgrep, which is how `map_attack_surface` can send them. What Semgrep collects: <https://semgrep.dev/docs/metrics>. `compliance_check` (RGPD pack) and `create_fix_pr`'s autofix always run with `--metrics=off`. |
| Semgrep's version check (Semgrep servers) | every Semgrep run — `local_only` and `check_toolchain`'s `semgrep --version` included | on by default in Semgrep; dev-guardian does not turn it off. `SEMGREP_ENABLE_VERSION_CHECK=0` in the server's environment does. |
| The project's NuGet feeds, and its MSBuild code | `scan_sast` on a .NET project (`dotnet restore --locked-mode`, then `dotnet build`) — **even with `local_only: true`** — and so `security_scan_full`, the CLI `scan` and `create_fix_pr`'s re-scans; `deps_audit` and `deps_update_plan` (`dotnet restore`, `dotnet list package`) | when the .NET SDK is installed: for `scan_sast`, whenever a root `.csproj` / `.fsproj` / `.sln` / `.slnx` is present; for `deps_audit` and `deps_update_plan`, for every `.sln` / `.csproj` they find. A restore and a build execute the project's own MSBuild targets. |
| Docker registry (`semgrep/semgrep` image) | `scan_sast`, `map_attack_surface` | only when Semgrep is not installed and Docker is |
| Trivy's vulnerability database and misconfiguration checks bundle | `scan_deps`, `deps_audit`, `scan_containers`, `scan_iac`, `review_pr`, `scan_wordpress`, `init_project`'s status report | when Trivy needs them and its local cache is stale; `scan_containers` may also pull the image it is given |
| The image's registry, and Sigstore's public-good trust root (`tuf-repo-cdn.sigstore.dev`) — Rekor (`rekor.sigstore.dev`) only for a signature that carries no inclusion proof | `scan_containers` given an `image`, which runs cosign ★: `cosign triangulate` (to pin the digest), then `cosign tree`, `cosign download signature` and `cosign download attestation` without a signer, `cosign verify` with `signer_identity` + `signer_issuer` (Sigstore's trust root is fetched for `verify` only) | per call, when cosign is installed; `GUARDIAN_OFFLINE=1` starts no cosign at all (`cosign` is then skipped and in `missing_tools`). cosign reads registry credentials from the Docker config, like Trivy, and keeps its trust root under `~/.sigstore`. It never signs, attests or pushes anything. |
| Maven Central | Trivy, for a `pom.xml` (in the tools above) | when it resolves Maven dependencies |
| Package registries, through the package managers | `deps_audit` (`npm audit`; `pip-audit`, which installs the requirements into a temporary virtualenv from PyPI), `deps_update_plan` (`npm outdated`, `composer outdated`, `bundle outdated`, `go list -m -u`, `cargo outdated`), `create_fix_pr` (installs in its worktree with `--ignore-scripts` / `--no-scripts`) | per call |
| The project's own test command and whatever it fetches | `create_fix_pr` runs `npm test`, `pytest`, `cargo test` or `go test ./...` in its worktrees (`cargo` and `go` download the project's dependencies; `npm ci --ignore-scripts` runs first when there is a lock file) | only for a candidate fix, dry runs included |
| nuclei's update check and templates | `scan_dast` with `use_nuclei` | nuclei's own automatic update check and template download are on by default; dev-guardian does not pass `-disable-update-check` |
| Syft's update check (Anchore) | `generate_sbom` | Syft's `check-for-app-update` defaults to true; `SYFT_CHECK_FOR_APP_UPDATE=false` in the server's environment turns it off |
| The GitHub API | `scan_iac`'s zizmor, when a GitHub token (`GH_TOKEN`) is in the server's environment | zizmor's online audits; without a token it runs offline |
| WPScan API, and the site itself | `wp_vuln_check` (through the `wpscan` CLI) | per call |
| `api.wordpress.org` | `wp_audit`, `bulk_audit_wordpress_sites` (WP-CLI `verify-checksums`) | per call |
| The target you name | `perf_check` (Lighthouse URL, k6 script) | per call |
| GitHub, through `gh` and `git` | `create_github_issues`, `create_fix_pr` with `apply: true` | only when asked; dry runs push nothing |
| Package managers and install scripts (winget, scoop, choco, apt, brew, pipx, npm, uv, cargo, go, curl from GitHub releases) | `install_toolchain` | only when asked; `dry_run` prints the commands |
| The dev-guardian repository (`git ls-remote`) | `dev-guardian ci-init` | only when the release tag is not in the local checkout |
| Sigstore (Fulcio, Rekor — or GitHub's own Sigstore instance for a private repository) and GitHub's attestations API | the pipeline `dev-guardian ci-init github --attest` generates, from your CI runner — `ci-init` itself contacts neither | on a push, in the generated `attest` job only: it signs a build-provenance attestation of the two report files with the job's OIDC identity. Only that job holds `id-token: write`. |

`map_attack_surface` itself sends nothing, but the Semgrep it runs does what
the rows above say: its version check, and metrics when you are logged in. The
hooks' SessionStart and secret-warning branches, `detect_stack`,
`audit_agent_config`, `observability_setup`, the `status` and `dashboard` CLI
commands and the history readers (`diff_scans`, `set_baseline`,
`suppress_finding`, `regression_alert`, `triage_findings`, `health_status`,
the resources) make no network request.
