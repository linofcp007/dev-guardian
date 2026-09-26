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
- **The hooks cannot be switched off by the thing they guard.** A project's
  `.guardian/hooks.config.json` may only make them stricter, and an assistant's
  edit of any hook configuration file is denied. See [docs/hooks.md](docs/hooks.md).
- **Least privilege.** The MCP server reads and writes within the target project
  and its `.guardian/` directory, plus the temporary directories and user cache
  listed in [mcp/README.md](mcp/README.md#what-the-server-writes).

## Network egress

`GUARDIAN_OFFLINE=1` stops the lookups dev-guardian makes on its own initiative
— marked ★ below: threat intelligence, package vetting, live secret
verification and the Wordfence / wordpress.org feed. What could not be checked
is then reported as `unknown` or as a coverage gap, never as clean. It does
**not** stop a request to a target you named (DAST, a skill URL, a Lighthouse
URL) or anything a third-party scanner does on its own.

| Destination | Who contacts it | When |
| --- | --- | --- |
| Semgrep registry (`semgrep.dev`) — rules download **and usage metrics to Semgrep Inc.** | `scan_sast` and `security_scan_full` (`--config=auto`), `review_pr`, `bug_hunt` (`p/r2c-bug-scan`, `p/security-audit`, optional language packs), `scan_wordpress` (`p/php`, `p/wordpress`) | by default. Semgrep refuses `--config=auto` with metrics off, so `scan_sast`, `security_scan_full`, `review_pr` and the CLI's `--local-only` offer `local_only: true`: only rules on disk, `--metrics=off`, nothing sent. `bug_hunt` and `scan_wordpress` have no local-only mode. What Semgrep collects: <https://semgrep.dev/docs/metrics>. `compliance_check` (RGPD pack) and `create_fix_pr`'s autofix always run with `--metrics=off`. |
| Docker registry (`semgrep/semgrep` image) | `scan_sast`, `map_attack_surface` | only when Semgrep is not installed and Docker is |
| Trivy's vulnerability database and misconfiguration checks bundle | `scan_deps`, `deps_audit`, `scan_containers`, `scan_iac`, `review_pr`, `scan_wordpress` | when Trivy needs them and its local cache is stale; `scan_containers` may also pull the image it is given |
| `api.osv.dev` | `vet_packages` ★, the install hook ★, `scan_skill` with `check_deps` | per call |
| `registry.npmjs.org`, `pypi.org`, `repo.packagist.org`, `api.nuget.org`, `azuresearch-usnc.nuget.org` | `vet_packages` ★, the install hook ★ (3 s budget) | per call; the hook only for a command that installs a package by name |
| Package registries, through the package managers | `deps_audit` (`npm audit`; `pip-audit`, which installs the requirements into a temporary virtualenv from PyPI; `dotnet restore`, which contacts the project's own NuGet feeds and runs its MSBuild), `deps_update_plan` (`npm outdated`, `composer outdated`, `bundle outdated`, `go list -m -u`, `cargo outdated`, `dotnet`), `create_fix_pr` (installs in its worktree with `--ignore-scripts` / `--no-scripts`) | per call |
| `www.cisa.gov` (KEV catalog), `api.first.org` (EPSS) | `prioritize_findings` ★, `risk_score` ★, `create_fix_pr` ★ | at most once per 24 h per CVE and for the catalog; `guardian://cves/active` only reads the cache |
| The secret's own provider: `api.github.com`, `gitlab.com`, `slack.com`, `api.stripe.com`, `api.openai.com`, `api.anthropic.com`, `registry.npmjs.org`, `api.sendgrid.com` | `scan_secrets` with `verify_live: true` ★ | **off by default**. Each secret goes only to its own provider's read-only identity endpoint (a fixed URL per rule, never a host from the repository), 5 s timeout, at most 4 in flight and 50 per scan; `security_scan_full` never verifies |
| `www.wordfence.com`, `api.wordpress.org` | `wp_vuln_check_source` ★ | Wordfence only with `WORDFENCE_API_KEY`; the feed is cached for 24 h |
| WPScan API, and the site itself | `wp_vuln_check` (through the `wpscan` CLI) | per call |
| `api.wordpress.org` | `wp_audit`, `bulk_audit_wordpress_sites` (WP-CLI `verify-checksums`) | per call |
| The target you name | `scan_dast` (loopback only unless `authorized_target: true`; optional nuclei), `wp_rest_audit`, `perf_check` (Lighthouse URL, k6 script), the CLI's DAST health check | per call |
| The URL you name | `scan_skill` given an HTTP(S) or git URL | per call |
| GitHub, through `gh` and `git` | `create_github_issues`, `create_fix_pr` with `apply: true` | only when asked; dry runs push nothing |
| Package managers and install scripts (winget, scoop, choco, apt, brew, pipx, npm, uv, cargo, go, curl from GitHub releases) | `install_toolchain` | only when asked; `dry_run` prints the commands |
| The dev-guardian repository (`git ls-remote`) | `dev-guardian ci-init` | only when the release tag is not in the local checkout |

The hooks' SessionStart and secret-warning branches, `detect_stack`,
`map_attack_surface` (with native Semgrep), `audit_agent_config`,
`observability_setup`, the dashboard and every history or reporting tool make
no network request.
