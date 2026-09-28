# dev-guardian

**English** · [Português (pt-PT)](README.pt-PT.md) · [Español](README.es.md)

An open-source security, bug-finding, code-quality, dependency, compliance, observability and performance toolkit for Claude Code and Cowork — and, through its MCP server, for any MCP-capable AI host. It drives open-source scanners (Semgrep, Trivy, gitleaks, Syft, …), keeps every result in a local SQLite database so baselines, deltas and suppressions survive between sessions, and says so when a scanner did not run instead of reporting "0 findings". It also vets third-party AI skills and MCP servers, and the packages an agent is about to install, before they reach your machine.

Trilingual: the skills and commands answer in English, Portuguese or Spanish, whichever you write in.

## What's inside

- **13 skills** and **10 slash commands** for Claude Code / Cowork (below).
- An **MCP server** with **57 tools** and **18 resources**, TypeScript on `node:sqlite`, committed pre-built — full reference in [docs/tools.md](docs/tools.md).
- **150 Semgrep rules in 11 packs** written for this project: bug classes for seven languages, an RGPD/GDPR pack, a route-inventory pack for nine languages, and an LLM-application pack (model output reaching eval/shell/SQL, remote code in a model load, prompt injection surface, no token cap) that `scan_sast` runs — see [docs/rule-packs.md](docs/rule-packs.md).
- **Guardrail hooks** that deny catastrophic shell commands, vet packages at install time and warn on secrets as they are written — see [docs/hooks.md](docs/hooks.md).
- A **CLI** (`cli/dev-guardian.mjs`) for CI gating, host setup, a terminal status view and an HTML dashboard.

## Requirements

- **Node.js ≥ 22.13.** The database is Node's built-in `node:sqlite`, used without any flag. On an older Node the server exits with `dev-guardian requires Node.js >= 22.13 (node:sqlite)`.
- **git.**
- **The scanners you want to use**, installed separately. `check_toolchain` reports what is present (and flags the compromised Trivy 0.69.4–0.69.6); `install_toolchain` or `/guardian-init` installs the rest. A scanner that is missing is reported as a coverage gap, never as a clean result.
- **Optional: Docker.** Without a native `semgrep`, `scan_sast` and `map_attack_surface` fall back to the `semgrep/semgrep` image.
- **Windows:** every scan runs natively, with no shell. A bash is needed only for `init_project`'s first-pass status report and for `install_toolchain`'s WSL fallback when none of winget, scoop or choco is present. dev-guardian looks for Git Bash first, then WSL, then any `bash` on `PATH`.

Nothing needs `npm install`: `mcp/dist/server.js` is committed as a self-contained bundle. Only the CLI's `scan` and `baseline update` need `npm ci --omit=dev` in `mcp/` once, for their runtime packages.

## Quick start (Claude Code)

```text
/plugin marketplace add https://github.com/linofcp007/dev-guardian
/plugin install dev-guardian@dev-guardian
```

Then, in your project:

```text
/guardian-init        detect the stack, install scanners, write configs and pre-commit hooks
/guardian-scan        full security scan (or --staged, --branch, --since …)
/guardian-status      one-screen health view
```

From a local clone instead: `claude --plugin-dir /path/to/dev-guardian` for one session, or `/plugin marketplace add /path/to/dev-guardian` to install it. Every skill also fires on plain language — "audit the project", "is this safe to ship?", "vê se há vulnerabilidades", "¿hay agujeros de seguridad?".

## Slash commands

| Command | Modes | What it does |
| --- | --- | --- |
| `/guardian-scan` | none, `--staged`, `--uncommitted`, `--unpushed`, `--branch [base]`, `--since <ref>`, `--incoming`, paths | Security scan of the whole project, or only of what changed |
| `/guardian-fix` | hint, fingerprint, `--pr [--apply]`, `--verify` | Find and fix bugs, open verified fix PRs, prove a fix with a re-scan |
| `/guardian-report` | `exec`, `handoff`, `trend`, `debt`, `changelog`, `soc2` | Reports from the scan history |
| `/guardian-incident` | `panic`, `leak`, `rollback`, `postmortem` | Incident response |
| `/guardian-release` | `predeploy`, `prerelease` | Go / no-go gates |
| `/guardian-status` | optional focus (e.g. "only security") | Latest scan, deltas, baseline, expiring suppressions |
| `/guardian-infra` | `docker`, `iac` | Dockerfile, image, compose, Terraform, Kubernetes, CloudFormation, Helm |
| `/guardian-wp` | install path or site URL | WordPress audit |
| `/guardian-dotnet` | project or solution path | C# / .NET audit |
| `/g` | what you want checked | Alias of the `guardian` router skill |

Version 2.0.0 had 48 of them; `CHANGELOG.md` maps every old name to its replacement.

## Skills

| Skill | For |
| --- | --- |
| `/guardian` | Router: picks the right command or skill |
| `/guardian-security` | SAST, secrets, dependency CVEs, IaC, DAST and reachability, with triage |
| `/guardian-bugfix` | Implementation bugs, found and fixed methodically |
| `/guardian-init` | First run in a project: toolchain, configs, pre-commit |
| `/guardian-review` | Senior-style review before a PR, merge or deploy |
| `/guardian-deps` | CVE audit, upgrade plan and PRs, install vetting, licences, SBOM |
| `/guardian-quality` | Duplication, complexity, tech debt, `.guardian/budgets.yml` |
| `/guardian-compliance` | RGPD/GDPR, licences, SBOM, audit evidence, cookie banner and privacy policy templates |
| `/guardian-observability` | Structured logging and metrics |
| `/guardian-performance` | Lighthouse, k6, performance budgets |
| `/guardian-grill` | Grills you on a diff's decisions before merge |
| `/guardian-improve` | Turns measured tech debt into improvement specs |
| `/guardian-scanskill` | Vets a third-party skill, MCP server or agent before install |

## The MCP server

| Area | Tools |
| --- | --- |
| Security scans | `security_scan_full`, `scan_sast`, `scan_secrets`, `scan_deps`, `scan_containers`, `scan_iac`, `review_pr` |
| Bugs and quality | `bug_hunt`, `quality_check`, `suggest_fix`, `create_fix_pr` |
| Dependencies and supply chain | `deps_audit`, `deps_update_plan`, `vet_packages`, `generate_sbom`, `sbom_diff`, `license_compatibility`, `scan_skill`, `audit_agent_config` |
| Attack surface | `map_attack_surface`, `scan_dast`, `validate_finding` |
| History and triage | `diff_scans`, `set_baseline`, `suppress_finding`, `regression_alert`, `risk_score`, `prioritize_findings`, `triage_findings`, `health_status` |
| Reports | `audit_executive`, `report_export`, `compliance_check`, `compliance_evidence`, `create_github_issues` |
| Setup and ops | `detect_stack`, `check_toolchain`, `install_toolchain`, `init_project`, `precommit_install`, `register_custom_rules`, `observability_setup`, `perf_check` |
| WordPress | `scan_wordpress`, `wp_audit`, `wp_vuln_check`, `wp_vuln_check_source`, `wp_plugin_check`, `wp_cron_audit`, `wp_rest_audit`, `wp_recommend_hardening`, `wp_describe_setup`, `bulk_audit_wordpress_sites` |
| C# / .NET | `scan_dotnet_secrets`, `dotnet_target_framework_check`, `dotnet_efcore_audit`, `dotnet_describe_setup` |

Resources (`guardian://scans/latest`, `guardian://findings/open`, `guardian://cves/active`, `guardian://surface/latest`, …) serve the stored results as JSON. Everything persists in `.guardian/guardian.db`; the server keeps `.guardian/` out of git except `.guardian/baseline.json`, which CI needs committed.

## What each stack gets

| Stack | Detected | Bug rules (`bug_hunt`) | Routes (`map_attack_surface`) | Dependency CVEs | Reachability (`validate_finding`) |
| --- | --- | --- | --- | --- | --- |
| JavaScript / TypeScript | yes | 13 rules | Express, NestJS | Trivy, `npm audit` | reachable / unreachable |
| Python | yes | 10 rules | Flask, FastAPI, Django | Trivy, `pip-audit` | reachable / unreachable |
| Go | yes | 9 rules | net/http, gin, chi | Trivy | reachable / unreachable |
| Rust | yes | 1 rule (blocking sleep in `async fn`) | actix-web | Trivy | reachable / unreachable |
| Java | yes | 7 rules | Spring | Trivy (Maven; Gradle only with a `gradle.lockfile`) | reachable / unknown only |
| C# / .NET | yes | 11 rules | ASP.NET Core | Trivy, `dotnet list package --vulnerable` | reachable / unknown only |
| PHP | yes, also without `composer.json` | 6 rules | Laravel | Trivy (`composer.lock`) | reachable / unknown only |
| WordPress | yes, with WooCommerce and Kadence | the PHP rules, plus `p/wordpress` in `scan_wordpress` | REST routes | WPScan (live URL), Wordfence feed (from source) | as PHP |
| Ruby | yes | none — use RuboCop | Rails-style routes | Trivy (`Gemfile.lock`) | reachable / unknown only |
| Kotlin | **detection only** | — | — | — | — |

Beyond the table, `scan_sast` runs Semgrep's registry ruleset (`--config=auto`), which picks rules for whatever languages it finds — Kotlin included — and gitleaks scans every project for secrets. Containers and IaC (Dockerfile, images, compose, Terraform, Kubernetes, CloudFormation, Helm, GitHub Actions workflows) are covered by `scan_containers` and `scan_iac`. "Reachable / unknown only" means the tool never claims code is unreachable in a language that resolves code at runtime (autoload, annotations, DI containers). `.NET` also has four dedicated tools; WordPress has ten. Trivy reads a Gradle lock file for any project, Kotlin included, and a Gradle build it could not read is a named coverage gap; no bug rule or route extractor exists for Kotlin.

**Gradle and Python need a lock file for Trivy.** Trivy reads Gradle dependencies only from `gradle.lockfile`, and Python ones only from `poetry.lock`, `uv.lock`, `Pipfile.lock` or a pinned `requirements.txt`. A `build.gradle` / `build.gradle.kts`, `pyproject.toml`, `setup.py` / `setup.cfg`, `Pipfile` or `requirements*.txt` it could not read is reported as a coverage gap (`trivy:gradle`, `trivy:python`, or `trivy` skipped when it read nothing else), never as a clean scan. Generate the lock file to close it. For Gradle, first enable `dependencyLocking { lockAllConfigurations() }` in the build — without it `gradle dependencies --write-locks` writes nothing — then run that command. For Python, run `poetry lock`, `uv lock` or `pipenv lock`, or pin every dependency in `requirements.txt`.

## Guardrail hooks

Loaded automatically with the plugin, dependency-free and fail-open:

- **SessionStart** — a short security-posture briefing.
- **PostToolUse** on writes — warns, with a redacted preview, when a secret is written.
- **PreToolUse** on Bash and PowerShell — denies catastrophic commands (`rm -rf /`, `curl … | sh`, `iwr … | iex`, raw-disk writes, fork bombs), warns on risky ones, and vets packages before `npm`, `pnpm`, `yarn`, `bun`, `pip`, `uv`, `poetry`, `composer` or `dotnet add package` installs them: a malicious package is denied, a nonexistent one is denied only in a plain, single install command.
- **PreToolUse** on writes — denies an assistant's edit of the hook configuration itself; optionally blocks writing a provider token.

A project's `.guardian/hooks.config.json` can only make these stricter; switching one off takes the user-level config or an environment variable.

Details, configuration and the escape hatches: [docs/hooks.md](docs/hooks.md). The same detectors run from a terminal with `node cli/dev-guardian.mjs check --file <path>` or `--bash "<command>"`.

## Other AI hosts

Cursor, Windsurf, GitHub Copilot, Codex CLI, Gemini CLI, Cline and Claude Desktop get the MCP server and a rules file (no skills, commands or hooks). Clone once, then run the CLI **by its absolute path** from your project:

```text
git clone --depth 1 --branch v3.0.0 https://github.com/linofcp007/dev-guardian.git ~/tools/dev-guardian
node ~/tools/dev-guardian/cli/dev-guardian.mjs mcp-config cursor --write
node ~/tools/dev-guardian/cli/dev-guardian.mjs mcp-config all --write --update-mcp
```

The clone above pins 3.0.0; to follow a later release, clone its `vX.Y.Z` tag instead. `--update-mcp`, `--global` and `ci-init` need 3.0.0 or later — 2.0.0 also writes the global Windsurf and Claude Desktop configs on `mcp-config all --write`. The CLI fills in absolute paths, merges instead of overwriting, and manages only a delimited block inside `AGENTS.md`-style files; `--update-mcp` refreshes an entry that is out of date. Per-host paths and manual snippets: [docs/hosts.md](docs/hosts.md).

## CI

```text
npm ci --omit=dev --prefix ~/tools/dev-guardian/mcp                                  # once: runtime packages for scan
node ~/tools/dev-guardian/cli/dev-guardian.mjs ci-init github --write                # also gitlab, bitbucket
node ~/tools/dev-guardian/cli/dev-guardian.mjs baseline update --project .           # commit .guardian/baseline.json
node ~/tools/dev-guardian/cli/dev-guardian.mjs scan --project . --fail-on high --sarif results.sarif
```

`ci-init` generates a pipeline with every action pinned by commit SHA and every scanner by version and checksum. `scan` exits 0 on a pass, 1 when a finding new to the baseline reaches `--fail-on`, **2 when a scanner did not run** (never read that as a pass) and 3 on a usage error. See [docs/ci.md](docs/ci.md). Run these from your project, with the path of your clone (the plugin's own copy works too). For a local view: `status` and `dashboard` (a self-contained HTML page, no network).

## Privacy and network

dev-guardian sends no telemetry of its own. Some tools do reach the network — Semgrep's registry mode (which sends usage metrics to Semgrep Inc.; `local_only: true` avoids it) and its version check, Trivy's database, a .NET project's NuGet feeds (`scan_sast` restores and builds it, `local_only` or not), OSV, package registries, CISA KEV / FIRST EPSS, Wordfence, and opt-in live secret verification. The complete list, per tool, is in [SECURITY.md](SECURITY.md). `GUARDIAN_OFFLINE=1` switches off the lookups dev-guardian makes on its own (threat intelligence, package vetting, live secret verification, the Wordfence feed); every environment variable is in [docs/env.md](docs/env.md).

## Troubleshooting

**The MCP server does not connect.** `/mcp` in Claude Code shows the server's state. Claude Code logs each server's stderr under its cache directory: `%LOCALAPPDATA%\claude-cli-nodejs\Cache\<project>\mcp-logs-<server>\` on Windows (the plugin's is `mcp-logs-plugin-dev-guardian-dev-guardian`), and — by the same convention, not verified here — `~/.cache/claude-cli-nodejs/…` on Linux and `~/Library/Caches/claude-cli-nodejs/…` on macOS. The usual causes:

- Node older than 22.13 (see Requirements).
- A project `.mcp.json` that uses `${CLAUDE_PROJECT_DIR}`: Claude Code does not expand it there, so `node` receives the literal string. Use a relative path; project servers start in the project root.

**`no_bash_shell`.** Only `install_toolchain`'s default install on Linux and macOS needs bash, plus `init_project`'s status report. On Windows, install Git for Windows. From PowerShell, `bash` may resolve to the WSL launcher stub rather than Git Bash; dev-guardian probes Git Bash first on its own, but a command you type yourself may not.

**Coverage `none` or `partial`, or `scan` exits 2.** A scanner was missing, failed, or scanned nothing. `tools_run` and `missing_tools` in the response name it; `check_toolchain` shows what is installed. Fix that and re-run — a scan with a gap is never served from the cache.

**`install_toolchain` with `elevation_allowed: true` fails with "sudo: a terminal is required to read the password".** Install steps run detached, with no terminal, so on Linux and macOS elevation only works with passwordless sudo for those commands. Otherwise run the commands listed under `requires_elevation` yourself. The .NET SDK is never installed automatically.

**Semgrep sends metrics.** The default `scan_sast` uses `--config=auto`, which Semgrep only allows with metrics on. Pass `local_only: true` (or `--local-only` on the CLI) to run only the rules on disk with `--metrics=off`.

## Repository layout

```text
.claude-plugin/   plugin.json + marketplace.json
commands/         the 10 slash commands
skills/           the 13 skills
hooks/            hooks.json + guardian-hook.mjs
cli/              dev-guardian.mjs (mcp-config, check, scan, baseline, ci-init, status, dashboard)
mcp/              the MCP server: src/, test/, dist/ (committed)
configs/          Semgrep packs, CI templates, gitleaks/Renovate/pre-commit configs, compliance templates
host-rules/       rules templates for other hosts
docs/             tools, rule packs, hooks, CI, hosts, environment
scripts/          install-linux.sh, install-macos.sh, initial-scan.sh
```

Contributing: [CONTRIBUTING.md](CONTRIBUTING.md) and [CLAUDE.md](CLAUDE.md). Security reports: [SECURITY.md](SECURITY.md).

## License

MIT. Carlos Pereira · [prodigitalkey.com](https://prodigitalkey.com)
