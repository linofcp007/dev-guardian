# Supported stacks, scanners and platforms

**Stacks.** JavaScript / TypeScript (npm, yarn, pnpm, bun), Python (pip, poetry, uv), PHP (composer, WordPress
included), Go, Rust, Ruby, Java / Kotlin (maven, gradle), C# / .NET, C / C++ (cppcheck; a `compile_commands.json`
when the project has one), shell scripts, Docker and compose, IaC (Terraform,
Kubernetes, Ansible, CloudFormation, Helm), GitHub Actions. Polyglot projects are supported.

**Run by the MCP tools.** Semgrep, Trivy, gitleaks, Syft, Bandit, gosec, govulncheck, cppcheck, Psalm, shellcheck, ruff, radon, jscpd, ESLint (when the project
has it), staticcheck, hadolint, cosign, Lighthouse, k6, nuclei, PHPCS, WP-CLI, WPScan, the .NET SDK analyzers,
OSV.dev.

**Recommended, configured by hand** (no tool runs them): Renovate (`init_project` installs `renovate.json`),
GlitchTip / Sentry, Prometheus + Grafana, Uptime Kuma, Artillery, Playwright.

**Platforms.** Linux, macOS and Windows. `check_toolchain {}` shows what is installed and this system's install
command; `install_toolchain { dry_run: true }` shows the plan — the scripts in `scripts/install/` on Linux and
macOS, winget, scoop or choco on Windows (or WSL). Syft, Trivy and gitleaks come from a pinned release with a
verified sha256 (on Windows, a ZIP downloaded by PowerShell into `%USERPROFILE%\.local\bin`, where dev-guardian
looks for them even outside `PATH`); on macOS, Syft and gitleaks come from Homebrew first.
