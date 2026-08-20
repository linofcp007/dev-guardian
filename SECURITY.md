# Security Policy

dev-guardian is a security tool, so we hold its own code to the bar it enforces.

## Supported versions

The latest minor release on the `main` branch receives security fixes. Older
tags are not patched — upgrade to the newest release.

| Version | Supported |
| ------- | --------- |
| 1.0.x   | ✅        |
| < 1.0   | ❌        |

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

In scope: the MCP server (`mcp/`), the `bin/` CLI, the skills and slash
commands, the bundled configs, and the supply-chain logic in `scan_skill`.

Out of scope: vulnerabilities in the third-party scanners dev-guardian
orchestrates (Semgrep, Trivy, gitleaks, Syft, WPScan, …) — report those to
their respective projects.

## Hardening posture

- **dev-guardian sends no telemetry of its own.** Scanners run on your machine;
  results persist to `.guardian/guardian.db` and never leave it. Reports are
  self-contained and load no external assets.
- **Semgrep does send telemetry, in the default SAST mode, and this used to be
  stated here as "no telemetry" without qualification.** `scan_sast` runs
  `semgrep --config=auto`, which fetches its ruleset from the Semgrep registry
  and reports usage metrics to Semgrep Inc. as a *condition* of doing so:
  passing `--metrics=off` alongside `--config=auto` fails outright with
  "Cannot create auto config when metrics are off". What Semgrep collects is
  documented at <https://semgrep.dev/docs/metrics>; dev-guardian neither adds
  to it nor sees it.

  To scan with nothing leaving the machine, pass `local_only: true` to
  `scan_sast`. That drops `--config=auto`, adds `--metrics=off`, and runs only
  rules already on disk — your project's own `.semgrep.yml` and anything added
  with `register_custom_rules`. Fewer rules than the default; no network, no
  metrics. The shipped pre-commit hook has the same trade-off, documented
  inline in `configs/pre-commit/pre-commit-config.yaml`.
- **No other runtime network** except explicit CVE lookups (OSV.dev) and any
  scanner you invoke.
- **Least privilege.** The MCP server reads/writes within the target project
  and its `.guardian/` directory.
