# Security Policy

dev-guardian is a security tool, so we hold its own code to the bar it enforces.

## Supported versions

The latest minor release on the `main` branch receives security fixes. Older
tags are not patched — upgrade to the newest release.

| Version | Supported |
| ------- | --------- |
| 0.6.x   | ✅        |
| < 0.6   | ❌        |

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

- **Local-only, no telemetry.** Scanners run on your machine; results persist
  to `.guardian/guardian.db`. Reports are self-contained and load no external
  assets.
- **No runtime network** except explicit CVE lookups (OSV.dev) and any scanner
  you invoke.
- **Least privilege.** The MCP server reads/writes within the target project
  and its `.guardian/` directory.
