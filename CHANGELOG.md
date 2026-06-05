# Changelog

All notable changes to dev-guardian are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses
[Semantic Versioning](https://semver.org/). Until 1.0 the surface may still
change; breaking changes are called out per release.

## [0.6.0] — 2026-06-05

### Added

- `mcp-config` CLI (`bin/dev-guardian.mjs`) — bootstrap dev-guardian into any AI
  host from a plain terminal, with the absolute server path filled in. Prints a
  paste-ready block or, with `--write`, merges it into the project.
- `mcp/src/hostsetup/setup.ts` — context-free host-setup core (`setupHost`,
  `previewMcpConfig`) shared by the CLI.

### Removed

- **BREAKING:** the `install_host_context` MCP tool. Use the `mcp-config` CLI
  instead. MCP tool count: 51 → 50.

## [0.5.1] — 2026-06-05

### Added

- In-repo AI host configs (dogfooding): `.mcp.json`, `.cursor/`, `.gemini/`,
  `.vscode/`, `.windsurf/`, `.github/copilot-instructions.md`, root `AGENTS.md`
  / `GEMINI.md`, and a `CLAUDE.md` contributor guide. Open the repo in any host
  and the MCP server + rules load out of the box (relative paths).

## [0.5.0] — 2026-06-05

### Added

- Branded Pro Digital Key HTML reports for `report_export` and
  `/guardian-report`: a self-contained shell with a dark/light toggle (system
  default, persisted), 100% offline, print-friendly, and trilingual chrome via
  a `lang` input.

### Changed

- **BREAKING:** `report_export` default format changed from `html` to
  `markdown`. `html` / `sarif` / `json` remain available explicitly.

## [0.4.0] — 2026-06-05

### Added

- Multi-host MCP installer: register the server (merging, never clobbering) plus
  the rules file across Cursor, Windsurf, GitHub Copilot, Cline, Codex CLI,
  Gemini CLI and Claude Desktop. Adds a `GEMINI.md` rules template.

## [0.3.0] — 2026-06-04

### Added

- `scan_skill` — vet a third-party skill / MCP server / agent before install
  (16 threat categories, YARA-style signatures, taint-light, OSV.dev lookups,
  0–100 risk score).

### Fixed

- Ship the compiled `mcp/dist/` so the plugin's MCP server starts without an
  install-time build.

## [0.2.1] — 2026-05-27

### Fixed

- MCP server startup.

## [0.2.0] — 2026-05-27

### Added

- First public release: open-source security / bugfix / quality / deps /
  observability / performance / compliance plugin with an MCP server, SQLite
  state, and trilingual (EN/PT/ES) triggers.

[0.6.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.6.0
[0.5.1]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.5.1
[0.5.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.5.0
[0.4.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.4.0
[0.3.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.3.0
[0.2.1]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.2.1
[0.2.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.2.0
