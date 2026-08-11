# Changelog

All notable changes to dev-guardian are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses
[Semantic Versioning](https://semver.org/). From 1.0.0 the MCP tool/resource
surface and default behaviours follow semver — breaking changes require a major
version bump.

## [Unreleased]

### Added

- **`map_attack_surface` — static route/env-var/port inventory across all 8 stacks.**
  New tool that runs a dedicated Semgrep rule pack (`configs/semgrep/routes.yml`) over
  the project to extract HTTP routes, referenced environment variables, declared ports
  and webhook endpoints, resolving Express-style router mount prefixes and WordPress
  REST namespaces to their effective path. Reports per-language `coverage`
  (`ok` / `no_rules` / ...) so an uncovered framework shows up as a gap rather than a
  silent zero. Persists one snapshot per run to a new `surface_snapshots` SQLite table,
  keyed by a tree hash so an unchanged working tree reuses the previous snapshot instead
  of re-scanning. The tool result itself returns a summary plus a 20-route sample and a
  `snapshot_id` — the full route list is deliberately kept out of the tool response (see
  the new resources below) so a project with hundreds of routes cannot exhaust the
  agent's context window on a single call.
  - **Not yet validated against a real Semgrep run.** Semgrep is not installed on the
    machine this was built on, so the whole pipeline — extraction, prefix resolution,
    coverage reporting — has only been exercised against hand-written JSON fixtures
    standing in for Semgrep's output. The Ruby and Rust rules in
    `configs/semgrep/routes.yml` are unvalidated guesses at the framework's route
    syntax, not rules checked against real code. Treat this as an unverified first cut,
    not a production-ready scanner.
- **`guardian://surface/latest` and `guardian://surface/{id}` resources.** Serve the
  full persisted attack-surface snapshot (every route, env var, port, webhook and the
  coverage report) by snapshot id or the most recent one. Return `{ snapshot: null }`
  when nothing has been captured yet, consistent with the rest of the resource surface.

### Fixed

- **A path we could not resolve is never emitted as a resolved path.** Only one route rule
  in the pack constrained its path capture to a string literal; the other thirteen let a
  Semgrep metavariable that had bound a *code expression* through as a confident path —
  `self::NAMESPACE`, `$this->namespace`, `SETTINGS.users_path`, `Paths.ORDERS`, a bare
  `routeVar`. The first two are the dominant idioms in real WordPress plugins, not edge
  cases, and the next tool in this series will send HTTP requests to whatever path it is
  handed. A new `isLiteralPath` predicate in `mcp/src/surface/extract.ts` now gates every
  route, in the one place they all flow through, so it also covers rules users add via
  `register_custom_rules`. A capture that fails it keeps its route — a route we cannot
  name is still evidence of surface — but is flagged `path_partial: true`, keeps the raw
  text in `path_resolved`, and drops to `low` confidence. Both resolvers now honour that
  flag instead of clearing it when they prepend a mount prefix or a `/wp-json` namespace.
  A `metavariable-regex` guard in the rule pack would be the wrong second layer here: it
  *drops* the match, so the extractor never sees it, and a route registered with a computed
  path is still surface — dropping it would make `coverage` report `no_matches` for the
  language, which is the same "this application exposes nothing" falsehood in a different
  place. `$PATH` literal guards are therefore confined to the two rules whose pattern does
  not identify a route on its own (`guardian-route-express`, `guardian-route-rails`), where
  the literal disambiguates rather than discards, and the pack header now states that rule
  so it is not re-added by pattern-matching.
- **`params` is derived from the path alone.** It was gated on both the path and the
  namespace being literal, so `register_rest_route(self::NAMESPACE, '/items/(?P<id>\d+)')`
  reported `params: []` — an assertion that the route takes no parameters — when `id` is
  plainly knowable from the path. Where the route is served stays unknown
  (`path_partial: true`); the parameters no longer do.
- **The HTTP method was lost for five of thirteen route rules.** `aspnet-minimal`,
  `aspnet`, `spring`, `nestjs` and `actix` all reported `ANY`. Semgrep never reports which
  `pattern-either` alternative fired, so a rule whose verb is encoded in the alternative
  cannot recover it — those families are now one rule per verb, each declaring
  `metadata.method` (which the extractor already read as a fallback, until now dead code).
  `normalizeMethod` also understands ASP.NET's `MapGet` / `MapPost` builder names.
- **A cached snapshot no longer hides the failed run that produced it.** The cache path
  reported a hardcoded `tools_run: [{semgrep, skipped, cached}]`, so the one case where a
  failing run is still persisted (Semgrep exited non-zero but left parseable JSON) carried
  its warning for exactly one call. Every later call on the same tree hash presented a
  snapshot that was empty *because the scan died* as "this application exposes nothing" —
  the falsehood this tool exists to prevent. The persisted `tools_run` entries are now
  reported alongside the cache marker.
- **`auth_hint` is no longer advertised as a feature.** No rule sets `metadata.auth`, so
  the field is always `unknown`. The claim was removed from the tool description, and the
  reason is recorded at `normalizeAuth` so the constant reads as deliberate rather than
  broken. Detecting auth properly needs to see the handler, not the registration site;
  that is its own piece of work.
- Regression coverage for the Semgrep exit-code gate (`exitCode === 1` means *matches
  found*, i.e. success), which previously could be deleted with the suite staying green.
- The Docker fallback in `map_attack_surface` no longer re-implements
  `buildSemgrepDockerArgs`; the shared builder takes a `configs` option (default
  `['auto']`) so both callers inherit anything added to it later.

## [1.2.1] — 2026-08-10

### Fixed

- **Marketplace sync failed on Claude Desktop / claude.ai.** The top-level `bin/` directory is now
  `cli/`. Desktop does not clone the repository — it delegates validation to a remote Anthropic
  service, which rejected the plugin with `status=failed_content`: *"Plugin contains a top-level
  bin/ directory ('bin/dev-guardian.mjs'). claude.ai-hosted plugins may not ship bin/ executables
  because they are added to PATH on the CLI but are not shown on the admin approval surface. Declare
  executable entry points via hooks, commands, or mcpServers instead."* The UI surfaced this only as
  **"Marketplace sync failed. Check the repository URL"**, which is misleading — the URL was always
  correct. Installing through the Claude Code CLI was never affected, because it uses a local
  `git clone` and skips this validation, so a passing CLI install is not evidence that Desktop will
  accept the plugin.
- The CLI is now `node cli/dev-guardian.mjs` — same commands (`mcp-config`, `check`), same
  behaviour. References updated in `README.md` (EN/PT/ES), `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`,
  `.cursor/rules/` and every `host-rules/` template.

## [1.2.0] — 2026-07-15

### Added

- **`guardian-grill` — the understanding gate.** A new front-end skill (with
  `/guardian-grill` and the `/gg` alias) that grills *you* on the
  domain-significant decisions a diff/PR introduced before you merge — for the
  long autonomous loops where you no longer read every line. Complements the code
  gates (lint / Semgrep / tests / review): those check the code, this checks that
  a human still understands the branches and rules the AI wrote. Records its
  verdict to `.guardian/last-grill.md` so the status and report gates can show an
  Understanding-gate row. Adapts the `dev-grill` engine when installed, runs the
  loop inline otherwise.
- **`guardian-improve` — from measured debt to improvement specs.** A new skill
  (with `/guardian-improve` and the `/gi` alias) that converts the ROI-ranked
  hotspots, quality-rule violations, oversized files, duplication and coverage
  gaps from the quality gate into metric-anchored **improvement spec seeds**
  (problem → affected files → current metric → target metric → draft EARS
  criteria) ready to hand to `dev-spec-driven`. Closes the loop:
  measure → spec → fix → re-measure. Targets are derived per project from
  `.guardian/budgets.yml`, the stack, or the baseline — never invented.

### Changed

- **`guardian-status`** now shows an **Understanding gate** row from
  `.guardian/last-grill.md` (🟢 / 🟡 / 🔴, or ⚪ when not run for the current diff).
- **`guardian-report`** includes the latest `guardian-grill` verdict in its
  Quality section — a green gate means the metrics passed *and* a human understood
  the change.
- **`guardian-budget`** now also audits code-quality budgets (max file / function
  lines, cyclomatic complexity, duplication %, coverage floor) from
  `.guardian/budgets.yml` — the single source of truth shared by the quality gate
  and `guardian-improve`, proposed per stack.
- README and CLAUDE.md counts updated to **13 skills + 48 slash commands**.

## [1.1.4] — 2026-07-09

### Added

- **Scan coverage trust signal.** Every scan now reports a `coverage` value
  (`full` / `partial` / `none`) derived from which scanners actually ran, so a
  "0 findings" result that scanned nothing can never read as "all clear". At
  coverage `none` a loud warning states plainly that nothing was scanned;
  `audit_executive` rolls up the worst coverage across its sub-scans and
  surfaces each gap. (`tools/scanCoverage.ts`)
- **Semgrep Docker fallback for SAST.** When `semgrep` is not on PATH but a
  Docker daemon is reachable, `scan_sast` runs the official `semgrep/semgrep`
  image (bind-mounted via `--mount` so it tolerates Windows drive letters and
  spaces in the path). A failed container run is recorded as a real coverage
  gap, never a silent empty scan. (`runners/dockerScanner.ts`)
- **`npm audit` findings are now counted.** `deps_audit` parses
  `npm audit --json` (npm 6 and 7+) into Findings, complementing Trivy's CVE
  coverage with GitHub advisories. (`runners/scannerParsers/npmAudit.ts`)

### Fixed

- **No double-counting of the same dependency CVE.** When Trivy already reports
  a package by CVE, the overlapping `npm audit` finding for that package is
  dropped (Trivy is the canonical CVE source); npm findings for packages Trivy
  missed are kept. Stops inflated severity counts from flowing into the
  executive roll-up.
- **An `npm audit` error is no longer treated as a clean scan.** A missing
  lockfile makes npm exit non-zero with an `{ error }` object rather than a
  report — previously counted as a successful "0 findings". It is now recorded
  as a failed auditor and a coverage gap.
- **A missing native auditor is a coverage gap.** When `npm` / `pip-audit` is
  expected (the manifest exists) but absent, it is added to `missing_tools` so
  coverage reflects the gap instead of reporting `full`.

## [1.1.3] — 2026-06-10

### Fixed

- **MCP server now starts on a fresh install — no `npm install` required.** The
  server imported `@modelcontextprotocol/sdk`, `better-sqlite3`, `execa` and
  `zod` as runtime dependencies, but the plugin ships git-first with
  `mcp/node_modules` git-ignored, so the *installed* server crashed on its first
  import with `ERR_MODULE_NOT_FOUND` and none of the 50 MCP tools came up (the
  zero-dependency hooks were unaffected).
  - Replaced the native **`better-sqlite3`** engine with the built-in
    **`node:sqlite`** (`DatabaseSync`), behind a thin adapter in
    `mcp/src/storage/db.ts` (`prepare/run/get/all/exec/pragma` + a nesting-aware
    `transaction`) — no native module to compile or ship.
  - The build now **bundles** `dist/server.js` with esbuild
    (`mcp/scripts/bundle.mjs`), inlining the remaining pure-JS deps, so the
    server runs with **zero** runtime `node_modules`.
  - The server is launched with `--experimental-sqlite` and now requires Node
    **>=22.5**. No change to the MCP tool/resource surface (still 50 tools,
    16 resources); the full test suite now exercises the `node:sqlite` engine.

### Changed

- Removed `better-sqlite3` / `@types/better-sqlite3`; bumped `@types/node` to
  22.x and added `esbuild` as the bundler. Verified the bundled server boots
  from a `node_modules`-free sandbox and lists all 50 tools.

## [1.1.2] — 2026-06-10

### Fixed

- **MCP server now loads when the plugin is enabled.** The plugin manifest
  (`.claude-plugin/plugin.json`) launched the server via the invalid
  `${pluginDir}` placeholder, which Claude Code does not recognise — it rejected
  the config with `Invalid MCP server config for "dev-guardian": Missing
  environment variables: pluginDir` and the 51 MCP tools never came up. Switched
  to the documented **`${CLAUDE_PLUGIN_ROOT}`** placeholder (already used by the
  guardrail hooks). Same fix applied to the docs that quoted the old form
  (`README.md`, `mcp/README.md`, `mcp/src/hostsetup/mcpConfig.ts`). No change to
  the MCP tool/resource surface or plugin behaviour.

## [1.1.1] — 2026-06-07

### Changed

- **Dropped the GitHub Actions CI workflow** (`.github/workflows/ci.yml`).
  dev-guardian is distributed git-first and the maintainer avoids the recurring
  Actions cost, so the quality gates now run **locally**: `npm test`,
  `npm run build` (rebuild `mcp/dist/` before committing — no CI to catch
  drift), markdownlint, the guardrail hooks, and the `dev-guardian check` CLI.
  No npm publishing either (unchanged — never set up). No change to the plugin
  behaviour or the MCP tool/resource surface.

## [1.1.0] — 2026-06-06

### Added

- **Guardrail hooks** (`hooks/hooks.json` + `hooks/guardian-hook.mjs`),
  auto-loaded when the plugin is enabled — **dependency-free** (only `node:`
  builtins + pure compiled detectors; no native modules, so they run in the
  installed plugin where `mcp/node_modules` isn't shipped) and **fail-open**
  (any error → exit 0, never breaks the host):
  - **SessionStart** — briefs the agent with the project's security posture
    (branch, uncommitted changes, last-scan age, init state).
  - **PostToolUse (Write/Edit/MultiEdit/NotebookEdit)** — warns, with a
    **redacted** preview, when freshly written text contains a hard-coded
    secret. The authoritative full scan stays `scan_secrets` (gitleaks).
  - **PreToolUse (Bash)** — denies catastrophic commands by default
    (`rm -rf /`, `curl … | sh`, raw-disk `dd`/`mkfs`, fork bombs); warns on
    risky ones (force-push, hard reset, `sudo`, `chmod 777`).
  - Configurable via `.guardian/hooks.config.json` (opt-in secret-write
    blocking with `secrets.block`), `.guardian/hooks-allowlist.json` for false
    positives, and the `GUARDIAN_HOOKS=off` kill switch.
- `mcp/src/hooks/secretScan.ts` + `bashGuard.ts` — pure, unit-tested detection
  engines (31 new tests) shared by the hooks and the CLI.
- `dev-guardian check` CLI subcommand (`--file <path>` / `--bash "<command>"`,
  `--min`, `--json`) — run the same guardrail detectors from a terminal or CI;
  exit code 1 on a finding.

### Fixed

- The MCP server no longer reports a hard-coded `0.1.0`; it reads its version
  from `.claude-plugin/plugin.json` at startup (falling back to the MCP
  `package.json`), keeping its reported identity in lock-step with the release.
- `mcp/package.json` version aligned with the plugin release (was stale at
  `0.1.0`).

## [1.0.0] — 2026-06-05

First stable release. Everything below was already shipped in 0.x; 1.0.0 marks
the point where the surface is proven and held to semver.

### Added

- **CI pipeline** (GitHub Actions): markdownlint; build + test on Linux, macOS
  and Windows; a dist-sync gate (committed `mcp/dist` must equal a fresh build);
  coverage thresholds; an e2e job running real Semgrep against a vulnerable
  fixture; and a dogfood self-audit (Syft SBOM + gitleaks + Semgrep SARIF).
- **Stability snapshot** — the exact 50 tools + 16 resources are pinned in
  `toolSurface.test.ts`; accidental surface drift fails CI.
- `SECURITY.md` (responsible disclosure), `CONTRIBUTING.md`, this `CHANGELOG.md`.

### Changed

- **First stable release.** The MCP tool/resource surface and default
  behaviours are now covered by semver.

### Fixed

- README counts corrected (44 commands, 16 resources).

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

[1.1.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v1.1.0
[1.0.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v1.0.0
[0.6.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.6.0
[0.5.1]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.5.1
[0.5.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.5.0
[0.4.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.4.0
[0.3.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.3.0
[0.2.1]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.2.1
[0.2.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.2.0
