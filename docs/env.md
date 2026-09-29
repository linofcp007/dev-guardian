# Environment variables

Every `GUARDIAN_*` variable the MCP server, the hooks, the CLI and the developer tooling read, with its default. `mcp/test/docs/docs.test.ts` fails when the code reads one this page does not name.

Set them where the process that reads them starts: in the `env` block of the MCP server entry (`.claude-plugin/plugin.json` for the plugin, your host's MCP config otherwise), in the shell that launches Claude Code for the hooks, or in the CI job for the CLI.

## Runtime

| Variable | Read by | Default | Effect |
| --- | --- | --- | --- |
| `GUARDIAN_OFFLINE` | MCP server, CLI (`scan`, `baseline update`), hooks | unset | `1` switches off the lookups dev-guardian makes on its own initiative: CISA KEV / FIRST EPSS (`prioritize_findings`, `risk_score`, `create_fix_pr`), the registries and OSV for vetting (`vet_packages`, the install hook), `scan_skill`'s OSV lookup (`check_deps`), `verify_live`, Wordfence / wordpress.org (`wp_vuln_check_source`), and cosign's signature and provenance check of an image (`scan_containers`: `cosign` skipped and in `missing_tools`). What could not be measured is reported as `unknown` / `unavailable` / partial coverage, never as clean. It does **not** stop requests to a target you named (`scan_dast`, `wp_rest_audit`, `perf_check`, a `scan_skill` URL) or the scanners' own network use (Semgrep registry, Trivy database) — see [SECURITY.md](../SECURITY.md#network-egress). |
| `GUARDIAN_RETENTION_SCANS` | MCP server | `50` | Scans kept per (project, scan type) in `.guardian/guardian.db`; `0` keeps everything. Scoped scans (a diff, `--staged`) and scans that measured nothing (failed, cancelled, coverage `none`) are counted apart, N of each, so the newest scan that did measure is never pushed out. A baseline's scan, a running scan, the scans a baselined `security_scan_full` or `audit_executive` run stands on (its children, its sub-scans), and every scan the project's open findings are read from (including an older one whose findings newer, partial scans did not measure again) are never pruned. Pruning runs in the background after the server starts. |
| `GUARDIAN_SCAN_TIMEOUT_MS` | MCP server, CLI | `600000` (10 min) | Timeout for a scanner process when the tool sets none of its own. On timeout the whole process tree is killed. `scan_containers`' cosign check gives each image this as ONE budget shared by all its cosign calls (each call also capped at 3 min); what the budget cuts short is reported as no verdict, naming it. |
| `GUARDIAN_MCP_AUDIT_BUDGET_MS` | MCP server | `600000` (10 min) | The whole budget of one `audit_mcp_tools` call. Each server gets the smaller of its `timeout_ms` and what is left; the servers left when it runs out are skipped with that reason, never passed. |
| `GUARDIAN_MAX_CONCURRENT_SCANS` | MCP server, CLI | `2` | Scanner processes allowed to run at once; further calls queue. `security_scan_full` holds no slot itself. |
| `GUARDIAN_SEMGREP_IMAGE` | MCP server, CLI | `semgrep/semgrep` | Docker image for the Semgrep fallback that `scan_sast` and `map_attack_surface` use when `semgrep` is not installed but Docker is. Pin a tag here for reproducible runs. |
| `GUARDIAN_CACHE_DIR` | MCP server | per-OS user cache | Where `wp_vuln_check_source` keeps the Wordfence feed, used as given. Default: `%LOCALAPPDATA%\dev-guardian\cache` on Windows, `$XDG_CACHE_HOME/dev-guardian` or `~/Library/Caches/dev-guardian` on macOS, `$XDG_CACHE_HOME/dev-guardian` or `~/.cache/dev-guardian` elsewhere. |
| `GUARDIAN_DATA_DIR` | MCP server, CLI (`status`, `dashboard`, `db adopt`) | per-OS user data dir | dev-guardian's per-user data: the registry of the databases it created (`registry/<db_id>.json` — a project's `.guardian/guardian.db` is trusted only when its id is registered there for that very path: created by dev-guardian there, or registered by you with `dev-guardian db adopt --yes` — one from 3.0.0 is not, until you do), and the database a project uses when its own cannot be used — foreign, not writable, tracked by git, or holding schema objects the migrations never create — as `<dir>/<hash of the project path>/guardian.db`. Default: `%LOCALAPPDATA%\dev-guardian` on Windows, `$XDG_DATA_HOME/dev-guardian` or `~/.local/share/dev-guardian` elsewhere. Its directories are created 0700 and, on POSIX, must belong to you; a symbolic link or another user's directory there is refused. When it cannot be used at all (it cannot be created — a container user with no home, `HOME=/` — or it is refused), the server does not exit: the session runs on an in-memory database, and `health_status` and every scan say history will not persist until this points at a writable directory. |
| `GUARDIAN_HOOKS` | hooks | unset | `off` disables every hook. The user-level `~/.config/dev-guardian/hooks.json` with `"enabled": false` does the same; a project's `.guardian/hooks.config.json` cannot (its `enabled: false` is ignored). |
| `GUARDIAN_HOOKS_BASH_BLOCK` | hooks | unset | `0` / `false`: catastrophic commands are only warned about; `1` / `true`: always blocked. Wins over both config files. A project's `.guardian/hooks.config.json` cannot switch the block off — see [hooks.md](hooks.md). |
| `GUARDIAN_HOOKS_DEBUG` | hooks | unset | `1` writes the hooks' diagnostics to stderr (they are silent and fail open otherwise). |
| `GUARDIAN_PKG_VET` | hooks | unset | `0` turns off install-time package vetting in the PreToolUse hook. No project file can do it — not even with `"enabled": false`; the user-level config's `"enabled": false` turns it off along with every other hook. The `vet_packages` tool is unaffected. |
| `GUARDIAN_DATA_DIR` | hooks | per-OS user data dir | Where the hooks find dev-guardian's per-user data directory, whose `registry/` of trusted databases an assistant may not write — with the Write tool or from the shell (see [hooks.md](hooks.md#the-database-registry)). Default: `%LOCALAPPDATA%\dev-guardian` on Windows, `$XDG_DATA_HOME/dev-guardian` or `~/.local/share/dev-guardian` elsewhere — the directory the storage keeps it in. |
| `GUARDIAN_PKG_VET_DEADLINE_MS` | hooks | `8000` | The one deadline for install-time package vetting in a PreToolUse hook call, in ms from the start of the call (at most `14000`: Claude Code kills a hook at 15 s, and the command then runs with no verdict). The 3 s network budget is cut to it; what is left when it passes reads "vetting time budget exhausted" — not verified, never ok. |

## Set by dev-guardian, not by you

| Variable | Where | Purpose |
| --- | --- | --- |
| `GUARDIAN_SCAN_ID` | environment of the scripts a scan runs | the id of the scan row the run belongs to |
| `GUARDIAN_PROC_TREE_ID` | every child process on Windows | a per-run token the runner uses to find and kill the whole process tree, including MSYS descendants `taskkill` cannot see |

## Developer tooling

Read only by the test suite and `npm run ablate`; nothing at runtime looks at them.

| Variable | Read by | Effect |
| --- | --- | --- |
| `GUARDIAN_REQUIRE_COSIGN` | test suite | `1` turns a missing (or pre-3.0) cosign in `test/e2e/cosignRegistry.test.ts` — the real cosign against a registry that fails on purpose — from a visible skip into a hard failure. With `1`, the `verify` cases' need for Sigstore's TUF trust root (`cosign initialize`, network) is a hard requirement too: it fails rather than skips them. |
| `GUARDIAN_REQUIRE_SEMGREP` | test suite | `1` turns a missing Semgrep (or Trivy, for the Trivy e2e) from a visible skip into a hard failure — set it when you need to know a rule pack was actually exercised. |
| `GUARDIAN_PERF_STRICT` | `test/unit/hooks/bashGuard.test.ts`, `secretScan.test.ts` | `1` makes their absolute time bounds the tight ones (for a quiet machine). By default each is a loose ceiling, at least ten times the typical time, and linearity is asserted as a ratio of best-of-5 times — so a busy runner or a slow container does not fail a correct build, and a quadratic shape still does. |
| `GUARDIAN_SEMGREP` | `npm run ablate` | Semgrep binary to use (after `--semgrep=`, before `PATH`). |
| `GUARDIAN_RUST_SRC`, `GUARDIAN_CS_SRC`, `GUARDIAN_JAVA_SRC`, `GUARDIAN_PY_SRC`, `GUARDIAN_GO_SRC`, `GUARDIAN_PHP_SRC` | `npm run ablate` | Real-code corpus for axis 3 of the `bugfix-rs`, `-cs`, `-java`, `-py`, `-go` and `-php` packs. Unset: axis 3 prints `N/A`. Set to a path that does not exist: the run throws. |
| `GUARDIAN_RGPD_SRC` | `npm run ablate` | Axis-3 corpus for the `rgpd` pack; unset falls back to `mcp/src`. |
| `GUARDIAN_LLM_SRC` | `npm run ablate` | Axis-3 corpus for the `llm` pack: a tree of real LLM-application code, Python and JS/TS (the pack header names the one it was measured on). Unset: axis 3 prints `N/A`. Set to a path that does not exist: the run throws. |
| `GUARDIAN_CI_INIT_PIN_SHA` | `cli/dev-guardian.mjs ci-init` | Test seam: a 40-hex commit used instead of resolving the release tag. Production never sets it. |
| `GUARDIAN_TEST_*` | individual tests | Test-internal switches (live network e2e, fetch mocks, raw temp paths). Not for users. |

The suite itself runs with `GUARDIAN_OFFLINE=1` (`mcp/vitest.config.ts`); a test that exercises a network path clears it and supplies its own mocked `fetch`.

## Other variables dev-guardian reads

| Variable | Read by | Effect |
| --- | --- | --- |
| `WORDFENCE_API_KEY` | `wp_vuln_check_source` | Wordfence Intelligence v3 token. Without it the Wordfence pass is skipped and coverage is partial; the wordpress.org checks still run. |
| `WPSCAN_API_TOKEN` | `wp_vuln_check` | WPScan API token when `api_token` is not passed; without one the public rate limit applies. |
| the variable named by `auth_header_env` | `scan_dast` | The `Authorization` header for authenticated probes, so the credential never enters the transcript. |
| `XDG_CACHE_HOME`, `LOCALAPPDATA` | `wp_vuln_check_source` | Base of the default cache directory (see `GUARDIAN_CACHE_DIR`). |
| `CLAUDE_CONFIG_DIR` | `audit_agent_config`, `audit_mcp_tools` (with `include_user_config`), hooks | Where Claude Code keeps its global `.claude.json` and `settings.json`, read from there instead of `~/.claude.json` and `~/.claude/settings.json`, as Claude Code does. The hooks guard `settings.json` / `settings.local.json` there like `~/.claude/settings*.json`. |
| `CLAUDE_PROJECT_DIR` | hooks | Set by Claude Code for every hook: the project whose `.guardian/` configuration applies, wherever the session has `cd`-ed to (without it, the nearest ancestor holding `.guardian` or `.git`, never the home directory, its ancestors or the temp directory). |
| `NO_COLOR` | `dev-guardian status` | Disables colour in the terminal summary. |
| `npm_config_*registry*`, `NPM_CONFIG_REGISTRY`, `NPM_CONFIG_USERCONFIG`, `NPM_CONFIG_GLOBALCONFIG`, `NPM_CONFIG_PREFIX`, `YARN_NPM_REGISTRY_SERVER`, `YARN_REGISTRY`, `BUN_CONFIG_REGISTRY`, `PIP_*INDEX*`, `PIP_FIND_LINKS`, `PIP_NO_INDEX`, `PIP_CONFIG_FILE`, `VIRTUAL_ENV`, `UV_*INDEX*`, `UV_FIND_LINKS`, `UV_CONFIG_FILE`, `CONDA_PREFIX`, `COMPOSER_HOME`, `NUGET_*SOURCE*`, `NUGET_*FEED*`, `NUGET_*CONFIG*`, `NuGetPackageSourceCredentials_*`, `ProgramFiles(x86)` | `vet_packages`, the install hook | Evidence of a private registry: a name missing from the public registry is then `unknown`, never denied. See [hooks.md](hooks.md#install-time-package-vetting). |
