# dev-guardian MCP server

The stdio MCP server behind the dev-guardian plugin: **59 tools** and **18 resources** for security, quality, bug hunting, dependencies, compliance, observability and performance. Every tool and resource, with its parameters, is listed in [`docs/tools.md`](../docs/tools.md), which `npm run build` generates from the registry.

Claude Code starts it from `.claude-plugin/plugin.json`:

```jsonc
{
  "mcpServers": {
    "dev-guardian": {
      "command": "node",
      "args": ["${CLAUDE_PLUGIN_ROOT}/mcp/dist/server.js"],
      "env": {}
    }
  }
}
```

Any other MCP host starts the same file by absolute path — see [`docs/hosts.md`](../docs/hosts.md).

## Requirements

Node.js **≥ 22.13** (`engines`). Storage is the built-in `node:sqlite`, used without any flag; on an older Node the server prints `dev-guardian requires Node.js >= 22.13 (node:sqlite)` and exits 1. `dist/server.js` is an esbuild bundle with no runtime `node_modules`, and it is committed: installing the plugin needs no build.

## Layout

```text
mcp/
├── src/
│   ├── server.ts        entry point: storage, shell probe, registry, stdio transport
│   ├── registerAll.ts   the import list that IS the public surface (tools + resources)
│   ├── tools/           one module per tool, plus the scan-tool factory (scanToolFactory.ts)
│   ├── resources/       guardian:// resources, paging, project scoping
│   ├── runners/         process runner (tree kill, timeouts), scanner parsers, install catalogue
│   ├── storage/         node:sqlite repositories, numbered SQL migrations, retention
│   ├── history/         open-set, per-scanner comparisons, scan roles
│   ├── hooks/           pure detectors shared by the hooks and `dev-guardian check`
│   ├── pkgvet/          package vetting (vet_packages and the install hook)
│   ├── platform/        OS, shell, project paths, .guardianignore, scopes
│   └── …                surface/, dast/, validate/, fixpr/, ci/, dashboard/, intel/, secrets/, wordpress/, …
├── test/
│   ├── unit/, integration/, e2e/   vitest (e2e needing a real scanner skip without it)
│   ├── ablate/          the rule-pack ablation harness (npm run ablate)
│   └── docs/            generator and tests for docs/tools.md and docs/rule-packs.md
├── scripts/             build steps: copy-assets, generateHostRules, bundle; smoke.mjs;
│                        generatePopularPackages.mjs (refreshes configs/popular-packages/)
└── dist/                compiled output, committed
```

## Build, run, test

```bash
cd mcp
npm ci                 # dev dependencies: tsc, esbuild, vitest, tsx
npm run lint           # tsc over src/ and test/
npm run build          # tsc, copy SQL migrations, regenerate host rules, bundle, regenerate docs/
npm test               # vitest (the whole suite)
node scripts/smoke.mjs # stdio handshake against the built server
npm run dev            # tsx src/server.ts, no build
```

`GUARDIAN_REQUIRE_SEMGREP=1` makes a missing Semgrep a failure instead of a skip. Every environment variable is in [`docs/env.md`](../docs/env.md).

## What happens at startup

1. Refuse to start, with one line on stderr, on a Node without `node:sqlite`.
2. Open `<project>/.guardian/guardian.db`, the project being the server's working directory. The database gets a busy timeout, WAL, `trusted_schema=OFF`, `cell_size_check=ON`, no memory map, and a real write probe. It is used only when it is the user's own: one dev-guardian creates carries a random `db_id`, registered under the per-user data directory (`GUARDIAN_DATA_DIR`, default `%LOCALAPPDATA%\dev-guardian` or `~/.local/share/dev-guardian`) before it is written, and the id is trusted only at the path it was registered for. One from 3.0.0 or earlier — or a copy of a registered one that landed elsewhere — is adopted once when git, if the project is a repository (a linked worktree included), does not track it (case-insensitively), no submodule, link or junction is involved, and it holds a completed scan filed under this project's own path (compared as text, never looked up) that finished after the project directory was created; `health_status.storage_adoption` reports it, with the suppressions it brought that have no project. Otherwise the database is foreign, is left untouched, and the per-user fallback is used — `health_status` and every scan say why, that the scans made meanwhile stay there, and that `dev-guardian db adopt` (CLI only) shows the database and registers it with `--yes` if it is yours. When the per-user data directory cannot be used (a container user with no home), the session runs on an in-memory database and says history will not persist. It is not used either when `.guardian/` is not writable (a file left by `sudo` or Docker, an ACL), when git tracks it (`git ls-files -s -- ':(icase).guardian'`, 3 s bound), or when its schema holds anything the migrations never create (a trigger, a view, an unknown table or index, a CHECK or UNIQUE constraint added to a known table). A database a newer build migrated still opens: new tables, non-UNIQUE indexes and columns every insert satisfies are accepted, while a trigger, a view or a UNIQUE index or constraint on a known table is refused from any build. A file SQLite cannot read stops the server with one line naming it.
3. Apply every SQL migration in `src/storage/migrations/` the database has not recorded in `schema_migrations`, each under the write lock, then check that every table, column and index the code needs is there. A database it cannot use stops the server with one line naming the file and what is missing.
4. Reap scans left `running` by a process that is gone, and rewrite suppressions and baselines stored under another spelling of a project's path to its canonical one.
5. Probe a bash — Git Bash, then WSL, then `bash` on `PATH` on Windows; `/bin/bash`, then `PATH` elsewhere — and cache the choice. Nothing but `install_toolchain`'s bundled install scripts and `init_project`'s first-pass status report uses it; without one those report `no_bash_shell` (or skip) and everything else works.
6. Keep `.guardian/` out of git in the project's `.gitignore` (`**/.guardian/*` plus `!**/.guardian/baseline.json`, so the CI baseline can be committed and a sub-project's `.guardian/` stays out too).
7. Register the tools and resources and connect stdio. Diagnostics go to stderr only; stdout is the JSON-RPC stream. A client that closes stdout ends the server with exit 0.
8. After connecting, prune old scans in short background batches (`GUARDIAN_RETENTION_SCANS`, default 50 per project and scan type).

## Storage

One SQLite file per project, `.guardian/guardian.db`, shared by every process that opens it (the plugin's server, a project-scoped server, the CLI).

| Table | Holds |
| --- | --- |
| `scans` | one row per tool run: type, status, coverage, `tools_run`, `missing_tools`, cache key, owner process |
| `findings` | findings per scan: fingerprint (per scan) and line-independent `identity` (across scans) |
| `scan_cves`, `cves` | CVEs per scan (`cves` is the legacy table, still read) |
| `cve_intel` | CISA KEV / FIRST EPSS per CVE, cached 24 h |
| `baselines` | baselines per project and scan type |
| `suppressions` | suppressions by identity or fingerprint, per project, with optional expiry |
| `tree_cache` | tree hash → scan, for the 5-minute scan cache |
| `stack_snapshots`, `surface_snapshots` | `detect_stack` and `map_attack_surface` results, the newest 10 per project |
| `finding_validations` | `validate_finding` verdicts |
| `agent_config_hashes` | `audit_agent_config`'s per-server hashes, to flag a changed MCP entry |
| `mcp_tool_pins`, `mcp_server_pins` | `audit_mcp_tools`'s per-tool definition hashes, to flag a tool that changed under the same name |
| `runtime_meta`, `schema_meta` | the cached shell choice and other server state; the highest migration applied |
| `schema_migrations` | every migration applied, by number, name and time |

Migrations are numbered, additive and idempotent; a database written by 2.0.0 keeps working. What decides whether one runs is the set in `schema_migrations`, not the highest number: migrations written on parallel branches can land in any order.

## Behaviour every tool shares

- **Per project.** A tool's `project_path` defaults to the server's working directory, and every history reader — the resources included — answers for one project, even though one database may hold several. A project is its canonical path (`realpath`, upper-case drive letter on Windows). Suppressions and baselines stored under another spelling of the same directory — 2.0.0 stored `c:\…` — are rewritten to it at startup, unless the path goes through a link (its target may be another project by now). Moving or renaming a repository is a new path: its history, suppressions and baselines stay under the old one.
- **Coverage is never guessed.** A scanner that is missing, failed or scanned nothing is `skipped` or `failed` with a reason, lands in `missing_tools`, and lowers `coverage` to `partial` or `none`. For Semgrep, `paths.scanned == 0` or a non-empty `errors` array is a failure even on exit 0.
- **Cache.** A scan-tool call within 5 minutes of an identical one — same project, inputs, tree hash, rule packs and plugin version — is served from the database, but only when the earlier run had full coverage.
- **Filters are views.** `severity_min`, `categories` and `packages` shape the response; every finding is still recorded, and the response says what it held back.
- **Bounded output.** Each spawned process is capped at 5 MB of stdout (`output_too_large` beyond that, with the report paths); a process that times out or is cancelled is killed with its whole tree.
- **Concurrency.** At most `GUARDIAN_MAX_CONCURRENT_SCANS` (default 2) scanner processes at once.
- **Cancellation.** A host's cancel stops the scanner processes. `create_fix_pr` is the exception to the usual error answer: a cancelled call returns `ok: true` with `cancelled: true` and the groups it finished, and an apply or verification step already in flight stops at the next boundary.

## What the server writes

- `<project>/.guardian/` — the database, and raw scanner output and exported reports under `.guardian/reports/`.
- The per-user data directory (`GUARDIAN_DATA_DIR`), only when the project's database cannot be used — see startup step 2.
- `<project>/.gitignore` — the two `.guardian` lines above, once.
- Files you asked for: `init_project` and `observability_setup` with `apply: true`, `precommit_install` (git hooks, through `pre-commit install`), and `scan_sast` / `bug_hunt` / `scan_wordpress` / `security_scan_full` with `auto_fix: true` — which refuses unless git confirms a clean tree or `allow_dirty: true` is passed.
- `create_fix_pr` works in disposable git worktrees and removes them; only `apply: true` commits, pushes and opens pull requests.
- `wp_vuln_check_source` caches the Wordfence feed in the user cache directory, never in the project.
- Temporary directories under the OS temp dir (review checkouts, verification reports), removed afterwards.

## Adding a scan tool

1. Parsing goes in `src/runners/scannerParsers/<scanner>.ts`, with a unit test.
2. Create `src/tools/<myTool>.ts` with `makeScanTool({...})` from `scanToolFactory.ts` — caching, persistence, identities, coverage, progress, scopes, `.guardianignore` and cancellation come with it.
3. Import it in `src/registerAll.ts` and add it to `test/integration/toolSurface.test.ts`: the surface is snapshotted on purpose.
4. Place every bookkeeping name it writes to `tools_run` / `missing_tools` in `src/history/runNames.ts`; the exhaustiveness test fails otherwise.
5. Keep the description under 1500 characters, add an integration test, run `npm run build`, and commit `dist/` and the regenerated `docs/` with the change.
